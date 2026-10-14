"""
Comprehensive False-Positive and Multi-Layer Threat Detection Regression Suite.
Validates:
1. Legitimate institutional/college URLs are NOT falsely flagged as ~63% phishing.
2. Attackers masquerading as universities (subdomain tricks) are correctly flagged.
3. Known genuine phishing links are accurately flagged as high risk.
4. Email phishing detection engine correctly catches header spoofing, lure text,
   and deceptive hyperlink anchor-mismatches.
"""

import pytest
from src.detection.verdict_engine import MultiLayerDetectionEngine
from src.utils.domain_parser import domain_parser, allowlist_manager
from src.email_analysis.email_scanner import EmailPhishingScanner

@pytest.fixture(scope="module")
def detection_engine():
    return MultiLayerDetectionEngine()

@pytest.fixture(scope="module")
def email_scanner(detection_engine):
    return EmailPhishingScanner(detection_engine=detection_engine)


class TestInstitutionalFalsePositiveElimination:
    """Verifies that legitimate academic and institutional URLs are safely classified."""

    @pytest.mark.parametrize("college_url", [
        "https://portal.stanford.edu/student/login",
        "https://mail.ox.ac.uk/owa",
        "https://sso.iitm.ac.in/auth/callback",
        "https://www.harvard.edu/admissions",
        "https://student.unimelb.edu.au/login",
        "https://library.nus.edu.sg/search?q=cybersecurity",
        "https://canvas.instructure.com/login/canvas",
        "https://blackboard.cmu.edu/webapps/login/"
    ])
    def test_legitimate_college_urls_are_safe(self, detection_engine, college_url):
        result = detection_engine.scan_url(
            college_url,
            include_dns=False,
            include_tls=False,
            include_threat_intel=False
        )
        assert result["verdict"] == "No Phishing Indicators Detected", (
            f"False positive triggered on {college_url}: verdict was '{result['verdict']}' with score {result['risk_score']}"
        )
        assert result["risk_score"] < 25, (
            f"Risk score too high for {college_url}: got {result['risk_score']}"
        )
        assert result["is_trusted"] is True, f"Expected {college_url} to be recognized as trusted/institutional."

    def test_psl_subdomain_boundary_parsing(self):
        """Validates that multi-part suffixes like .ac.uk and .ac.in do not trigger excessive subdomain warnings."""
        info_ox = domain_parser.parse("mail.ox.ac.uk")
        assert info_ox["registered_domain"] == "ox.ac.uk"
        assert info_ox["subdomain"] == "mail"
        assert info_ox["subdomain_count"] == 1
        assert info_ox["is_institutional"] is True

        info_iit = domain_parser.parse("sso.iitm.ac.in")
        assert info_iit["registered_domain"] == "iitm.ac.in"
        assert info_iit["subdomain"] == "sso"
        assert info_iit["subdomain_count"] == 1
        assert info_iit["is_institutional"] is True


class TestGenuineThreatDetection:
    """Ensures that true phishing, raw IPs, and deceptive lookalikes remain strictly detected."""

    @pytest.mark.parametrize("phish_url", [
        "http://paypal-security-verification.xyz/login",
        "http://192.168.1.1/admin-login",
        "http://account-update-bank.com.scam-target.xyz/auth",
        "http://stanford.edu.account-update.xyz/login"
    ])
    def test_genuine_threats_are_flagged(self, detection_engine, phish_url):
        result = detection_engine.scan_url(
            phish_url,
            include_dns=False,
            include_tls=False,
            include_threat_intel=False
        )
        assert result["verdict"] in ("Likely Phishing", "Suspicious — Further Verification Recommended"), (
            f"Failed to detect threat on {phish_url}: got '{result['verdict']}' (Score: {result['risk_score']})"
        )
        assert result["risk_score"] >= 40, (
            f"Risk score too low for threat {phish_url}: got {result['risk_score']}"
        )

    def test_lookalike_spoof_fails_allowlist_match(self):
        """Confirms that 'stanford.edu.evil.xyz' is NOT trusted even though 'stanford.edu' is allowlisted."""
        is_trusted, _ = allowlist_manager.is_trusted("stanford.edu.evil.xyz")
        assert is_trusted is False, "Allowlist boundary leak detected on deceptive subdomain construct."


class TestEmailPhishingScanner:
    """Tests the dedicated email phishing analysis engine."""

    def test_detects_authority_spoofing_and_urgency(self, email_scanner):
        fake_email = (
            "From: \"IT Helpdesk\" <urgent-support@gmail.com>\n"
            "To: student@stanford.edu\n"
            "Subject: URGENT: Your student account will be suspended within 24 hours\n"
            "Reply-To: phisher-collector@mail.ru\n\n"
            "Please click below to verify your password immediately:\n"
            "http://paypal-security-verification.xyz/login\n"
        )
        res = email_scanner.scan_raw_text(fake_email)
        assert res["verdict"] == "Likely Phishing Email"
        assert res["risk_score"] >= 75
        finding_names = [f["name"] for f in res["findings"]]
        assert "Display-Name Authority Spoofing" in finding_names
        assert "Reply-To Address Mismatch" in finding_names
        assert any("Suspended" in f["name"] or "Termination" in f["name"] for f in res["findings"])

    def test_detects_link_text_vs_href_mismatch(self, email_scanner):
        mismatch_html = (
            "From: registrar@stanford.edu\n"
            "Subject: Semester Schedule\n"
            "Content-Type: text/html\n\n"
            "<p>Click <a href='http://malicious-scam.xyz/steal'>https://portal.stanford.edu</a> to view.</p>"
        )
        res = email_scanner.scan_raw_text(mismatch_html)
        finding_names = [f["name"] for f in res["findings"]]
        assert any("Deceptive Hyperlink" in name for name in finding_names)
        assert res["risk_score"] >= 40

    def test_clean_institutional_email_is_safe(self, email_scanner):
        clean_email = (
            "From: \"Stanford University Registrar\" <registrar@stanford.edu>\n"
            "To: student@stanford.edu\n"
            "Subject: Autumn Quarter Enrollment Details\n\n"
            "Dear Student,\n\n"
            "Autumn Quarter course enrollment opens next Monday. View your schedule on Axess:\n"
            "https://portal.stanford.edu/student/login\n\n"
            "Regards,\nOffice of the Registrar"
        )
        res = email_scanner.scan_raw_text(clean_email)
        assert res["verdict"] in ("No Phishing Indicators Detected", "Legitimate / Low Risk")
        assert res["risk_score"] < 25

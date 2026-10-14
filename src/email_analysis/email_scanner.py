"""
Enterprise Email Phishing and Social Engineering Analysis Engine.
Supports parsing of raw pasted email text and uploaded .eml files.
Extracts header anomalies, display-name spoofing, Reply-To mismatches,
SPF/DKIM/DMARC authentication evidence, link destination mismatches,
urgency lures, and malicious attachment extensions.
Zero execution of attachments or embedded scripts.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from src.detection.verdict_engine import MultiLayerDetectionEngine
from src.utils.domain_parser import domain_parser, allowlist_manager
from src.utils.logging_config import logger

# High-risk executable or script attachment extensions
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".msc", ".hta", ".cpl", ".iso", ".img", ".dmg", ".pkg",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".jar", ".ps1"
}

# Free webmail providers commonly abused in display-name spoofing
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.ru", "proton.me", "protonmail.com", "yandex.com", "zoho.com",
    "gmx.com", "icloud.com"
}

# Authority and urgency keywords in display names and email subjects
SPOOFED_AUTHORITY_TERMS = [
    "it support", "helpdesk", "help desk", "service desk", "administrator",
    "security team", "account team", "payroll", "billing", "financial aid",
    "registrar", "portal support", "system alert", "security center"
]

URGENCY_LURE_PATTERNS = [
    (r"\b(?:account|access|mailbox|password)\b.{0,30}?\b(?:suspended|terminated|disabled|expired|locked|closed|deactivated)\b", "Account Termination Threat", "HIGH"),
    (r"\b(?:urgent|immediate|within\s+24\s+hours|action\s+required|critical\s+alert)\b", "Urgent Time Pressure", "MEDIUM"),
    (r"\b(?:verify|confirm|validate|update)\s+your\s+(?:account|password|identity|credentials|ssn|banking)\b", "Credential Harvesting Prompt", "HIGH"),
    (r"\b(?:gift\s+card|wire\s+transfer|bitcoin|crypto|unauthorized\s+transaction|overdue\s+invoice)\b", "Financial / Wire Fraud Lure", "HIGH"),
    (r"\b(?:one-time\s+passcode|otp|security\s+code|two-factor|2fa)\b", "MFA / OTP Interception Lure", "HIGH")
]

class EmailPhishingScanner:
    """Enterprise multi-signal email security analyzer."""

    def __init__(self, detection_engine: MultiLayerDetectionEngine = None):
        self.engine = detection_engine or MultiLayerDetectionEngine()

    def scan_raw_text(self, text: str) -> dict:
        """Parses and analyzes raw pasted email text (headers + body or just body)."""
        if not text or not text.strip():
            return {
                "verdict": "INCONCLUSIVE",
                "risk_score": 0,
                "summary": "Empty email content provided.",
                "findings": [],
                "links": [],
                "headers": {},
                "auth_status": {},
                "attachments": []
            }

        # Attempt standard email parse
        msg = Parser(policy=policy.default).parsestr(text)
        return self._analyze_message_object(msg, raw_fallback_text=text)

    def scan_eml_bytes(self, eml_bytes: bytes) -> dict:
        """Parses and analyzes uploaded .eml binary file contents."""
        if not eml_bytes:
            return {
                "verdict": "INCONCLUSIVE",
                "risk_score": 0,
                "summary": "Empty .eml file provided.",
                "findings": [],
                "links": [],
                "headers": {},
                "auth_status": {},
                "attachments": []
            }

        msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
        return self._analyze_message_object(msg)

    def _analyze_message_object(self, msg: email.message.EmailMessage, raw_fallback_text: str = "") -> dict:
        findings = []
        
        # 1. Extract Headers
        from_hdr = str(msg.get("From", "")).strip()
        to_hdr = str(msg.get("To", "")).strip()
        subject_hdr = str(msg.get("Subject", "")).strip()
        reply_to_hdr = str(msg.get("Reply-To", "")).strip()
        date_hdr = str(msg.get("Date", "")).strip()

        # Parse From address components
        display_name = ""
        sender_email = ""
        sender_domain = ""

        if "<" in from_hdr and ">" in from_hdr:
            parts = from_hdr.split("<")
            display_name = parts[0].strip().strip('"').strip("'")
            sender_email = parts[1].split(">")[0].strip().lower()
        elif "@" in from_hdr:
            sender_email = from_hdr.strip().lower()

        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].strip()

        # Parse Reply-To address
        reply_to_domain = ""
        if "@" in reply_to_hdr:
            m = re.search(r"[\w\.-]+@([\w\.-]+)", reply_to_hdr)
            if m:
                reply_to_domain = m.group(1).lower().strip()

        # ======================================================================
        # 2. Header & Sender Spoofing Analysis
        # ======================================================================
        if display_name and sender_domain:
            low_dn = display_name.lower()
            # A. Display name claims authority/brand, but sender is free webmail
            if any(term in low_dn for term in SPOOFED_AUTHORITY_TERMS) and sender_domain in FREE_WEBMAIL_DOMAINS:
                findings.append({
                    "name": "Display-Name Authority Spoofing",
                    "evidence": f"Display name '{display_name}' sent from free personal webmail '{sender_email}'",
                    "severity": "CRITICAL",
                    "explanation": "Scammers frequently set their display name to an institutional or corporate authority while sending from untraceable free webmail accounts.",
                    "source": "Sender Header Analysis",
                    "action": "Do not reply or trust the sender."
                })
            # B. Display name contains a university or brand name, but domain is completely different
            for inst_domain in ["stanford", "harvard", "mit", "oxford", "paypal", "microsoft", "apple"]:
                if inst_domain in low_dn and inst_domain not in sender_domain:
                    findings.append({
                        "name": "Brand / Institutional Impersonation",
                        "evidence": f"Display name '{display_name}' does not match sender domain '@{sender_domain}'",
                        "severity": "HIGH",
                        "explanation": "Sender name mimics an established institution or service that they do not operate.",
                        "source": "Header Inspection",
                        "action": "Verify through verified official channels."
                    })
                    break

        # C. Sender vs Reply-To Mismatch
        if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
            # Check if reply-to is free webmail while sender was a custom domain
            findings.append({
                "name": "Reply-To Address Mismatch",
                "evidence": f"Sent from '@{sender_domain}', but replies are routed to '@{reply_to_domain}'",
                "severity": "HIGH",
                "explanation": "Diverting replies to an external domain is a tactic used to hijack email threads and steal confidential responses.",
                "source": "Routing Headers",
                "action": "Do not click Reply."
            })

        # ======================================================================
        # 3. Authentication Headers (SPF, DKIM, DMARC)
        # ======================================================================
        auth_status = {"spf": "NOT_PRESENT", "dkim": "NOT_PRESENT", "dmarc": "NOT_PRESENT"}
        auth_hdr = str(msg.get("Authentication-Results", "")).lower()
        spf_hdr = str(msg.get("Received-SPF", "")).lower()

        combined_auth = f"{auth_hdr} {spf_hdr}"
        if "spf=pass" in combined_auth or "pass (google.com:" in combined_auth:
            auth_status["spf"] = "PASS"
        elif "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
            auth_status["spf"] = "FAIL"
            findings.append({
                "name": "SPF Authentication Failure",
                "evidence": "Sender IP failed SPF authorization for sender domain",
                "severity": "HIGH",
                "explanation": "The sending server was not authorized by the domain's DNS SPF policy.",
                "source": "Email Authentication",
                "action": "Likely spoofed message."
            })

        if "dkim=pass" in combined_auth:
            auth_status["dkim"] = "PASS"
        elif "dkim=fail" in combined_auth:
            auth_status["dkim"] = "FAIL"
            findings.append({
                "name": "DKIM Cryptographic Signature Failure",
                "evidence": "Message DKIM cryptographic signature verification failed",
                "severity": "HIGH",
                "explanation": "The email body or headers were modified in transit or forged.",
                "source": "Email Authentication",
                "action": "Treat message as forged."
            })

        if "dmarc=pass" in combined_auth:
            auth_status["dmarc"] = "PASS"
        elif "dmarc=fail" in combined_auth:
            auth_status["dmarc"] = "FAIL"
            findings.append({
                "name": "DMARC Alignment Failure",
                "evidence": "Message failed domain alignment under DMARC policy",
                "severity": "HIGH",
                "explanation": "The message fails DMARC policy validation against the From header.",
                "source": "Email Authentication",
                "action": "Do not trust sender authenticity."
            })

        # ======================================================================
        # 4. Extract Body (Plain Text & HTML)
        # ======================================================================
        plain_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" not in disp:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            text_decoded = payload.decode(charset, errors="replace")
                            if ctype == "text/plain":
                                plain_body += "\n" + text_decoded
                            elif ctype == "text/html":
                                html_body += "\n" + text_decoded
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                    if msg.get_content_type() == "text/html":
                        html_body = decoded
                    else:
                        plain_body = decoded
            except Exception:
                plain_body = str(msg.get_payload())

        # Fallback to raw text if parser yielded empty body
        full_text_search = f"{subject_hdr}\n{plain_body}\n{html_body}\n{raw_fallback_text}"

        # ======================================================================
        # 5. Social Engineering & Urgency Analysis
        # ======================================================================
        for pattern, finding_name, severity in URGENCY_LURE_PATTERNS:
            matches = re.findall(pattern, full_text_search, re.IGNORECASE)
            if matches:
                findings.append({
                    "name": finding_name,
                    "evidence": f"Found phrase matching: '{matches[0]}'",
                    "severity": severity,
                    "explanation": "Social engineering attacks induce panic or urgency to compel victims to act before verifying.",
                    "source": "Behavioral Content Analysis",
                    "action": "Pause and independently contact the purported organization."
                })

        # ======================================================================
        # 6. Embedded Links & Link-Text Mismatch Analysis
        # ======================================================================
        extracted_urls = []
        
        # A. HTML Links (<a> tags)
        if html_body:
            soup = BeautifulSoup(html_body, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                link_text = a_tag.get_text(strip=True)
                if href.startswith(("http://", "https://")):
                    extracted_urls.append(href)
                    
                    # Deceptive anchor text detection: text displays legit URL, but href goes elsewhere
                    if link_text.startswith(("http://", "https://", "www.")):
                        txt_norm = link_text if link_text.startswith("http") else f"https://{link_text}"
                        parsed_txt = urlparse(txt_norm).netloc.lower()
                        parsed_href = urlparse(href).netloc.lower()
                        
                        if parsed_txt and parsed_href and parsed_txt != parsed_href:
                            findings.append({
                                "name": "Deceptive Hyperlink Destination (Link-Text Mismatch)",
                                "evidence": f"Link text displays '{parsed_txt}', but directs to '{parsed_href}'",
                                "severity": "CRITICAL",
                                "explanation": "Attackers disguise malicious phishing links by writing an authentic domain in the visible link text.",
                                "source": "HTML Link Discrepancy",
                                "action": "Do not click this link."
                            })

        # B. Plain text URLs
        raw_found = re.findall(r"https?://[^\s<>\"']+", full_text_search)
        extracted_urls.extend(raw_found)
        # Deduplicate
        unique_urls = list(set(u.rstrip(".,;)>]") for u in extracted_urls if len(u) > 8))

        # Scan top 5 extracted URLs using MultiLayerDetectionEngine
        link_audit_results = []
        has_phishing_link = False
        
        for u in unique_urls[:5]:
            scan_res = self.engine.scan_url(u, include_dns=False, include_tls=False, include_threat_intel=True)
            link_audit_results.append({
                "url": scan_res["redacted_url"],
                "verdict": scan_res["verdict"],
                "risk_score": scan_res["risk_score"]
            })
            if scan_res["verdict_badge"] == "CRITICAL_PHISHING" or scan_res["risk_score"] >= 70:
                has_phishing_link = True
                findings.append({
                    "name": "Malicious Phishing URL Inside Email",
                    "evidence": f"Embedded URL '{scan_res['redacted_url']}' classified as {scan_res['verdict']} (Risk: {scan_res['risk_score']}/100)",
                    "severity": "CRITICAL",
                    "explanation": "The email contains a link with verified phishing indicators or malicious reputation.",
                    "source": "Deep URL Engine",
                    "action": "Do not click or navigate to this address."
                })
            elif scan_res["verdict_badge"] == "SUSPICIOUS" or scan_res["risk_score"] >= 40:
                findings.append({
                    "name": "Suspicious URL Inside Email",
                    "evidence": f"Embedded URL '{scan_res['redacted_url']}' classified as {scan_res['verdict']} (Risk: {scan_res['risk_score']}/100)",
                    "severity": "MEDIUM",
                    "explanation": "The email contains an anomalous or unverified external link.",
                    "source": "Deep URL Engine",
                    "action": "Verify destination before clicking."
                })

        # ======================================================================
        # 7. Attachment Analysis
        # ======================================================================
        attachments_found = []
        if msg.is_multipart():
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    ext = "." + fn.split(".")[-1].lower() if "." in fn else ""
                    is_susp = ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS
                    attachments_found.append({
                        "filename": fn,
                        "extension": ext,
                        "is_suspicious": is_susp
                    })
                    if is_susp:
                        findings.append({
                            "name": "Dangerous Executable Attachment",
                            "evidence": f"Attached file '{fn}' uses high-risk extension '{ext}'",
                            "severity": "CRITICAL",
                            "explanation": "Attackers attach executable or macro-enabled files to deliver trojans, ransomware, or keyloggers.",
                            "source": "Attachment Inspection",
                            "action": "Do not open, execute, or save this file."
                        })

        # ======================================================================
        # 8. Overall Email Risk Score & Verdict
        # ======================================================================
        risk_score = 0
        critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in findings if f["severity"] == "HIGH")
        med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

        if critical_count > 0:
            risk_score = max(80, 75 + critical_count * 10)
        elif high_count > 0:
            risk_score = min(75, 45 + high_count * 15)
        elif med_count > 0:
            risk_score = min(40, 15 + med_count * 10)
        else:
            risk_score = 5

        risk_score = min(max(risk_score, 0), 100)

        # Verdict assignment
        if risk_score >= 70 or critical_count > 0:
            verdict = "Likely Phishing Email"
            verdict_badge = "CRITICAL_PHISHING"
            summary = "High-confidence indicators of malicious email phishing, spoofing, or credential fraud detected."
        elif risk_score >= 40 or high_count > 0:
            verdict = "Suspicious Email"
            verdict_badge = "SUSPICIOUS"
            summary = "Multiple anomalous characteristics observed. Exercise caution before trusting sender."
        else:
            verdict = "No Phishing Indicators Detected"
            verdict_badge = "SAFE"
            summary = "No prominent phishing or social engineering markers detected in the provided message."

        return {
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "risk_score": risk_score,
            "summary": summary,
            "headers": {
                "From": from_hdr,
                "To": to_hdr,
                "Subject": subject_hdr,
                "Reply-To": reply_to_hdr,
                "Date": date_hdr,
                "Sender Domain": sender_domain
            },
            "auth_status": auth_status,
            "findings": findings,
            "links": link_audit_results,
            "attachments": attachments_found,
            "total_links_found": len(unique_urls)
        }

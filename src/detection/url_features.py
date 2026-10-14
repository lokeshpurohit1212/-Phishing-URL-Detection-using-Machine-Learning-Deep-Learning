"""
Advanced URL feature extraction and heuristic risk analysis engine.
Extracts structural, lexical, and brand-impersonation features.
Also provides tabular feature vector matching the trained ML dataset.
"""

from urllib.parse import urlparse
import ipaddress
import re
import math
from src.config import TRUSTED_DOMAINS, TRUSTED_BRANDS, SUSPICIOUS_KEYWORDS
from src.utils.url_validation import normalize_url, is_ip_address, is_punycode
from src.utils.domain_parser import domain_parser, allowlist_manager

SHORTENING_SERVICES_REGEX = re.compile(
    r"(?:bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl\.com|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|"
    r"u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|vzturl\.com|qr\.net|"
    r"1url\.com|tweez\.me|v\.gd|link\.zip\.net)",
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".link", ".buzz", ".guru",
    ".space", ".gq", ".cf", ".tk", ".ml", ".ga", ".fit", ".rest", ".bar"
}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of string (randomness indicator)."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    for char in set(text):
        p = text.count(char) / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def is_trusted_domain(domain: str) -> bool:
    """Check if domain or parent domain matches known trusted list."""
    clean = domain.lower().split(":")[0]
    if clean.startswith("www."):
        clean = clean[4:]
    for trusted in TRUSTED_DOMAINS:
        if clean == trusted or clean.endswith("." + trusted):
            return True
    return False

def extract_advanced_features(url: str) -> dict:
    """
    Performs comprehensive lexical, structural, and heuristic feature extraction.
    Returns extracted metrics, rule risk score (0-100), and specific findings.
    """
    raw_url = url.strip()
    norm_url = normalize_url(raw_url)
    parsed = urlparse(norm_url)
    
    hostname = parsed.netloc.split(":")[0].lower()
    clean_host = hostname[4:] if hostname.startswith("www.") else hostname
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_target = f"{clean_host} {path} {query}"

    # Precise Public Suffix List domain parsing
    domain_info = domain_parser.parse(clean_host)
    registered_domain = domain_info["registered_domain"]
    subdomain_count = domain_info["subdomain_count"]
    is_institutional = domain_info["is_institutional"]
    is_allowlisted, matched_allowlist_domain = allowlist_manager.is_trusted(clean_host)

    uses_http_explicit = raw_url.lower().startswith("http://")
    has_ip = is_ip_address(clean_host)
    has_at = "@" in raw_url
    url_length = len(raw_url)
    host_length = len(clean_host)
    
    # Redirection // check
    pos = raw_url.rfind("//")
    has_double_slash_redirect = pos > 7

    # Subdomain analysis using eTLD+1 boundary
    has_multiple_subdomains = subdomain_count >= 2 and not is_institutional and not is_allowlisted

    # Character counts
    dot_count = clean_host.count(".")
    hyphen_count = clean_host.count("-")
    digit_count = sum(c.isdigit() for c in clean_host)
    special_char_count = len(re.findall(r"[-_~%&=?@]", raw_url))
    entropy = calculate_entropy(clean_host)

    # Shortener check
    is_shortened = bool(SHORTENING_SERVICES_REGEX.search(raw_url))
    
    # Punycode
    punycode_detected = is_punycode(clean_host)
    
    # Suspicious TLD
    has_suspicious_tld = any(clean_host.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # Trust classification
    trusted = is_allowlisted or is_trusted_domain(clean_host) or (is_institutional and not has_suspicious_tld and not punycode_detected)

    # Keywords detection (suppressed for benign login/portal paths on verified institutions)
    detected_keywords = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_target:
            # If domain is trusted/institutional and keyword is normal portal/login token, do not flag
            if trusted and kw in ("login", "portal", "account", "auth", "signin", "verify", "student", "webmail", "admin"):
                continue
            detected_keywords.append(kw)

    # Brand impersonation detection
    impersonated_brands = []
    if not trusted:
        for brand in TRUSTED_BRANDS:
            # Brand appearing in subdomain or hyphenated host outside the brand's own domain
            if brand in clean_host and not clean_host.endswith(f".{brand}.com") and clean_host != f"{brand}.com":
                impersonated_brands.append(brand)

    # ==============================
    # RULE RISK SCORING (0 - 100)
    # ==============================
    risk_score = 0
    findings = []

    if is_allowlisted:
        findings.append({
            "name": "Verified Institutional Allowlist Match",
            "evidence": f"Domain '{clean_host}' matches institutional allowlist entry '{matched_allowlist_domain}'",
            "severity": "LOW",
            "explanation": "The domain is confirmed on your organization's verified institutional allowlist.",
            "source": "Institutional Allowlist",
            "action": "Proceed with confidence for academic/campus tasks."
        })
    elif is_institutional:
        findings.append({
            "name": "Recognized Institutional Domain",
            "evidence": f"Domain '{clean_host}' uses authentic educational/institutional hierarchy '.{domain_info['suffix']}'",
            "severity": "LOW",
            "explanation": "Academic and governmental domain spaces are subject to institutional credential validation.",
            "source": "PSL / Institutional Registry",
            "action": "Standard campus/institutional access."
        })
    elif trusted:
        findings.append({
            "name": "Trusted Platform Match",
            "evidence": f"Domain '{clean_host}' is recognized as an authoritative platform",
            "severity": "LOW",
            "explanation": "The domain matches a known, high-reputation legitimate service.",
            "source": "Heuristic Directory",
            "action": "Proceed with standard awareness."
        })
    else:
        # 1. IP address in URL
        if has_ip:
            risk_score += 35
            findings.append({
                "name": "Direct IP Address Hostname",
                "evidence": f"Host '{clean_host}' is a raw IP instead of a registered domain",
                "severity": "HIGH",
                "explanation": "Phishers commonly deploy scam pages on raw IP addresses to bypass domain reputation systems.",
                "source": "URL Structure",
                "action": "Do not enter sensitive data or credentials."
            })

        # 2. Impersonated brand
        if impersonated_brands:
            risk_score += 30
            findings.append({
                "name": "Brand Name In Hostname",
                "evidence": f"Domain contains brand token(s): {', '.join(impersonated_brands)}",
                "severity": "HIGH",
                "explanation": "Legitimate brands host services on their primary domains, not in third-party or sub-level hostnames.",
                "source": "Brand Intelligence",
                "action": "Check the address bar carefully for typosquatting."
            })

        # 3. Punycode
        if punycode_detected:
            risk_score += 25
            findings.append({
                "name": "Punycode / IDN Homoglyph",
                "evidence": f"Host starts with xn--: {clean_host}",
                "severity": "HIGH",
                "explanation": "Punycode allows attackers to disguise Cyrillic or Greek lookalike characters as standard English letters.",
                "source": "Lexical Analysis",
                "action": "Inspect the real ASCII destination carefully."
            })

        # 4. @ symbol
        if has_at:
            risk_score += 25
            findings.append({
                "name": "@ Symbol in URL",
                "evidence": "'@' found in URL string",
                "severity": "HIGH",
                "explanation": "The '@' character instructs browsers to ignore preceding text and route to the destination following the '@'.",
                "source": "URL Syntax",
                "action": "Verify the true destination after the '@'."
            })

        # 5. Multiple subdomains
        if has_multiple_subdomains:
            risk_score += 15
            findings.append({
                "name": "Excessive Subdomains",
                "evidence": f"{subdomain_count} subdomains detected in '{clean_host}'",
                "severity": "MEDIUM",
                "explanation": "Attackers chain multiple subdomains (e.g. login.verification.bank.scam.com) to deceive users on mobile displays.",
                "source": "Hostname Structure",
                "action": "Examine the rightmost domain labels before the top-level domain."
            })

        # 6. Multiple hyphens
        if hyphen_count >= 2:
            risk_score += 12
            findings.append({
                "name": "Multiple Hyphens in Hostname",
                "evidence": f"{hyphen_count} hyphens present in '{clean_host}'",
                "severity": "MEDIUM",
                "explanation": "Phishing domains frequently separate fake brand terms with multiple hyphens.",
                "source": "Lexical Analysis",
                "action": "Verify against the brand's genuine single-word domain."
            })

        # 7. Shortener
        if is_shortened:
            risk_score += 15
            findings.append({
                "name": "URL Shortener Service",
                "evidence": f"Matches known shortener pattern: {raw_url[:30]}...",
                "severity": "MEDIUM",
                "explanation": "Shortened links conceal the ultimate destination, preventing pre-click visual inspection.",
                "source": "Shortener Detection",
                "action": "Use an unshortener tool to inspect the true destination before visiting."
            })

        # 8. Insecure HTTP
        if uses_http_explicit:
            risk_score += 10
            findings.append({
                "name": "Plain HTTP Protocol",
                "evidence": "URL uses unencrypted http://",
                "severity": "MEDIUM",
                "explanation": "Communications are transmitted in cleartext and vulnerable to interception or tampering.",
                "source": "Transport Protocol",
                "action": "Never transmit credentials over plain HTTP."
            })

        # 9. Suspicious TLD
        if has_suspicious_tld:
            risk_score += 15
            findings.append({
                "name": "High-Risk Top Level Domain",
                "evidence": f"Uses high-abuse TLD in '{clean_host}'",
                "severity": "MEDIUM",
                "explanation": "Free or low-cost TLDs correlate strongly with short-lived malicious campaigns.",
                "source": "TLD Intelligence",
                "action": "Check domain reputation before interacting."
            })

        # 10. Suspicious Keywords
        if detected_keywords:
            k_score = min(len(detected_keywords) * 8, 24)
            risk_score += k_score
            findings.append({
                "name": "Security-Sensitive Keywords",
                "evidence": f"Found: {', '.join(detected_keywords[:4])}",
                "severity": "MEDIUM",
                "explanation": "Keywords related to authentication, verification, and payment are heavily leveraged in credential harvesting.",
                "source": "Keyword Analysis",
                "action": "Do not enter passwords unless you explicitly requested account access."
            })

        # 11. Unusually long URL
        if url_length > 100:
            risk_score += 10
            findings.append({
                "name": "Unusually Long URL",
                "evidence": f"Length is {url_length} characters",
                "severity": "LOW",
                "explanation": "Excessive URL lengths can be utilized to push the suspicious domain past mobile browser viewport limits.",
                "source": "URL Metrics",
                "action": "Inspect full address line."
            })

    # Trusted domain safety clamp
    if trusted:
        risk_score = min(risk_score, 10)
    else:
        risk_score = min(max(risk_score, 0), 100)

    # Tabular feature vector for ML model (matching 5.urldata.csv)
    # ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']
    depth = len([s for s in parsed.path.split('/') if s])
    tabular_features = {
        "Have_IP": 1 if has_ip else 0,
        "Have_At": 1 if has_at else 0,
        "URL_Length": 1 if url_length >= 54 else 0,
        "URL_Depth": depth,
        "Redirection": 1 if has_double_slash_redirect else 0,
        "https_Domain": 1 if "https" in clean_host else 0,
        "TinyURL": 1 if is_shortened else 0,
        "Prefix/Suffix": 1 if "-" in clean_host else 0,
        # Default baseline values for live features when web scraping not requested:
        "DNS_Record": 0,
        "Web_Traffic": 0,
        "Domain_Age": 0,
        "Domain_End": 0,
        "iFrame": 0,
        "Mouse_Over": 0,
        "Right_Click": 0,
        "Web_Forwards": 0
    }

    return {
        "url": raw_url,
        "hostname": clean_host,
        "is_trusted": trusted,
        "rule_risk_score": risk_score,
        "findings": findings,
        "metrics": {
            "url_length": url_length,
            "hostname_length": host_length,
            "subdomains": subdomain_count,
            "dots": dot_count,
            "hyphens": hyphen_count,
            "digits": digit_count,
            "entropy": entropy,
            "has_ip": has_ip,
            "has_at": has_at,
            "is_shortened": is_shortened,
            "is_punycode": punycode_detected,
            "uses_http": uses_http_explicit
        },
        "tabular_features": tabular_features
    }

from urllib.parse import urlparse
import ipaddress
import re


# ==============================
# TRUSTED DOMAINS
# ==============================

TRUSTED_DOMAINS = [
    "google.com",
    "github.com",
    "youtube.com",
    "microsoft.com",
    "facebook.com",
    "amazon.com",
    "paypal.com",
    "apple.com",
    "stackoverflow.com",
    "wikipedia.org"
]

BRAND_KEYWORDS = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "github"
]

# ==============================
# SUSPICIOUS KEYWORDS
# ==============================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "banking",
    "signin",
    "wallet",
    "recover",
    "unlock",
    "support",
    "authenticate"
]


# ==============================
# URL NORMALIZATION
# ==============================

def normalize_url(url):
    """
    Add HTTPS temporarily for parsing if
    the user enters only a domain.

    Example:
    google.com
    becomes
    https://google.com
    """

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


# ==============================
# TRUSTED DOMAIN CHECK
# ==============================

def is_trusted_domain(domain):

    domain = domain.lower()

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    for trusted in TRUSTED_DOMAINS:

        # Exact domain
        if domain == trusted:
            return True

        # Valid subdomain
        # Example:
        # mail.google.com -> trusted
        if domain.endswith("." + trusted):
            return True

    return False


# ==============================
# IP ADDRESS CHECK
# ==============================

def is_ip_address(domain):

    try:
        ipaddress.ip_address(domain)
        return True

    except ValueError:
        return False


# ==============================
# MAIN URL ANALYSIS
# ==============================

def analyze_url(url):

    original_url = url.strip()

    # Check whether user explicitly supplied HTTP
    uses_http = original_url.lower().startswith("http://")

    # Normalize URL for parsing
    normalized_url = normalize_url(original_url)

    parsed = urlparse(normalized_url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Remove port
    domain = domain.split(":")[0]

    # Remove www for analysis
    clean_domain = domain

    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]


    # ==============================
    # INITIAL VALUES
    # ==============================

    risk_score = 0
    reasons = []

    trusted = is_trusted_domain(clean_domain)


    # ==============================
    # 1. TRUSTED DOMAIN
    # ==============================

    if trusted:

        reasons.append(
            "Domain matches a known trusted website"
        )

        # --------------------------------
    # Fake Trusted Domain Detection
    # --------------------------------

    if not trusted:

        for trusted_domain in TRUSTED_DOMAINS:

            if trusted_domain in domain:

                risk_score += 35

                reasons.append(
                    f"Contains trusted brand name "
                    f"'{trusted_domain}' inside a non-trusted domain"
                )

                break

    # ==============================
    # BRAND IMPERSONATION DETECTION
    # ==============================
   
    if not trusted:

        for brand in BRAND_KEYWORDS:

            if brand in clean_domain:

                risk_score += 25

                reasons.append(
                f"Possible impersonation of trusted brand: {brand}"
            )

            break


    # ==============================
    # 2. IP ADDRESS
    # ==============================

    if is_ip_address(clean_domain):

        risk_score += 35

        reasons.append(
            "Uses an IP address instead of a normal domain"
        )


    # ==============================
    # 3. @ SYMBOL
    # ==============================

    if "@" in original_url:

        risk_score += 25

        reasons.append(
            "Contains '@' symbol which can hide the real destination"
        )


    # ==============================
    # 4. LONG URL
    # ==============================

    if len(original_url) > 100:

        risk_score += 15

        reasons.append(
            "URL is unusually long"
        )


    # ==============================
    # 5. MANY SUBDOMAINS
    # ==============================

    parts = clean_domain.split(".")

    # Example:
    # login.verify.google.com = 4 parts
    # More than normal can be suspicious

    if not is_ip_address(clean_domain) and len(parts) >= 4:
        risk_score += 15
        reasons.append(
            "Contains multiple subdomains"
        )


    # ==============================
    # 6. HYPHEN CHECK
    # ==============================

    hyphen_count = clean_domain.count("-")

    if hyphen_count >= 2:

        risk_score += 12

        reasons.append(
            "Domain contains multiple hyphens"
        )

    elif hyphen_count == 1:

        risk_score += 5

        reasons.append(
            "Domain contains a hyphen"
        )


    # ==============================
    # 7. SUSPICIOUS KEYWORDS
    # ==============================

    full_text = (
        clean_domain + " " + path
    ).lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in full_text:
            found_keywords.append(keyword)


    if found_keywords:

        keyword_risk = min(
            len(found_keywords) * 8,
            30
        )

        risk_score += keyword_risk

        reasons.append(
            "Suspicious keyword(s) detected: "
            + ", ".join(found_keywords)
        )


    # ==============================
    # 8. EXPLICIT HTTP CHECK
    # ==============================

    # Only penalize if the user explicitly
    # uses insecure http://

    if uses_http:

        risk_score += 10

        reasons.append(
            "Uses insecure HTTP instead of HTTPS"
        )


    # ==============================
    # 9. EXCESSIVE NUMBERS
    # ==============================

    number_count = len(
        re.findall(r"\d", clean_domain)
    )

    if number_count >= 4:

        risk_score += 10

        reasons.append(
            "Domain contains an unusual number of digits"
        )


    # ==============================
    # 10. TRUSTED DOMAIN ADJUSTMENT
    # ==============================

    # A legitimate trusted domain should
    # not become high-risk due to normal paths.

    if trusted:

        risk_score = min(
            risk_score,
            10
        )


    # ==============================
    # FINAL SCORE LIMIT
    # ==============================

    risk_score = min(
        risk_score,
        100
    )


    # ==============================
    # RISK LEVEL
    # ==============================

    if risk_score >= 60:

        risk_level = "HIGH RISK"

    elif risk_score >= 20:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "LOW RISK"

    # ==============================
    # RETURN RESULT
    # ==============================

    return {

        "url": original_url,

        "domain": clean_domain,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "trusted": trusted,

        "reasons": reasons
    }


# ==============================
# TESTING
# ==============================

if __name__ == "__main__":

    test_urls = [

        "google.com",

        "https://github.com",

        "https://paypal.com",

        "paypal-login-secure.xyz",

        "http://192.168.1.100/login",

        "https://google.verify.account.security-login.xyz",

        "login.google.com",

        "google.com.evil-site.xyz",

        "http://amazon-security-login-update.xyz"

        "google.com.evil-site.xyz",

        "paypal.com.fake-login.xyz"

    ]


    for test_url in test_urls:

        result = analyze_url(test_url)

        print("\n" + "=" * 55)

        print("URL:", result["url"])

        print("Domain:", result["domain"])

        print("Risk Score:", result["risk_score"])

        print("Risk Level:", result["risk_level"])

        print("Trusted:", result["trusted"])

        print("\nReasons:")

        if result["reasons"]:

            for reason in result["reasons"]:

                print("-", reason)

        else:

            print(
                "- No major suspicious patterns detected"
            )
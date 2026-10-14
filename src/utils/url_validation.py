"""
URL validation, parsing, and redaction utilities.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import ipaddress
import re

SENSITIVE_PARAM_KEYS = {
    "password", "pass", "pwd", "token", "auth", "key", "apikey",
    "secret", "session", "sess", "jwt", "access_token", "refresh_token",
    "pin", "cvv", "creditcard", "card", "ssn", "email"
}

def normalize_url(url: str) -> str:
    """Ensure URL has an HTTP/HTTPS scheme and stripped whitespace."""
    if not url:
        return ""
    clean = url.strip()
    # If scheme missing, default to https:// for safe parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean):
        clean = "https://" + clean
    return clean

def is_ip_address(hostname: str) -> bool:
    """Check if hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return False
    # Strip brackets for IPv6 if present
    host = hostname.strip("[]").split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_punycode(hostname: str) -> bool:
    """Check if the hostname uses Punycode (starts with xn-- in any label)."""
    if not hostname:
        return False
    labels = hostname.lower().split(".")
    return any(label.startswith("xn--") for label in labels)

def redact_sensitive_query_params(url: str) -> str:
    """
    Redact sensitive query parameters such as tokens, passwords, sessions.
    Returns safe URL for display and logging.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
            
        queries = parse_qs(parsed.query, keep_blank_values=True)
        sanitized_queries = {}
        for k, v in queries.items():
            if k.lower() in SENSITIVE_PARAM_KEYS or any(sens in k.lower() for sens in ["token", "secret", "pass", "key"]):
                sanitized_queries[k] = ["<REDACTED>"]
            else:
                sanitized_queries[k] = v
                
        new_query = urlencode(sanitized_queries, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return url

def validate_url_input(url_str: str) -> tuple[bool, str]:
    """
    Validates user URL input.
    Returns (is_valid, error_message).
    """
    if not url_str or not url_str.strip():
        return False, "URL cannot be empty."
        
    trimmed = url_str.strip()
    if len(trimmed) > 2048:
        return False, "URL exceeds maximum permitted length of 2048 characters."
        
    # Check for whitespace in URL
    if any(c.isspace() for c in trimmed):
        return False, "URL contains invalid whitespace characters."

    # Check for forbidden/unsupported schemes in raw input
    lower_raw = trimmed.lower()
    for forbidden in ("javascript:", "data:", "file:", "mailto:", "ftp:", "about:"):
        if lower_raw.startswith(forbidden):
            return False, f"Unsupported protocol '{forbidden[:-1]}'. Only HTTP and HTTPS are permitted."

    normalized = normalize_url(trimmed)
    try:
        parsed = urlparse(normalized)
        if not parsed.netloc:
            return False, "Invalid URL: missing domain or host."
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
            
        host = parsed.hostname
        if not host:
            return False, "Invalid URL: unable to extract hostname."
            
        # Must contain dot or be valid IP or localhost
        if not is_ip_address(host) and "." not in host and host != "localhost":
            return False, f"Invalid domain name: '{host}'."
            
        return True, ""
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}"

def parse_url_components(url: str) -> dict:
    """
    Deconstructs URL into readable components for cybersecurity breakdown.
    """
    norm = normalize_url(url)
    parsed = urlparse(norm)
    # Use parsed.hostname to cleanly extract host without userinfo credentials preceding '@'
    host = (parsed.hostname or parsed.netloc.split("@")[-1].split(":")[0]).lower()
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
    
    # Registrable domain & subdomain extraction
    parts = host.split(".")
    if is_ip_address(host):
        registrable_domain = host
        subdomain = ""
    elif len(parts) >= 2:
        # Basic heuristic for registrable domain (e.g. google.com or co.uk handling)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "edu", "net") and len(parts[-1]) == 2:
            registrable_domain = ".".join(parts[-3:])
            subdomain = ".".join(parts[:-3])
        else:
            registrable_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
    else:
        registrable_domain = host
        subdomain = ""
        
    query_params = list(parse_qs(parsed.query).keys())
    
    return {
        "original_url": url,
        "normalized_url": norm,
        "redacted_url": redact_sensitive_query_params(norm),
        "scheme": parsed.scheme.lower(),
        "hostname": host,
        "registrable_domain": registrable_domain,
        "subdomain": subdomain,
        "port": port,
        "path": parsed.path or "/",
        "query_keys": query_params,
        "has_query": bool(parsed.query),
        "is_ip": is_ip_address(host),
        "is_punycode": is_punycode(host),
        "fragment": parsed.fragment
    }

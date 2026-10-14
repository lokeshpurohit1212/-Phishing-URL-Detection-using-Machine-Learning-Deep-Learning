"""
TLS and SSL certificate inspection module.
Performs socket-level certificate handshake with timeout and hostname verification.
"""

import socket
import ssl
from datetime import datetime, timezone
from src.config import NETWORK_TIMEOUT
from src.utils.logging_config import logger
from src.utils.url_validation import is_ip_address

def inspect_tls_certificate(hostname: str, port: int = 443) -> dict:
    """
    Connects to the server over TLS/SSL and extracts certificate metadata.
    Distinguishes handshake failure from security warnings.
    """
    clean_host = hostname.split(":")[0].strip().lower()
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    if is_ip_address(clean_host):
        return {
            "status": "NOT_CHECKED",
            "has_tls": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "is_expired": False,
            "hostname_matches": False,
            "findings": [{
                "name": "TLS Not Standard for Raw IP",
                "evidence": f"Target is a raw IP: {clean_host}",
                "severity": "LOW",
                "explanation": "Standard SSL certificates are issued for registered domain names, not private or ephemeral IPs.",
                "source": "TLS Inspection",
                "action": "Proceed with caution."
            }],
            "details": "Raw IP target - standard TLS validation omitted."
        }

    findings = []
    status = "COMPLETED"
    details = ""
    cert_info = {}

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL

    try:
        with socket.create_connection((clean_host, port), timeout=NETWORK_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    # In CERT_OPTIONAL, server may return empty cert if not verified
                    # Try with default verification
                    return {
                        "status": "COMPLETED",
                        "has_tls": True,
                        "issuer": "Self-signed or unverified",
                        "subject": clean_host,
                        "expires_at": None,
                        "days_until_expiry": None,
                        "is_expired": False,
                        "hostname_matches": False,
                        "findings": [{
                            "name": "Unverified / Self-Signed TLS Certificate",
                            "evidence": "Server presented an untrusted certificate chain",
                            "severity": "HIGH",
                            "explanation": "Self-signed certificates cannot guarantee the authenticity of the website operator.",
                            "source": "TLS Inspection",
                            "action": "Do not enter passwords or financial information."
                        }],
                        "details": "Untrusted or self-signed certificate."
                    }

                # Extract Issuer & Subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown Issuer"))
                subject_cn = subject_dict.get("commonName", "Unknown Subject")

                # Expiration parsing
                not_after_str = cert.get("notAfter")
                is_expired = False
                days_until_expiry = None
                expires_at_iso = None

                if not_after_str:
                    not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    expires_at_iso = not_after_dt.isoformat()
                    now = datetime.now(timezone.utc)
                    delta = (not_after_dt - now).days
                    days_until_expiry = delta

                    if delta < 0:
                        is_expired = True
                        findings.append({
                            "name": "Expired TLS Certificate",
                            "evidence": f"Certificate expired on {not_after_str} ({abs(delta)} days ago)",
                            "severity": "HIGH",
                            "explanation": "An expired certificate indicates negligence or a decommissioned infrastructure.",
                            "source": "TLS Inspection",
                            "action": "Avoid submitting credentials."
                        })
                    elif delta < 14:
                        findings.append({
                            "name": "Certificate Expiring Soon",
                            "evidence": f"Certificate expires in {delta} days",
                            "severity": "LOW",
                            "explanation": "Certificate has not been renewed yet.",
                            "source": "TLS Inspection",
                            "action": "Monitor domain health."
                        })

                # Hostname matching check
                alt_names = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                matches_host = (clean_host == subject_cn or clean_host in alt_names)
                if not matches_host:
                    # Check wildcard
                    matches_wildcard = any(
                        an.startswith("*.") and clean_host.endswith(an[1:])
                        for an in alt_names
                    )
                    matches_host = matches_wildcard

                if not matches_host and alt_names:
                    findings.append({
                        "name": "TLS Hostname Mismatch",
                        "evidence": f"Certificate CN '{subject_cn}' does not match requested host '{clean_host}'",
                        "severity": "HIGH",
                        "explanation": "A certificate issued for a different domain strongly indicates redirection or malicious proxying.",
                        "source": "TLS Inspection",
                        "action": "Disconnect immediately."
                    })

                details = f"Valid TLS from '{issuer_org}'. Expires in {days_until_expiry} days."
                return {
                    "status": "COMPLETED",
                    "has_tls": True,
                    "issuer": issuer_org,
                    "subject": subject_cn,
                    "expires_at": expires_at_iso,
                    "days_until_expiry": days_until_expiry,
                    "is_expired": is_expired,
                    "hostname_matches": matches_host,
                    "findings": findings,
                    "details": details
                }

    except (socket.timeout, TimeoutError):
        logger.warning(f"TLS handshake timed out for {clean_host}")
        return {
            "status": "TIMEOUT",
            "has_tls": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "is_expired": False,
            "hostname_matches": False,
            "findings": [],
            "details": f"Connection timed out after {NETWORK_TIMEOUT}s."
        }
    except ssl.SSLError as e:
        logger.warning(f"SSL error for {clean_host}: {e}")
        return {
            "status": "COMPLETED",
            "has_tls": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "is_expired": False,
            "hostname_matches": False,
            "findings": [{
                "name": "SSL Handshake Rejection",
                "evidence": str(e),
                "severity": "HIGH",
                "explanation": "The target server failed the cryptographic TLS negotiation.",
                "source": "TLS Inspection",
                "action": "Do not bypass certificate warnings."
            }],
            "details": f"SSL Handshake failed: {e}"
        }
    except Exception as e:
        return {
            "status": "ERROR",
            "has_tls": False,
            "issuer": None,
            "subject": None,
            "expires_at": None,
            "days_until_expiry": None,
            "is_expired": False,
            "hostname_matches": False,
            "findings": [],
            "details": f"Port 443 unreachable or connection refused: {e}"
        }

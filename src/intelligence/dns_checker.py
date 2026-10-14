"""
Domain and DNS intelligence analyzer.
Performs real DNS lookups (A, AAAA, MX, NS) with strict timeouts and error classification.
"""

import dns.resolver
from src.config import NETWORK_TIMEOUT
from src.utils.logging_config import logger
from src.utils.url_validation import is_ip_address

def analyze_dns(hostname: str) -> dict:
    """
    Queries DNS records for a given hostname.
    Distinguishes failed network lookups from unresolvable malicious indicators.
    """
    clean_host = hostname.split(":")[0].strip().lower()
    if clean_host.startswith("www."):
        clean_host = clean_host[4:]

    # Direct IP addresses don't have standard domain DNS records
    if is_ip_address(clean_host):
        return {
            "status": "COMPLETED",
            "is_resolvable": True,
            "ip_addresses": [clean_host],
            "mx_records": [],
            "ns_records": [],
            "findings": [{
                "name": "Host is Direct IP",
                "evidence": f"{clean_host} has no domain hierarchy",
                "severity": "MEDIUM",
                "explanation": "Target uses an IP directly without DNS resolution.",
                "source": "DNS Intelligence",
                "action": "Proceed with caution."
            }],
            "details": "Direct IP address - no DNS lookup performed."
        }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = NETWORK_TIMEOUT
    resolver.timeout = NETWORK_TIMEOUT

    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": []
    }
    findings = []
    lookup_status = "COMPLETED"
    details = ""

    try:
        # A records (IPv4)
        try:
            a_answers = resolver.resolve(clean_host, "A")
            records["A"] = [r.to_text() for r in a_answers]
        except dns.resolver.NoAnswer:
            pass

        # AAAA records (IPv6)
        try:
            aaaa_answers = resolver.resolve(clean_host, "AAAA")
            records["AAAA"] = [r.to_text() for r in aaaa_answers]
        except dns.resolver.NoAnswer:
            pass

        # MX records (Mail servers)
        try:
            mx_answers = resolver.resolve(clean_host, "MX")
            records["MX"] = [r.exchange.to_text().rstrip(".") for r in mx_answers]
        except dns.resolver.NoAnswer:
            pass

        # NS records (Nameservers)
        try:
            ns_answers = resolver.resolve(clean_host, "NS")
            records["NS"] = [r.target.to_text().rstrip(".") for r in ns_answers]
        except dns.resolver.NoAnswer:
            pass

        total_ips = len(records["A"]) + len(records["AAAA"])
        if total_ips == 0:
            findings.append({
                "name": "Unresolvable Domain",
                "evidence": f"No A/AAAA DNS records found for {clean_host}",
                "severity": "HIGH",
                "explanation": "The domain does not resolve to an active IP address. It may be abandoned or taken down.",
                "source": "DNS Intelligence",
                "action": "Avoid accessing unresolvable domains."
            })
            details = "Domain has no valid IP resolution."
        else:
            details = f"Resolved {len(records['A'])} IPv4 and {len(records['AAAA'])} IPv6 addresses."

    except dns.resolver.NXDOMAIN:
        lookup_status = "COMPLETED"
        findings.append({
            "name": "Non-Existent Domain (NXDOMAIN)",
            "evidence": f"DNS server reports domain '{clean_host}' does not exist",
            "severity": "HIGH",
            "explanation": "NXDOMAIN indicates the domain is not registered or currently deregistered.",
            "source": "DNS Intelligence",
            "action": "Do not trust links pointing to non-existent domains."
        })
        details = "Domain does not exist (NXDOMAIN)."

    except dns.resolver.Timeout:
        lookup_status = "TIMEOUT"
        details = f"DNS query timed out after {NETWORK_TIMEOUT}s."
        # Note: A timeout is a network failure, NOT proof of malice
        logger.warning(f"DNS query timed out for {clean_host}")

    except Exception as e:
        lookup_status = "ERROR"
        details = f"DNS query failed: {str(e)}"
        logger.warning(f"DNS lookup error for {clean_host}: {e}")

    return {
        "status": lookup_status,
        "is_resolvable": len(records["A"]) > 0 or len(records["AAAA"]) > 0,
        "ip_addresses": records["A"] + records["AAAA"],
        "mx_records": records["MX"],
        "ns_records": records["NS"],
        "findings": findings,
        "details": details
    }

"""
SSRF-Protected Safe HTTP Fetcher.
Safely retrieves public web page content for Deep Analysis while strictly blocking:
- Localhost (127.0.0.0/8, ::1)
- Private RFC 1918 IP addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Link-local and Cloud Metadata endpoints (169.254.169.254, metadata.google.internal)
- IPv6 private/link-local/loopback
- Non-HTTP/HTTPS protocols
- Revalidates destination after every redirect!
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from src.config import NETWORK_TIMEOUT, MAX_REDIRECTS, MAX_RESPONSE_BYTES
from src.utils.logging_config import logger
from src.utils.url_validation import normalize_url

# Blocked IP networks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local & Cloud Metadata (AWS, GCP, Azure)
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("::1/128"),         # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),        # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),       # IPv6 Link-Local
]

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "metadata.google.internal",
    "instance-data", "metadata"
}

def is_ip_blocked(ip_str: str) -> bool:
    """Checks whether an IP address belongs to any forbidden/private network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check standard properties
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return True
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True

def validate_ssrf_safety(url: str) -> tuple[bool, str, list[str]]:
    """
    Validates that a URL's destination host does not resolve to an internal/private IP.
    Returns (is_safe, reason, resolved_ips).
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return False, f"Forbidden protocol '{scheme}'. Only HTTP and HTTPS are permitted.", []

        hostname = parsed.netloc.split(":")[0].strip().lower()
        if not hostname:
            return False, "Missing hostname in URL.", []

        if hostname in BLOCKED_HOSTNAMES:
            return False, f"SSRF Block: Explicit blocked internal host '{hostname}'.", []

        # Resolve hostname to all candidate IP addresses
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = list(set([item[4][0] for item in addr_info]))
        except socket.gaierror:
            return False, f"DNS resolution failed for hostname '{hostname}'.", []

        if not resolved_ips:
            return False, f"No IP addresses resolved for hostname '{hostname}'.", []

        for ip in resolved_ips:
            if is_ip_blocked(ip):
                return False, f"SSRF Block: Host '{hostname}' resolves to forbidden/private IP ({ip}).", resolved_ips

        return True, "Destination is public and safe.", resolved_ips
    except Exception as e:
        return False, f"SSRF validation error: {str(e)}", []

def safe_fetch_url(url: str) -> dict:
    """
    Executes a safe GET request with strict SSRF controls, size limits, and manual redirect validation.
    """
    current_url = normalize_url(url)
    redirect_chain = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuardAI-SecurityScanner/2.5",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close"
    }

    session = requests.Session()
    session.max_redirects = 0  # Disable automatic redirects to intercept every hop!

    for hop in range(MAX_REDIRECTS + 1):
        # 1. SSRF Validation for current hop
        is_safe, reason, ips = validate_ssrf_safety(current_url)
        if not is_safe:
            logger.warning(f"SSRF Protection triggered for {current_url}: {reason}")
            return {
                "success": False,
                "status_code": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "html_content": None,
                "resolved_ips": ips,
                "error": reason,
                "ssrf_blocked": True
            }

        try:
            resp = session.get(
                current_url,
                headers=headers,
                timeout=NETWORK_TIMEOUT,
                allow_redirects=False,
                stream=True
            )

            # Check redirect status
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(current_url, location)
                redirect_chain.append(current_url)
                current_url = next_url
                continue

            # Read content up to MAX_RESPONSE_BYTES
            content_chunks = []
            total_bytes = 0
            for chunk in resp.iter_content(chunk_size=4096):
                content_chunks.append(chunk)
                total_bytes += len(chunk)
                if total_bytes >= MAX_RESPONSE_BYTES:
                    break

            raw_bytes = b"".join(content_chunks)
            encoding = resp.encoding or "utf-8"
            try:
                html_text = raw_bytes.decode(encoding, errors="replace")
            except Exception:
                html_text = raw_bytes.decode("utf-8", errors="replace")

            return {
                "success": True,
                "status_code": resp.status_code,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "html_content": html_text,
                "resolved_ips": ips,
                "error": None,
                "ssrf_blocked": False
            }

        except (requests.Timeout, socket.timeout):
            return {
                "success": False,
                "status_code": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "html_content": None,
                "resolved_ips": ips,
                "error": f"Connection timed out after {NETWORK_TIMEOUT}s.",
                "ssrf_blocked": False
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "status_code": None,
                "final_url": current_url,
                "redirect_chain": redirect_chain,
                "html_content": None,
                "resolved_ips": ips,
                "error": f"Network request failed: {str(e)}",
                "ssrf_blocked": False
            }

    return {
        "success": False,
        "status_code": None,
        "final_url": current_url,
        "redirect_chain": redirect_chain,
        "html_content": None,
        "resolved_ips": [],
        "error": f"Exceeded maximum permitted redirects ({MAX_REDIRECTS}).",
        "ssrf_blocked": False
    }

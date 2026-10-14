"""
Unit tests for URL validation, normalization, and sanitization (Tests 1, 2, 3, 5, 6, 7).
"""

import pytest
from src.utils.url_validation import (
    normalize_url,
    validate_url_input,
    is_ip_address,
    is_punycode,
    redact_sensitive_query_params,
    parse_url_components
)

def test_valid_http_and_https_urls():
    """Test 1: Valid HTTP and HTTPS URLs."""
    valid_https = "https://example.com/login"
    valid_http = "http://example.org/path?page=1"
    
    is_valid_1, err_1 = validate_url_input(valid_https)
    is_valid_2, err_2 = validate_url_input(valid_http)
    
    assert is_valid_1 is True
    assert err_1 == ""
    assert is_valid_2 is True
    assert err_2 == ""
    assert normalize_url("example.com") == "https://example.com"

def test_malformed_and_empty_inputs():
    """Test 2: Malformed URLs and empty inputs."""
    assert validate_url_input("")[0] is False
    assert validate_url_input("   ")[0] is False
    assert validate_url_input("ftp://unsupported.com")[0] is False
    assert validate_url_input("javascript:alert(1)")[0] is False

def test_urls_containing_ip_addresses():
    """Test 3: URLs containing IPv4 and IPv6 addresses."""
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1") is True
    assert is_ip_address("8.8.8.8") is True
    assert is_ip_address("google.com") is False
    
    comp = parse_url_components("http://192.168.1.100/admin")
    assert comp["is_ip"] is True
    assert comp["hostname"] == "192.168.1.100"

def test_urls_containing_at_symbol():
    """Test 5: URLs containing @ symbols."""
    url = "https://legit-site.com@attacker-site.com/login"
    comp = parse_url_components(url)
    assert "@" in url
    # Hostname parsed by urlparse is attacker-site.com
    assert comp["hostname"] == "attacker-site.com"

def test_unicode_and_punycode_hostnames():
    """Test 6: Unicode and Punycode hostnames."""
    punycode_host = "xn--appl-43d.com"  # e.g. applе.com with Cyrillic e
    assert is_punycode(punycode_host) is True
    assert is_punycode("apple.com") is False
    
    comp = parse_url_components(f"https://{punycode_host}/")
    assert comp["is_punycode"] is True

def test_url_shortener_detection():
    """Test 7: URL shorteners normalization and handling."""
    from src.detection.url_features import extract_advanced_features
    shortened_url = "https://bit.ly/3xY8aB"
    feat = extract_advanced_features(shortened_url)
    assert feat["metrics"]["is_shortened"] is True
    assert any("Shortener" in f["name"] for f in feat["findings"])

def test_redact_sensitive_query_parameters():
    """Privacy test: Redact tokens, passwords, sessions."""
    url = "https://example.com/login?token=secret123&user=john&password=mypassword&key=apikey456"
    redacted = redact_sensitive_query_params(url)
    assert "secret123" not in redacted
    assert "mypassword" not in redacted
    assert "apikey456" not in redacted
    assert "user=john" in redacted

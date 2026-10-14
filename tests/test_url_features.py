"""
Unit tests for URL feature extraction and heuristics (Tests 4, 16).
"""

import pytest
from src.detection.url_features import extract_advanced_features, is_trusted_domain
from src.comparison.brand_comparison import compare_domains

def test_misleading_subdomains():
    """Test 4: URLs with misleading subdomains and brand mimicry."""
    url = "https://paypal.com.account-update.xyz/login"
    features = extract_advanced_features(url)
    
    assert features["is_trusted"] is False
    assert features["rule_risk_score"] > 30
    assert any("Brand Name" in f["name"] or "Subdomain" in f["name"] for f in features["findings"])

def test_trusted_domains():
    """Test that authentic trusted domains receive low baseline risk."""
    assert is_trusted_domain("google.com") is True
    assert is_trusted_domain("mail.google.com") is True
    assert is_trusted_domain("github.com") is True
    assert is_trusted_domain("evil-google.com") is False
    
    feat = extract_advanced_features("https://github.com/security")
    assert feat["is_trusted"] is True
    assert feat["rule_risk_score"] <= 10

def test_brand_comparison_typosquatting():
    """Test typosquatting and homoglyph detection in domain comparison."""
    comp1 = compare_domains("goog1e.com", "google.com")
    assert comp1["similarity_score"] >= 80
    assert any("Homoglyph" in t["trick"] or "Typosquatting" in t["trick"] for t in comp1["detected_tricks"])

    comp2 = compare_domains("paypal.com.verify-billing.xyz", "paypal.com")
    assert any("Deceptive Subdomain" in t["trick"] for t in comp2["detected_tricks"])

def test_entropy_and_special_characters():
    """Test entropy calculation and special character detection."""
    high_entropy_url = "https://x89q2k4m9v1z0a7.top/gateway"
    feat = extract_advanced_features(high_entropy_url)
    assert feat["metrics"]["entropy"] > 3.0
    assert feat["rule_risk_score"] > 0

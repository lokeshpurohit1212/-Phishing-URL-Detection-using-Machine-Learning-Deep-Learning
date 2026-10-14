"""
Automated validation suite for Cloudflare Dashboard Design System,
Light/Dark/System theme generation, and 4-verdict evidence classification.
"""

import pytest
from unittest.mock import patch
from src.ui.theme import generate_theme_css, get_theme, get_plotly_layout
from src.detection.verdict_engine import MultiLayerDetectionEngine

def test_theme_tokens_and_cloudflare_orange():
    """Confirms Cloudflare Orange #f38020 is authoritative across both themes."""
    light = get_theme("Light")
    dark = get_theme("Dark")
    assert light["accent_orange"] == "#f38020"
    assert dark["accent_orange"] == "#f38020"
    assert light["bg_page"] == "#f3f4f6"
    assert dark["bg_page"] == "#111827"

def test_theme_css_generation_light_dark_system():
    """Verifies generated CSS contains proper variables and system media queries."""
    css_light = generate_theme_css("Light")
    assert "--cf-orange: #f38020" in css_light
    assert "--cf-bg-page: #f3f4f6" in css_light

    css_dark = generate_theme_css("Dark")
    assert "--cf-bg-page: #111827" in css_dark

    css_system = generate_theme_css("System")
    assert "@media (prefers-color-scheme: dark)" in css_system
    assert "--cf-bg-page: #f3f4f6" in css_system
    assert "--cf-bg-page: #111827" in css_system

def test_plotly_layout_themes():
    """Confirms chart layouts match active theme background."""
    layout_light = get_plotly_layout("Light")
    layout_dark = get_plotly_layout("Dark")
    assert layout_light["plot_bgcolor"] == "#ffffff"
    assert layout_dark["plot_bgcolor"] == "#1f2937"

def test_four_verdict_classifications():
    """Confirms all returned verdicts strictly map to the four evidence-based states."""
    engine = MultiLayerDetectionEngine()
    
    # 1. Clean institutional URL -> No Phishing Indicators Detected
    res_clean = engine.scan_url("https://portal.stanford.edu/student/login", include_dns=False, include_tls=False, include_threat_intel=False)
    assert res_clean["verdict"] == "No Phishing Indicators Detected"
    assert res_clean["verdict_badge"] == "SAFE"

    # 2. Known phishing scam -> Likely Phishing
    res_phish = engine.scan_url("http://paypal-security-verification.xyz/login", include_dns=False, include_tls=False, include_threat_intel=False)
    assert res_phish["verdict"] == "Likely Phishing"
    assert res_phish["verdict_badge"] == "CRITICAL_PHISHING"

    # 3. Direct IP admin host -> Suspicious
    res_susp = engine.scan_url("http://192.168.1.1/admin-login", include_dns=False, include_tls=False, include_threat_intel=False)
    assert res_susp["verdict"] == "Suspicious"
    assert res_susp["verdict_badge"] == "SUSPICIOUS"

def test_inconclusive_verdict_when_models_unavailable():
    """Confirms Inconclusive is assigned when models are unavailable and no threat indicators exist."""
    engine = MultiLayerDetectionEngine()
    
    with patch.object(engine.cnn, "predict", return_value={"available": False, "probability": None, "label": "UNAVAILABLE"}), \
         patch.object(engine.ml, "predict", return_value={"available": False, "probability": None, "label": "UNAVAILABLE"}):
        
        # Test on a generic neutral domain with no threat signals
        res = engine.scan_url("http://example-neutral-testing-123.com", include_dns=False, include_tls=False, include_threat_intel=False)
        assert res["verdict"] == "Inconclusive"
        assert res["verdict_badge"] == "INCONCLUSIVE"

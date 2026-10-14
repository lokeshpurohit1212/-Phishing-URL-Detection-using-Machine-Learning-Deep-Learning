"""
Unit tests for Model inference, missing model handling, and verdict logic (Tests 12, 16).
"""

from unittest.mock import patch
import pytest
from src.detection.url_classifier import CNNURLClassifier
from src.detection.ml_models import TabularMLDetector
from src.detection.verdict_engine import MultiLayerDetectionEngine

def test_cnn_model_loaded_and_inference():
    """Test 16: CNN Model loaded and producing valid probabilities."""
    classifier = CNNURLClassifier()
    assert classifier.is_available is True
    
    res = classifier.predict("google.com")
    assert res["available"] is True
    assert 0.0 <= res["probability"] <= 1.0
    assert res["label"] in ("LEGITIMATE", "PHISHING")

def test_missing_model_files_graceful_fallback():
    """Test 12: Missing model files diagnostic reporting without crashing."""
    with patch("pathlib.Path.exists") as mock_exists:
        mock_exists.return_value = False
        
        # Instantiate new instance with mocked missing file
        dummy_classifier = CNNURLClassifier.__new__(CNNURLClassifier)
        dummy_classifier._is_loaded = False
        dummy_classifier._load_error = "Model file not found"
        
        res = dummy_classifier.predict("https://example.com")
        assert res["available"] is False
        assert res["label"] == "UNAVAILABLE"
        assert "not found" in res["error"]

def test_verdict_engine_thresholds_and_aggregation():
    """Test 16: Verdict mapping and multi-engine risk score bounds."""
    engine = MultiLayerDetectionEngine()
    
    # Trusted site
    res_safe = engine.scan_url("https://google.com", include_dns=False, include_tls=False, include_threat_intel=False)
    assert res_safe["risk_score"] < 40
    assert res_safe["verdict"] == "No Phishing Indicators Detected"

    # Known phishing-style URL
    res_phish = engine.scan_url("http://192.168.1.100/login", include_dns=False, include_tls=False, include_threat_intel=False)
    assert res_phish["risk_score"] >= 40
    assert res_phish["verdict"] in ("Likely Phishing", "Suspicious — Further Verification Recommended")

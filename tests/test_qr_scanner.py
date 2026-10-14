"""
Unit and integration tests for Quishing (QR code phishing) detection engine.
"""

import pytest
import io
from PIL import Image

from src.inspection.qr_scanner import (
    decode_qr_image,
    generate_qr_image_bytes,
    get_sample_qr_codes,
)
from src.detection.verdict_engine import MultiLayerDetectionEngine


@pytest.fixture
def detection_engine():
    return MultiLayerDetectionEngine()


def test_generate_and_decode_qr_url():
    """Verify QR code generation and successful decoding of an HTTP URL."""
    test_url = "https://portal.stanford.edu/student/login"
    img_bytes = generate_qr_image_bytes(test_url)
    assert isinstance(img_bytes, bytes)
    assert len(img_bytes) > 0

    res = decode_qr_image(img_bytes)
    assert res["success"] is True
    assert res["found"] is True
    assert res["is_url"] is True
    assert res["payload_type"] == "URL"
    assert res["sanitized_url"] == test_url
    assert res["payload"] == test_url
    assert res["width"] > 0
    assert res["height"] > 0


def test_decode_plain_text_qr():
    """Verify QR code containing non-URL text is correctly categorized as PLAIN_TEXT."""
    text_payload = "WIFI:S:MyGuestNetwork;T:WPA;P:SecretKey123;;"
    img_bytes = generate_qr_image_bytes(text_payload)
    
    res = decode_qr_image(img_bytes)
    assert res["success"] is True
    assert res["found"] is True
    assert res["is_url"] is False
    assert res["payload_type"] == "PLAIN_TEXT"
    assert res["payload"] == text_payload
    assert res["sanitized_url"] is None


def test_decode_pil_image_input():
    """Verify decode_qr_image accepts a PIL Image instance directly."""
    test_url = "http://paypal-security-verification.xyz/login"
    img_bytes = generate_qr_image_bytes(test_url)
    pil_img = Image.open(io.BytesIO(img_bytes))

    res = decode_qr_image(pil_img)
    assert res["success"] is True
    assert res["found"] is True
    assert res["is_url"] is True
    assert res["sanitized_url"] == test_url


def test_decode_invalid_corrupt_data():
    """Verify decode_qr_image handles corrupted or non-image bytes gracefully without crashing."""
    corrupt_bytes = b"NOT_A_VALID_IMAGE_DATA_BYTES_12345"
    res = decode_qr_image(corrupt_bytes)
    assert res["success"] is False
    assert res["found"] is False
    assert res["error"] is not None


def test_decode_blank_image():
    """Verify decoding a blank white image returns found=False without error."""
    blank = Image.new("RGB", (200, 200), color="white")
    res = decode_qr_image(blank)
    assert res["success"] is True
    assert res["found"] is False
    assert res["payload"] == ""


def test_sample_qr_codes_catalog():
    """Verify get_sample_qr_codes provides pre-rendered samples with all required metadata."""
    samples = get_sample_qr_codes()
    assert len(samples) >= 4
    assert "paypal_phish" in samples
    assert "stanford_clean" in samples
    assert "subdomain_trap" in samples
    assert "wifi_text" in samples

    for key, item in samples.items():
        assert "name" in item
        assert "threat_label" in item
        assert "category" in item
        assert "description" in item
        assert "png_bytes" in item
        assert isinstance(item["png_bytes"], bytes)
        assert len(item["png_bytes"]) > 0


def test_quishing_pipeline_end_to_end(detection_engine):
    """
    Test full Quishing pipeline:
    1. Decode QR code representing a phishing lure.
    2. Pass extracted sanitized URL into MultiLayerDetectionEngine.
    3. Assert threat detection flags phishing verdict.
    """
    samples = get_sample_qr_codes()
    phish_qr_bytes = samples["paypal_phish"]["png_bytes"]

    # Step 1: Decode
    decoded = decode_qr_image(phish_qr_bytes)
    assert decoded["found"] is True
    assert decoded["is_url"] is True
    extracted_url = decoded["sanitized_url"]

    # Step 2: Multi-layer scan
    scan_result = detection_engine.scan_url(
        extracted_url,
        include_dns=False,
        include_tls=False,
        include_threat_intel=False
    )

    # Step 3: Assert detection results
    assert scan_result["verdict_badge"] == "CRITICAL_PHISHING"
    assert scan_result["risk_score"] >= 70
    assert any("PAYPAL" in f["evidence"].upper() or "BRAND" in f["name"].upper() for f in scan_result["findings"])

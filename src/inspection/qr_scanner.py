"""
Quishing (QR Code Phishing) Inspection and Decoding Engine.
Provides robust multi-strategy QR code decoding, payload classification,
and test sample generation for FlareShield.
"""

import io
import re
from typing import Any, Optional, Union
import numpy as np
import cv2
import qrcode
from PIL import Image

from src.utils.logging_config import logger
from src.utils.url_validation import validate_url_input, normalize_url


def _get_detector() -> Any:
    """Instantiate the most accurate available OpenCV QR detector."""
    if hasattr(cv2, "QRCodeDetectorAruco"):
        try:
            return cv2.QRCodeDetectorAruco()
        except Exception:
            pass
    return cv2.QRCodeDetector()


def _convert_to_cv2(image_input: Union[str, bytes, io.BytesIO, Image.Image, Any]) -> tuple[Optional[np.ndarray], tuple[int, int]]:
    """
    Safely convert various input types (bytes, PIL Image, Streamlit UploadedFile, file path)
    into an OpenCV BGR numpy array. Returns (cv_image, (width, height)).
    """
    try:
        if isinstance(image_input, (str, bytes, bytearray, io.BytesIO)) or hasattr(image_input, "read"):
            if hasattr(image_input, "read"):
                # Handle Streamlit UploadedFile or file-like buffer
                image_input.seek(0)
                raw_bytes = image_input.read()
            elif isinstance(image_input, (bytes, bytearray)):
                raw_bytes = bytes(image_input)
            elif isinstance(image_input, io.BytesIO):
                raw_bytes = image_input.getvalue()
            elif isinstance(image_input, str):
                # Path on disk
                with open(image_input, "rb") as f:
                    raw_bytes = f.read()
            else:
                return None, (0, 0)

            # Load with PIL first to guarantee support for WEBP, PNG, JPEG, TIFF, BMP
            pil_img = Image.open(io.BytesIO(raw_bytes))
        elif isinstance(image_input, Image.Image):
            pil_img = image_input
        elif isinstance(image_input, np.ndarray):
            h, w = image_input.shape[:2]
            return image_input, (w, h)
        else:
            return None, (0, 0)

        width, height = pil_img.size

        # Convert PIL to RGB then BGR for OpenCV
        if pil_img.mode != "RGB":
            pil_img = pil_img.convert("RGB")
        
        rgb_arr = np.array(pil_img)
        cv_bgr = cv2.cvtColor(rgb_arr, cv2.COLOR_RGB2BGR)
        return cv_bgr, (width, height)
    except Exception as e:
        logger.error(f"Error converting input to OpenCV image: {e}")
        return None, (0, 0)


def decode_qr_image(image_input: Union[str, bytes, io.BytesIO, Image.Image, Any]) -> dict[str, Any]:
    """
    Decodes an uploaded or provided QR code image using a multi-pass pipeline:
    1. Direct pass with OpenCV QR detector.
    2. Grayscale & contrast enhancement (CLAHE).
    3. Otsu binary thresholding for low-contrast/noisy images.
    4. Image inversion (for white-on-dark QR codes).
    5. Multi-detection fallback.

    Returns a comprehensive result dictionary:
    {
        "success": bool,
        "found": bool,
        "payload": str,
        "payload_type": "URL" | "PLAIN_TEXT" | "EMPTY",
        "is_url": bool,
        "sanitized_url": Optional[str],
        "validation_error": Optional[str],
        "width": int,
        "height": int,
        "points": Optional[list],
        "strategy": str,
        "error": Optional[str]
    }
    """
    result: dict[str, Any] = {
        "success": False,
        "found": False,
        "payload": "",
        "payload_type": "EMPTY",
        "is_url": False,
        "sanitized_url": None,
        "validation_error": None,
        "width": 0,
        "height": 0,
        "points": None,
        "strategy": "none",
        "error": None
    }

    cv_img, (width, height) = _convert_to_cv2(image_input)
    if cv_img is None or width == 0 or height == 0:
        result["error"] = "Unable to parse or decode image format. Ensure file is a valid PNG, JPG, or WEBP image."
        return result

    result["width"] = width
    result["height"] = height
    detector = _get_detector()

    # Strategy 1: Standard Direct Detection
    try:
        decoded_text, points, _ = detector.detectAndDecode(cv_img)
        if decoded_text and decoded_text.strip():
            return _format_qr_result(result, decoded_text.strip(), points, "standard")
    except Exception as e:
        logger.debug(f"Direct QR detection pass failed: {e}")

    # Strategy 2: Grayscale + CLAHE (Contrast Limited Adaptive Histogram Equalization)
    try:
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        decoded_text, points, _ = detector.detectAndDecode(enhanced)
        if decoded_text and decoded_text.strip():
            return _format_qr_result(result, decoded_text.strip(), points, "clahe_enhanced")
    except Exception as e:
        logger.debug(f"CLAHE QR detection pass failed: {e}")

    # Strategy 3: Otsu Binary Thresholding
    try:
        if "gray" not in locals():
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        decoded_text, points, _ = detector.detectAndDecode(thresh)
        if decoded_text and decoded_text.strip():
            return _format_qr_result(result, decoded_text.strip(), points, "otsu_threshold")
    except Exception as e:
        logger.debug(f"Otsu threshold QR detection pass failed: {e}")

    # Strategy 4: Inverted Thresholding (White QR on Dark Background)
    try:
        inverted = cv2.bitwise_not(gray)
        decoded_text, points, _ = detector.detectAndDecode(inverted)
        if decoded_text and decoded_text.strip():
            return _format_qr_result(result, decoded_text.strip(), points, "inverted")
    except Exception as e:
        logger.debug(f"Inverted QR detection pass failed: {e}")

    # Strategy 5: Multi-detection fallback
    try:
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(cv_img)
        if retval and decoded_info:
            for text in decoded_info:
                if text and text.strip():
                    return _format_qr_result(result, text.strip(), points, "multi_detector")
    except Exception as e:
        logger.debug(f"Multi-detection QR pass failed: {e}")

    # No QR code found across all strategies
    result["success"] = True
    result["found"] = False
    result["error"] = "No valid QR code pattern or barcode markers could be recognized in the uploaded image."
    return result


def _format_qr_result(base_dict: dict[str, Any], payload: str, points: Any, strategy: str) -> dict[str, Any]:
    """Helper to structure and validate payload data."""
    base_dict["success"] = True
    base_dict["found"] = True
    base_dict["payload"] = payload
    base_dict["strategy"] = strategy

    if points is not None:
        try:
            base_dict["points"] = points.tolist()
        except Exception:
            base_dict["points"] = None

    # Determine if payload is an HTTP/HTTPS URL or web link
    norm_url = normalize_url(payload)
    is_valid, err_msg = validate_url_input(norm_url)

    # Secondary check: does it look like a web link even if missing scheme?
    looks_like_url = bool(re.match(r"^(https?://|www\.)[a-zA-Z0-9-.]+\.[a-zA-Z]{2,}", payload, re.IGNORECASE))

    if is_valid or looks_like_url:
        base_dict["is_url"] = True
        base_dict["payload_type"] = "URL"
        base_dict["sanitized_url"] = norm_url
        if not is_valid:
            base_dict["validation_error"] = err_msg
    else:
        base_dict["is_url"] = False
        base_dict["payload_type"] = "PLAIN_TEXT"
        base_dict["sanitized_url"] = None

    return base_dict


def generate_qr_image_bytes(data: str, box_size: int = 10, border: int = 4, fill_color: str = "black", back_color: str = "white") -> bytes:
    """Generates PNG bytes for a QR code encoding the provided data."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color=fill_color, back_color=back_color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


_SAMPLE_CATALOG: Optional[dict[str, dict[str, Any]]] = None

def get_sample_qr_codes() -> dict[str, dict[str, Any]]:
    """
    Returns a catalog of pre-configured demonstration QR codes,
    with title, URL payload, threat category, description, and pre-rendered PNG bytes.
    """
    global _SAMPLE_CATALOG
    if _SAMPLE_CATALOG is not None:
        return _SAMPLE_CATALOG

    samples: dict[str, dict[str, Any]] = {
        "paypal_phish": {
            "id": "paypal_phish",
            "name": "🔴 PayPal Credential Harvester (Quishing)",
            "url": "http://paypal-security-verification.xyz/login",
            "threat_label": "CRITICAL PHISHING",
            "badge_color": "danger",
            "category": "Credential Harvesting Quishing",
            "description": "Simulates a deceptive QR code placed on physical notices or emails claiming immediate account suspension, redirecting mobile users to a fake PayPal portal.",
            "expected_verdict": "CRITICAL_PHISHING",
        },
        "stanford_clean": {
            "id": "stanford_clean",
            "name": "🎓 Stanford University Portal (Clean Institutional)",
            "url": "https://portal.stanford.edu/student/login",
            "threat_label": "GENUINE / BENIGN",
            "badge_color": "safe",
            "category": "Academic Portal (PSL Protected)",
            "description": "Legitimate institutional student portal. Demonstrates how Public Suffix List boundary rules and institutional allowlists protect genuine domains from false alarms.",
            "expected_verdict": "BENIGN",
        },
        "subdomain_trap": {
            "id": "subdomain_trap",
            "name": "🟡 Subdomain Camouflage Trap (Lookalike)",
            "url": "http://stanford.edu.account-update.xyz/login",
            "threat_label": "SUSPICIOUS LOOKALIKE",
            "badge_color": "warning",
            "category": "Subdomain Impersonation",
            "description": "Attackers exploit user trust by prefixing 'stanford.edu' onto an untrusted '.xyz' root domain to deceive mobile victims who cannot view the full URL on their phone.",
            "expected_verdict": "SUSPICIOUS",
        },
        "oxford_mail": {
            "id": "oxford_mail",
            "name": "🎓 Oxford University Webmail (Clean)",
            "url": "https://mail.ox.ac.uk/owa",
            "threat_label": "GENUINE / BENIGN",
            "badge_color": "safe",
            "category": "Educational Webmail",
            "description": "Legitimate institutional email login endpoint verified via educational eTLD+1 boundary protection.",
            "expected_verdict": "BENIGN",
        },
        "wifi_text": {
            "id": "wifi_text",
            "name": "📶 Raw Wi-Fi Configuration (Non-URL Payload)",
            "url": "",
            "raw_payload": "WIFI:S:FlareShield-Secure-Guest;T:WPA;P:K9#m$L82vP!q;;",
            "threat_label": "NON-URL METADATA",
            "badge_color": "neutral",
            "category": "Non-Web Payload",
            "description": "Validates FlareShield's safe input handling when encountering non-HTTP QR payloads such as Wi-Fi credentials or raw cryptographic keys.",
            "expected_verdict": "NON_URL",
        }
    }

    # Generate PNG bytes for each sample
    for key, data in samples.items():
        payload = data.get("url") or data.get("raw_payload", "")
        data["png_bytes"] = generate_qr_image_bytes(payload)

    _SAMPLE_CATALOG = samples
    return _SAMPLE_CATALOG

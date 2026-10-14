"""
Central configuration module for PhishGuard AI.
Loads settings from environment variables and defines paths and defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
SRC_DIR = Path(__file__).resolve().parent
BASE_DIR = SRC_DIR.parent
MODEL_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"

# Load .env if present
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)

# Application metadata
APP_NAME = "PhishGuard AI"
APP_SUBTITLE = "Enterprise Multi-Layer Phishing & Cyber Threat Intelligence Platform"
APP_VERSION = "2.5.0"

# Model paths
CNN_MODEL_PATH = MODEL_DIR / "phishing_cnn_model.h5"
TOKENIZER_PATH = MODEL_DIR / "tokenizer.pkl"
XGBOOST_MODEL_PATH = MODEL_DIR / "xgboost_model.pkl"
RANDOM_FOREST_MODEL_PATH = MODEL_DIR / "random_forest_model.pkl"
METRICS_PATH = MODEL_DIR / "model_metrics.json"

# Database
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", DATA_DIR / "scans.db"))

# Threat Intelligence API keys
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "").strip()

# Network & Security Timeouts
NETWORK_TIMEOUT = float(os.getenv("NETWORK_TIMEOUT_SECONDS", "3.5"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "3"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "524288"))  # 512 KB

# Detection Thresholds
PHISHING_THRESHOLD = 0.70
SUSPICIOUS_THRESHOLD = 0.40

# Trusted brand keywords for impersonation checks
TRUSTED_BRANDS = [
    "google", "paypal", "microsoft", "apple", "amazon", "facebook",
    "instagram", "whatsapp", "netflix", "github", "twitter", "linkedin",
    "dropbox", "chase", "bankofamerica", "wellsfargo", "citibank",
    "adobe", "spotify", "binance", "coinbase"
]

# Trusted high-reputation domains (for whitelist/baseline)
TRUSTED_DOMAINS = [
    "google.com", "github.com", "youtube.com", "microsoft.com",
    "facebook.com", "amazon.com", "paypal.com", "apple.com",
    "stackoverflow.com", "wikipedia.org", "linkedin.com", "netflix.com",
    "twitter.com", "instagram.com", "openai.com", "cloudflare.com"
]

# Suspicious keywords commonly seen in phishing paths/subdomains
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "confirmation", "password", "banking", "signin",
    "wallet", "recover", "recovery", "unlock", "support", "authenticate",
    "billing", "invoice", "validate", "suspended", "urgent", "bonus", "reward"
]

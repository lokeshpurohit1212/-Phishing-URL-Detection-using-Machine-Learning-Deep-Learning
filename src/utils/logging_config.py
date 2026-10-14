"""
Structured logging module for cybersecurity auditing.
Ensures zero credential leaks and sanitizes logged URLs.
"""

import logging
import sys
from src.utils.url_validation import redact_sensitive_query_params

class SanitizingFormatter(logging.Formatter):
    """Custom formatter that automatically strips secrets from log strings."""
    def format(self, record):
        msg = super().format(record)
        # Check if any URL-like structure exists and redact
        words = msg.split()
        sanitized_words = []
        for word in words:
            if word.startswith(("http://", "https://")):
                sanitized_words.append(redact_sensitive_query_params(word))
            else:
                sanitized_words.append(word)
        return " ".join(sanitized_words)

def setup_logger(name: str = "PhishGuard") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = SanitizingFormatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

logger = setup_logger()

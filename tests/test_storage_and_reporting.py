"""
Unit tests for Database storage, history, bulk parsing, and reports (Tests 15, 17, 18).
"""

import tempfile
import json
import pytest
from pathlib import Path
from src.storage.scan_repository import ScanRepository
from src.reporting.report_generator import (
    generate_json_report,
    generate_csv_report,
    generate_text_summary
)
from src.utils.url_validation import validate_url_input

def test_database_crud_operations():
    """Test 17: Database persistence, audit history, and stats aggregation."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_db_path = tf.name

    repo = ScanRepository(db_path=temp_db_path)
    
    # 1. Save scan
    scan_id = repo.save_scan({
        "url": "https://suspicious-sample.xyz/auth?token=supersecret123",
        "verdict": "Likely Phishing",
        "risk_score": 85,
        "cnn_probability": 0.95,
        "ml_probability": 0.88,
        "model_version": "2.5.0",
        "scan_duration_ms": 120,
        "findings": [{"name": "Suspicious TLD", "severity": "HIGH"}],
        "engine_results": {"cnn": "WARNING_DETECTED"}
    })
    
    assert scan_id > 0
    
    # 2. Retrieve scan
    record = repo.get_scan_by_id(scan_id)
    assert record is not None
    assert record["verdict"] == "Likely Phishing"
    assert record["risk_score"] == 85
    # Token must be redacted in stored record!
    assert "supersecret123" not in record["redacted_url"]
    
    # 3. Retrieve recent scans
    recent = repo.get_recent_scans(limit=10)
    assert len(recent) == 1
    
    # 4. Aggregated statistics
    stats = repo.get_scan_statistics()
    assert stats["total_scans"] == 1
    assert stats["phishing_count"] == 1
    assert stats["safe_count"] == 0
    
    # 5. Delete scan
    assert repo.delete_scan(scan_id) is True
    assert repo.get_scan_by_id(scan_id) is None

def test_bulk_parsing_with_malformed_records():
    """Test 15: Bulk uploads containing empty rows and malformed strings."""
    raw_lines = [
        "https://google.com",
        "",                         # Empty line
        "not a valid url here",     # Malformed
        "   ",                      # Whitespace
        "http://paypal-fake.com",
        "ftp://unsupported.org"     # Invalid scheme
    ]

    valid_urls = []
    rejected_urls = []

    for line in raw_lines:
        line_str = line.strip()
        if not line_str:
            continue
        is_valid, err = validate_url_input(line_str)
        if is_valid:
            valid_urls.append(line_str)
        else:
            rejected_urls.append((line_str, err))

    assert len(valid_urls) == 2
    assert "https://google.com" in valid_urls
    assert "http://paypal-fake.com" in valid_urls
    assert len(rejected_urls) == 2
    assert any("ftp" in r[1] for r in rejected_urls)

def test_exported_reports():
    """Test 18: Exported reports generation (JSON, CSV, Plaintext)."""
    sample_scan = {
        "url": "https://test-report-domain.com/login?token=mytoken999",
        "redacted_url": "https://test-report-domain.com/login?token=<REDACTED>",
        "verdict": "Suspicious — Further Verification Recommended",
        "risk_score": 65,
        "cnn_probability": 0.62,
        "ml_probability": 0.58,
        "rule_risk_score": 45,
        "is_trusted": False,
        "model_version": "2.5.0",
        "summary_statement": "Multiple suspicious signals detected.",
        "findings": [
            {"name": "Suspicious Keyword", "evidence": "login", "severity": "MEDIUM", "explanation": "Login prompt", "action": "Verify host"}
        ],
        "recommended_actions": ["Do not enter passwords"],
        "timestamp": "2026-03-30 12:00:00 UTC",
        "scan_duration_ms": 250
    }

    # JSON export test
    json_out = generate_json_report(sample_scan)
    parsed_json = json.loads(json_out)
    assert parsed_json["risk_score"] == 65
    assert "mytoken999" not in json_out

    # CSV export test
    csv_out = generate_csv_report([sample_scan])
    assert "Scan Timestamp" in csv_out
    assert "Suspicious" in csv_out
    assert "mytoken999" not in csv_out

    # Text summary test
    txt_out = generate_text_summary(sample_scan)
    assert "PHISHGUARD AI" in txt_out
    assert "Risk Score:" in txt_out
    assert "mytoken999" not in txt_out

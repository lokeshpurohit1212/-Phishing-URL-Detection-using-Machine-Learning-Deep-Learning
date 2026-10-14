"""
CLI Phishing Detection Utility.
Supports single URL, multiple URLs, and file input (-f).
Integrates both the 1D-CNN Model and the Multi-Layer Security Engine.
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.detection.verdict_engine import MultiLayerDetectionEngine
from src.utils.url_validation import validate_url_input, redact_sensitive_query_params
from src.reporting.report_generator import generate_csv_report

def main():
    if len(sys.argv) < 2:
        print("Usage: python src/predict.py <URL1> <URL2> ... OR python src/predict.py -f urls.txt")
        sys.exit(1)

    urls = []
    if sys.argv[1] == "-f":
        if len(sys.argv) < 3:
            print("Error: Missing file path. Usage: python src/predict.py -f urls.txt")
            sys.exit(1)
        file_path = sys.argv[2]
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file '{file_path}': {e}")
            sys.exit(1)
    else:
        urls = [arg.strip() for arg in sys.argv[1:] if arg.strip()]

    if not urls:
        print("No URLs supplied for analysis.")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("      PHISHGUARD AI - MULTI-LAYER CLI SECURITY SCANNER       ")
    print("=" * 70)

    engine = MultiLayerDetectionEngine()
    results = []

    header = f"{'TARGET URL':<35} | {'VERDICT':<20} | {'RISK':<5} | {'CNN PROB':<8}"
    print(header)
    print("-" * 75)

    for raw_url in urls:
        is_v, err = validate_url_input(raw_url)
        if not is_v:
            print(f"{raw_url[:35]:<35} | INVALID INPUT        | N/A   | N/A")
            continue

        res = engine.scan_url(raw_url, include_dns=False, include_tls=False, include_threat_intel=False)
        results.append(res)

        cnn_p = f"{res['cnn_probability']:.1%}" if res['cnn_probability'] is not None else "N/A"
        r_url = res['redacted_url'][:35]
        v_str = res['verdict'][:20]
        risk_str = f"{res['risk_score']}"

        print(f"{r_url:<35} | {v_str:<20} | {risk_str:<5} | {cnn_p:<8}")

    print("=" * 75)
    print(f"Total URLs audited: {len(results)}")

if __name__ == "__main__":
    main()
"""
Exportable report generation utilities.
Generates structured JSON, CSV, and formatted text summaries of security assessments.
"""

import json
import csv
import io
from src.utils.url_validation import redact_sensitive_query_params

def generate_json_report(scan_result: dict) -> str:
    """Generates a sanitized JSON export string of a scan result."""
    clean_copy = dict(scan_result)
    # Ensure URL is redacted
    clean_copy["url"] = redact_sensitive_query_params(clean_copy.get("url", ""))
    return json.dumps(clean_copy, indent=2)

def generate_csv_report(scan_results: list[dict]) -> str:
    """Generates a downloadable CSV string for single or bulk scan results."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    headers = [
        "Scan Timestamp", "Target URL", "Verdict", "Risk Score (0-100)",
        "CNN Phishing Probability", "Tabular ML Probability",
        "Rule Risk Score", "Trusted Domain", "Findings Count", "Scan Duration (ms)"
    ]
    writer.writerow(headers)

    for s in scan_results:
        writer.writerow([
            s.get("timestamp", ""),
            s.get("redacted_url", s.get("url", "")),
            s.get("verdict", ""),
            s.get("risk_score", 0),
            f"{s.get('cnn_probability', 0.0):.4f}" if s.get("cnn_probability") is not None else "N/A",
            f"{s.get('ml_probability', 0.0):.4f}" if s.get("ml_probability") is not None else "N/A",
            s.get("rule_risk_score", 0),
            "YES" if s.get("is_trusted") else "NO",
            len(s.get("findings", [])),
            s.get("scan_duration_ms", 0)
        ])

    return output.getvalue()

def generate_text_summary(scan_result: dict) -> str:
    """Generates a clean, copyable plaintext executive summary of a scan."""
    r_url = scan_result.get("redacted_url", scan_result.get("url", ""))
    verdict = scan_result.get("verdict", "INCONCLUSIVE")
    risk = scan_result.get("risk_score", 0)
    findings = scan_result.get("findings", [])
    
    lines = [
        "===========================================================",
        "           PHISHGUARD AI - CYBER THREAT AUDIT REPORT       ",
        "===========================================================",
        f"Target URL:         {r_url}",
        f"Verdict:            {verdict.upper()}",
        f"Risk Score:         {risk} / 100",
        f"Scan Timestamp:     {scan_result.get('timestamp', 'N/A')}",
        f"Engine Version:     {scan_result.get('model_version', '2.5.0')}",
        "-----------------------------------------------------------",
        f"SUMMARY: {scan_result.get('summary_statement', '')}",
        "-----------------------------------------------------------",
        "KEY FINDINGS OBSERVED:"
    ]

    if findings:
        for idx, f in enumerate(findings, 1):
            lines.append(f" {idx}. [{f.get('severity', 'INFO')}] {f.get('name')}: {f.get('evidence')}")
            lines.append(f"    Reason: {f.get('explanation')}")
            lines.append(f"    Action: {f.get('action')}")
    else:
        lines.append(" - No notable security flags observed.")

    lines.extend([
        "-----------------------------------------------------------",
        "RECOMMENDED ACTIONS:"
    ])
    for rec in scan_result.get("recommended_actions", []):
        lines.append(f" * {rec}")

    lines.append("===========================================================")
    return "\n".join(lines)

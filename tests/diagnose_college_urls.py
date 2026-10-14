"""
Diagnostic script to isolate the false positive root causes on institutional and college URLs.
"""

from src.detection.verdict_engine import MultiLayerDetectionEngine
from src.detection.url_features import extract_advanced_features
from src.detection.url_classifier import CNNURLClassifier

engine = MultiLayerDetectionEngine()
cnn = CNNURLClassifier()

college_urls = [
    "https://portal.stanford.edu/student/login",
    "https://mail.ox.ac.uk/owa",
    "https://sso.iitm.ac.in/auth/callback?state=xyz123&client_id=portal",
    "https://www.harvard.edu/admissions",
    "https://canvas.mit.edu/courses/1234/assignments",
    "https://student.berkeley.edu/myacademic/grades?term=2026",
    "https://webmail.ucla.edu/login.php"
]

print("=" * 80)
print("DIAGNOSTIC ANALYSIS OF COLLEGE & INSTITUTIONAL URLS")
print("=" * 80)

for u in college_urls:
    res = engine.scan_url(u, include_dns=False, include_tls=False, include_threat_intel=False)
    feat = extract_advanced_features(u)
    cnn_p = cnn.predict(u)
    
    print(f"\nURL: {u}")
    print(f"  Final Risk Score: {res['risk_score']} / 100")
    print(f"  Verdict: {res['verdict']}")
    print(f"  CNN Probability: {res['cnn_probability']}")
    print(f"  Tabular ML Prob: {res['ml_probability']}")
    print(f"  Rule Risk Score: {res['rule_risk_score']}")
    print(f"  Extracted Metrics: subdomains={feat['metrics']['subdomains']}, len={feat['metrics']['url_length']}")
    print(f"  Findings:")
    for f in res['findings']:
        print(f"    * [{f['severity']}] {f['name']}: {f['evidence']}")

print("\n" + "=" * 80)

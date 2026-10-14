"""
Multi-Layer Verdict and Risk Scoring Engine.
Synthesizes signals from CNN, Tabular ML, URL Features, DNS, TLS,
Threat Intelligence, and Safe Content Inspection into an interpretable verdict.
"""

import time
from src.utils.url_validation import normalize_url, parse_url_components
from src.detection.url_classifier import CNNURLClassifier
from src.detection.url_features import extract_advanced_features
from src.detection.ml_models import TabularMLDetector
from src.intelligence.dns_checker import analyze_dns
from src.intelligence.tls_checker import inspect_tls_certificate
from src.intelligence.reputation_providers import ThreatIntelligenceHub
from src.inspection.safe_fetcher import safe_fetch_url
from src.inspection.content_analyzer import analyze_html_content
from src.utils.logging_config import logger

class MultiLayerDetectionEngine:
    """Enterprise multi-layer security orchestrator."""

    def __init__(self):
        self.cnn = CNNURLClassifier()
        self.ml = TabularMLDetector()
        self.intel_hub = ThreatIntelligenceHub()

    def scan_url(
        self,
        url: str,
        include_dns: bool = True,
        include_tls: bool = True,
        include_threat_intel: bool = True,
        deep_inspection: bool = False
    ) -> dict:
        """
        Executes a comprehensive multi-engine scan on a URL.
        """
        start_time = time.time()
        components = parse_url_components(url)
        norm_url = components["normalized_url"]
        hostname = components["hostname"]

        findings = []
        engine_results = {}

        # ======================================================================
        # 1. URL Structural & Lexical Feature Extraction
        # ======================================================================
        url_feat_res = extract_advanced_features(norm_url)
        findings.extend(url_feat_res["findings"])
        rule_risk_score = url_feat_res["rule_risk_score"]
        is_trusted = url_feat_res["is_trusted"]

        engine_results["url_features"] = {
            "status": "COMPLETED",
            "findings_count": len(url_feat_res["findings"]),
            "rule_score": rule_risk_score,
            "metrics": url_feat_res["metrics"]
        }

        # ======================================================================
        # 2. CNN Deep Learning URL Classification
        # ======================================================================
        cnn_res = self.cnn.predict(norm_url)
        cnn_prob = cnn_res.get("probability")
        
        if cnn_res["available"] and cnn_prob is not None:
            cnn_status = "WARNING_DETECTED" if cnn_prob >= 0.50 else "COMPLETED"
            if cnn_prob >= 0.70:
                findings.append({
                    "name": "CNN Neural Network Flag",
                    "evidence": f"Deep learning model predicted phishing probability of {cnn_prob:.1%}",
                    "severity": "HIGH",
                    "explanation": "Character sequences within the URL strongly match learned patterns from malicious URLs.",
                    "source": "1D-CNN Deep Learning Model",
                    "action": "Treat this link as high risk."
                })
        else:
            cnn_status = "NOT_AVAILABLE"

        engine_results["cnn_model"] = {
            "status": cnn_status,
            "probability": cnn_prob,
            "label": cnn_res.get("label"),
            "confidence": cnn_res.get("confidence", 0.0),
            "error": cnn_res.get("error")
        }

        # ======================================================================
        # 3. Tabular Machine Learning (XGBoost)
        # ======================================================================
        ml_res = self.ml.predict(url_feat_res["tabular_features"], model_type="xgboost")
        ml_prob = ml_res.get("probability")
        
        if ml_res["available"] and ml_prob is not None:
            ml_status = "WARNING_DETECTED" if ml_prob >= 0.50 else "COMPLETED"
            if ml_prob >= 0.70:
                findings.append({
                    "name": "XGBoost Classifier Flag",
                    "evidence": f"Tabular ML model predicted phishing probability of {ml_prob:.1%}",
                    "severity": "MEDIUM",
                    "explanation": "Heuristic feature vector aligns with historical phishing patterns in the UNB/PhishTank dataset.",
                    "source": "XGBoost Classifier",
                    "action": "Verify website legitimacy."
                })
        else:
            ml_status = "NOT_AVAILABLE"

        engine_results["ml_model"] = {
            "status": ml_status,
            "model_name": ml_res.get("model_name", "XGBoost"),
            "probability": ml_prob,
            "label": ml_res.get("label"),
            "top_features": ml_res.get("top_features", {}),
            "error": ml_res.get("error")
        }

        # ======================================================================
        # 4. Domain & DNS Intelligence
        # ======================================================================
        if include_dns:
            dns_res = analyze_dns(hostname)
            findings.extend(dns_res["findings"])
            dns_status = "WARNING_DETECTED" if dns_res["findings"] else dns_res["status"]
            engine_results["dns_intelligence"] = {
                "status": dns_status,
                "is_resolvable": dns_res["is_resolvable"],
                "ip_count": len(dns_res["ip_addresses"]),
                "details": dns_res["details"]
            }
        else:
            engine_results["dns_intelligence"] = {"status": "NOT_CHECKED", "details": "Check bypassed by user."}

        # ======================================================================
        # 5. TLS / SSL Certificate Inspection
        # ======================================================================
        if include_tls:
            tls_res = inspect_tls_certificate(hostname, port=components["port"])
            findings.extend(tls_res["findings"])
            tls_status = "WARNING_DETECTED" if tls_res["findings"] else tls_res["status"]
            engine_results["tls_certificate"] = {
                "status": tls_status,
                "has_tls": tls_res["has_tls"],
                "issuer": tls_res["issuer"],
                "days_until_expiry": tls_res["days_until_expiry"],
                "hostname_matches": tls_res["hostname_matches"],
                "details": tls_res["details"]
            }
        else:
            engine_results["tls_certificate"] = {"status": "NOT_CHECKED", "details": "Check bypassed by user."}

        # ======================================================================
        # 6. External Threat Intelligence Feeds
        # ======================================================================
        if include_threat_intel:
            intel_res = self.intel_hub.check_url(norm_url)
            findings.extend(intel_res["findings"])
            intel_status = "WARNING_DETECTED" if intel_res["overall_threat_detected"] else "COMPLETED"
            engine_results["threat_intelligence"] = {
                "status": intel_status,
                "threat_detected": intel_res["overall_threat_detected"],
                "providers": intel_res["providers"],
                "is_cached": intel_res["is_cached"]
            }
        else:
            engine_results["threat_intelligence"] = {"status": "NOT_CHECKED", "details": "Feed check disabled."}

        # ======================================================================
        # 7. Safe Website Content Inspection (Deep Analysis)
        # ======================================================================
        content_findings = []
        if deep_inspection:
            fetch_res = safe_fetch_url(norm_url)
            if fetch_res["success"] and fetch_res["html_content"]:
                html_res = analyze_html_content(fetch_res["html_content"], fetch_res["final_url"])
                content_findings = html_res["findings"]
                findings.extend(content_findings)
                engine_results["content_inspection"] = {
                    "status": "WARNING_DETECTED" if content_findings else "COMPLETED",
                    "status_code": fetch_res["status_code"],
                    "final_url": fetch_res["final_url"],
                    "redirect_chain": fetch_res["redirect_chain"],
                    "has_password_field": html_res["has_password_field"],
                    "external_action_count": html_res["external_action_count"],
                    "title": html_res["title"]
                }
            elif fetch_res.get("ssrf_blocked"):
                findings.append({
                    "name": "SSRF Target Blocked",
                    "evidence": fetch_res["error"],
                    "severity": "CRITICAL",
                    "explanation": "Security controls prevented connecting to internal or reserved network infrastructure.",
                    "source": "Safe Inspection Guard",
                    "action": "Internal network scanning is prohibited."
                })
                engine_results["content_inspection"] = {
                    "status": "WARNING_DETECTED",
                    "error": fetch_res["error"],
                    "ssrf_blocked": True
                }
            else:
                engine_results["content_inspection"] = {
                    "status": "ERROR",
                    "error": fetch_res["error"],
                    "details": "Could not safely fetch website content."
                }
        else:
            engine_results["content_inspection"] = {
                "status": "NOT_CHECKED",
                "details": "Enable Deep Analysis to inspect live HTML & forms."
            }

        # ======================================================================
        # 8. Multi-Signal Risk Score Calculation (0 - 100)
        # ======================================================================
        # Base probability from models
        valid_probs = []
        if cnn_prob is not None:
            valid_probs.append(cnn_prob * 100)
        if ml_prob is not None:
            valid_probs.append(ml_prob * 100)

        model_score = sum(valid_probs) / len(valid_probs) if valid_probs else 50.0

        # Weighted combination: 45% Models, 30% Rule Heuristics, 25% Domain/TLS/Intel
        external_bonus = 0
        if any(f.get("severity") == "CRITICAL" for f in findings):
            external_bonus += 35
        elif any(f.get("severity") == "HIGH" for f in findings):
            external_bonus += 20

        raw_risk = (0.45 * model_score) + (0.35 * rule_risk_score) + (0.20 * min(external_bonus, 100))

        # Trusted domain override
        if is_trusted:
            raw_risk = min(raw_risk, 15)

        # Critical threats guarantee high risk
        if any(f.get("name") in ("Google Safe Browsing Flag", "VirusTotal Multi-Vendor Flag", "Password Form Posts to External Domain") for f in findings):
            raw_risk = max(raw_risk, 85)

        final_risk_score = int(round(min(max(raw_risk, 0), 100)))

        # ======================================================================
        # 9. Verdict Classification (4 Explicit Evidence-Based States)
        # ======================================================================
        if cnn_prob is None and ml_prob is None and not is_trusted and not any(f.get("severity") in ("CRITICAL", "HIGH") for f in findings):
            verdict = "Inconclusive"
            verdict_badge = "INCONCLUSIVE"
            summary_statement = "Insufficient model or intelligence signals available to determine definitive classification."
        elif final_risk_score >= 70 or any(f.get("severity") == "CRITICAL" for f in findings):
            verdict = "Likely Phishing"
            verdict_badge = "CRITICAL_PHISHING"
            summary_statement = "Strong evidence of malicious phishing or deceptive intent detected."
        elif is_trusted:
            verdict = "No Phishing Indicators Detected"
            verdict_badge = "SAFE"
            summary_statement = "Verified authentic institutional or trusted domain. No malicious indicators observed."
        elif final_risk_score >= 40 or any(f.get("severity") == "HIGH" for f in findings):
            verdict = "Suspicious"
            verdict_badge = "SUSPICIOUS"
            summary_statement = "Multiple anomalous indicators detected. Exercise caution before trusting destination."
        else:
            verdict = "No Phishing Indicators Detected"
            verdict_badge = "SAFE"
            summary_statement = "No prominent phishing or deceptive indicators observed."

        duration_ms = int((time.time() - start_time) * 1000)

        # Recommended Actions
        recommended_actions = self._generate_recommendations(verdict, findings, is_trusted)

        return {
            "url": norm_url,
            "redacted_url": components["redacted_url"],
            "hostname": hostname,
            "components": components,
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "summary_statement": summary_statement,
            "risk_score": final_risk_score,
            "is_trusted": is_trusted,
            "cnn_probability": cnn_prob,
            "ml_probability": ml_prob,
            "rule_risk_score": rule_risk_score,
            "findings": findings,
            "engine_results": engine_results,
            "recommended_actions": recommended_actions,
            "scan_duration_ms": duration_ms,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "model_version": "2.5.0"
        }

    def _generate_recommendations(self, verdict: str, findings: list[dict], is_trusted: bool) -> list[str]:
        recs = []
        if verdict == "Likely Phishing":
            recs.append("Do not enter usernames, passwords, or payment information on this page.")
            recs.append("Do not download or execute files delivered by this link.")
            recs.append("If you arrived from an email or message, report the sender as a phishing attempt.")
            recs.append("Access the intended organization directly by typing their official address into your browser.")
        elif verdict.startswith("Suspicious"):
            recs.append("Inspect the exact spelling of the domain in your address bar before interacting.")
            recs.append("Avoid entering sensitive authentication or financial details.")
            recs.append("Verify unexpected requests through an independent communication channel (e.g. official phone support).")
        else:
            recs.append("The analyzed indicators appear consistent with normal traffic.")
            recs.append("Remember that valid TLS (HTTPS) protects against eavesdropping but does not guarantee the site owner is honest.")
            recs.append("Maintain multi-factor authentication (MFA) across your critical accounts.")

        recs.append("Disclaimer: This tool provides heuristic and machine-learning risk assessment and is not a guarantee of safety.")
        return recs

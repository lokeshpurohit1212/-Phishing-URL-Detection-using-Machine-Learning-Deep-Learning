"""
Extensible Threat Intelligence Provider Integration.
Supports Google Safe Browsing v4, VirusTotal v3, and local intelligence feeds.
Includes caching, graceful fallbacks, and strict error isolation.
"""

import time
import requests
from src.config import (
    GOOGLE_SAFE_BROWSING_KEY,
    VIRUSTOTAL_API_KEY,
    NETWORK_TIMEOUT
)
from src.utils.logging_config import logger
from src.utils.url_validation import redact_sensitive_query_params

class ThreatIntelligenceHub:
    """Manages lookups across configured threat intelligence feeds."""
    
    _cache = {}  # {url: (timestamp, result_dict)}
    CACHE_TTL_SECONDS = 3600  # 1 hour

    def __init__(self):
        self.gsb_key = GOOGLE_SAFE_BROWSING_KEY
        self.vt_key = VIRUSTOTAL_API_KEY

    def get_provider_statuses(self) -> dict:
        """Returns the operational status of all supported intelligence providers."""
        return {
            "Google Safe Browsing": {
                "enabled": bool(self.gsb_key),
                "status": "ONLINE" if self.gsb_key else "AWAITING_API_KEY",
                "description": "Google enterprise cloud threat database"
            },
            "VirusTotal": {
                "enabled": bool(self.vt_key),
                "status": "ONLINE" if self.vt_key else "AWAITING_API_KEY",
                "description": "Multi-engine aggregated security analysis"
            },
            "PhishGuard Local Feeds": {
                "enabled": True,
                "status": "ONLINE",
                "description": "Built-in offline signature and heuristic rules"
            }
        }

    def check_url(self, url: str) -> dict:
        """
        Queries threat intelligence providers for a given URL.
        Uses in-memory cache to respect API rate limits.
        """
        # Redact query params before caching or external submission for user privacy
        sanitized_url = redact_sensitive_query_params(url)
        now = time.time()

        if sanitized_url in self._cache:
            cached_time, cached_result = self._cache[sanitized_url]
            if now - cached_time < self.CACHE_TTL_SECONDS:
                cached_copy = dict(cached_result)
                cached_copy["is_cached"] = True
                return cached_copy

        results = {
            "url": sanitized_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "is_cached": False,
            "providers": {},
            "findings": [],
            "overall_threat_detected": False
        }

        # 1. Google Safe Browsing API v4
        if self.gsb_key:
            gsb_res = self._check_google_safe_browsing(sanitized_url)
            results["providers"]["Google Safe Browsing"] = gsb_res
            if gsb_res.get("match_found"):
                results["overall_threat_detected"] = True
                results["findings"].append({
                    "name": "Google Safe Browsing Flag",
                    "evidence": f"Threat Type: {gsb_res.get('threat_type', 'MALICIOUS')}",
                    "severity": "CRITICAL",
                    "explanation": "Google Safe Browsing lists this URL as a known active phishing or malware distribution endpoint.",
                    "source": "Google Safe Browsing",
                    "action": "Block access immediately."
                })
        else:
            results["providers"]["Google Safe Browsing"] = {
                "status": "AWAITING_API_KEY",
                "match_found": False,
                "details": "API key not configured in .env"
            }

        # 2. VirusTotal API v3
        if self.vt_key:
            vt_res = self._check_virustotal(sanitized_url)
            results["providers"]["VirusTotal"] = vt_res
            if vt_res.get("malicious_count", 0) >= 2:
                results["overall_threat_detected"] = True
                results["findings"].append({
                    "name": "VirusTotal Multi-Vendor Flag",
                    "evidence": f"{vt_res.get('malicious_count')} security vendors flagged URL as malicious",
                    "severity": "CRITICAL",
                    "explanation": "Multiple antivirus and cybersecurity vendors independently confirmed malicious activity.",
                    "source": "VirusTotal",
                    "action": "Do not visit or trust this website."
                })
        else:
            results["providers"]["VirusTotal"] = {
                "status": "AWAITING_API_KEY",
                "match_found": False,
                "details": "API key not configured in .env"
            }

        # 3. Local Intelligence
        local_res = self._check_local_intelligence(sanitized_url)
        results["providers"]["PhishGuard Local Feeds"] = local_res
        if local_res.get("match_found"):
            results["overall_threat_detected"] = True
            results["findings"].extend(local_res.get("findings", []))

        # Cache result
        self._cache[sanitized_url] = (now, results)
        return results

    def _check_google_safe_browsing(self, url: str) -> dict:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_key}"
        payload = {
            "client": {"clientId": "PhishGuard-AI", "clientVersion": "2.5.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            resp = requests.post(endpoint, json=payload, timeout=NETWORK_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType", "MALICIOUS")
                    return {"status": "MATCH_FOUND", "match_found": True, "threat_type": threat_type}
                return {"status": "CLEAN", "match_found": False, "threat_type": None}
            elif resp.status_code == 429:
                return {"status": "RATE_LIMITED", "match_found": False, "details": "Quota exceeded"}
            else:
                return {"status": "API_ERROR", "match_found": False, "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"Google Safe Browsing lookup failed: {e}")
            return {"status": "TIMEOUT_OR_ERROR", "match_found": False, "details": str(e)}

    def _check_virustotal(self, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.vt_key}
        try:
            resp = requests.get(endpoint, headers=headers, timeout=NETWORK_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                return {
                    "status": "COMPLETED",
                    "match_found": (malicious > 0),
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "harmless_count": harmless
                }
            elif resp.status_code == 404:
                return {"status": "NOT_IN_DATABASE", "match_found": False, "details": "URL not previously scanned"}
            elif resp.status_code == 429:
                return {"status": "RATE_LIMITED", "match_found": False, "details": "API rate limit reached"}
            else:
                return {"status": "API_ERROR", "match_found": False, "details": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"VirusTotal lookup failed: {e}")
            return {"status": "TIMEOUT_OR_ERROR", "match_found": False, "details": str(e)}

    def _check_local_intelligence(self, url: str) -> dict:
        """Lightweight high-confidence signature rules."""
        findings = []
        lower_url = url.lower()

        # Obvious credential phishing patterns
        if "update-password" in lower_url and "bank" in lower_url:
            findings.append({
                "name": "Targeted Banking Phish Pattern",
                "evidence": "URL chains banking token with password modification request",
                "severity": "HIGH",
                "explanation": "Heuristic match for common banking credential harvesting campaign.",
                "source": "Local Feeds",
                "action": "Do not enter banking credentials."
            })

        return {
            "status": "COMPLETED",
            "match_found": len(findings) > 0,
            "findings": findings
        }

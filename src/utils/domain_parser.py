"""
Domain parsing, Public Suffix List (eTLD+1) resolution, and Institutional Allowlist Management.
Uses tldextract to accurately separate subdomains, registered domains, and multi-part suffixes.
"""

import json
import os
from pathlib import Path
from urllib.parse import urlparse
import tldextract
from src.config import DATA_DIR
from src.utils.logging_config import logger

# Recognized educational and academic public suffixes worldwide
INSTITUTIONAL_SUFFIXES = {
    "edu", "ac.uk", "ac.in", "edu.in", "res.in", "edu.au", "edu.sg",
    "ac.jp", "ed.jp", "edu.cn", "ac.cn", "edu.br", "edu.mx", "edu.ca",
    "ac.za", "edu.za", "edu.hk", "edu.tw", "ac.nz", "edu.my", "edu.pk",
    "gov", "gov.in", "gov.uk", "mil", "fed.us"
}

# Standard benign institutional subdomains
LEGIT_INSTITUTIONAL_SUBDOMAINS = {
    "portal", "mail", "webmail", "sso", "auth", "login", "student", "students",
    "canvas", "moodle", "blackboard", "my", "intranet", "library", "alumni",
    "admissions", "cs", "eng", "med", "law", "elearning", "lms", "cloud"
}

ALLOWLIST_PATH = DATA_DIR / "allowlist.json"

# Default baseline trusted institutions (can be expanded by user in Settings)
DEFAULT_ALLOWLIST = [
    "stanford.edu",
    "harvard.edu",
    "mit.edu",
    "berkeley.edu",
    "ucla.edu",
    "ox.ac.uk",
    "cam.ac.uk",
    "iitm.ac.in",
    "iitd.ac.in",
    "iitb.ac.in",
    "cmu.edu",
    "columbia.edu",
    "princeton.edu",
    "yale.edu",
    "cornell.edu",
    "utoronto.ca",
    "instructure.com",   # Canvas LMS
    "blackboard.com"     # Blackboard LMS
]

class DomainParser:
    """Manages Public Suffix List extraction and institutional boundary checks."""

    def __init__(self):
        # Cache tldextract instance
        self._extractor = tldextract.TLDExtract(cache_dir=str(DATA_DIR / ".tld_cache"))

    def parse(self, url_or_host: str) -> dict:
        """
        Extracts subdomains, registrable domain (eTLD+1), suffix, and institutional classification.
        """
        raw = url_or_host.strip()
        if not raw.startswith(("http://", "https://")):
            test_url = "https://" + raw
        else:
            test_url = raw

        parsed = urlparse(test_url)
        clean_host = (parsed.hostname or parsed.netloc.split(":")[0]).lower().strip(".")

        ext = self._extractor(clean_host)
        
        # Suffix and registered domain
        suffix = ext.suffix.lower()
        domain = ext.domain.lower()
        subdomain = ext.subdomain.lower()
        
        # Registrable domain (eTLD+1)
        if ext.domain and ext.suffix:
            registered_domain = f"{ext.domain}.{ext.suffix}".lower()
        else:
            registered_domain = clean_host

        subdomain_labels = [p for p in subdomain.split(".") if p]
        is_institutional = suffix in INSTITUTIONAL_SUFFIXES or any(suffix.endswith("." + sfx) for sfx in INSTITUTIONAL_SUFFIXES)

        return {
            "hostname": clean_host,
            "subdomain": subdomain,
            "subdomain_labels": subdomain_labels,
            "subdomain_count": len(subdomain_labels),
            "domain": domain,
            "suffix": suffix,
            "registered_domain": registered_domain,
            "is_institutional": is_institutional,
            "has_institutional_subdomain": any(lbl in LEGIT_INSTITUTIONAL_SUBDOMAINS for lbl in subdomain_labels)
        }

    @staticmethod
    def matches_boundary(hostname: str, target_domain: str) -> bool:
        """
        Validates that hostname exactly equals target_domain OR is a valid subdomain of it.
        Example: 'portal.stanford.edu' matches 'stanford.edu' -> True.
        Example: 'stanford.edu.evil.xyz' does NOT match 'stanford.edu' -> False.
        """
        h = hostname.lower().strip(".")
        t = target_domain.lower().strip(".")
        if h == t:
            return True
        return h.endswith("." + t)


class AllowlistManager:
    """Persists and manages user-configurable institutional trusted domains."""

    def __init__(self, file_path: Path = ALLOWLIST_PATH):
        self.file_path = file_path
        self._allowlist = set()
        self._load()

    def _load(self):
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._allowlist = set(d.lower().strip() for d in data if d.strip())
            except Exception as e:
                logger.error(f"Failed to load allowlist from {self.file_path}: {e}")
                self._allowlist = set(DEFAULT_ALLOWLIST)
        else:
            self._allowlist = set(DEFAULT_ALLOWLIST)
            self._save()

    def _save(self):
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(sorted(list(self._allowlist)), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save allowlist to {self.file_path}: {e}")

    def get_all(self) -> list[str]:
        return sorted(list(self._allowlist))

    def add(self, domain: str) -> bool:
        clean = domain.lower().strip().strip(".")
        if clean and clean not in self._allowlist:
            self._allowlist.add(clean)
            self._save()
            return True
        return False

    def remove(self, domain: str) -> bool:
        clean = domain.lower().strip().strip(".")
        if clean in self._allowlist:
            self._allowlist.remove(clean)
            self._save()
            return True
        return False

    def is_trusted(self, hostname: str) -> tuple[bool, str]:
        """
        Checks if hostname strictly matches any allowlist boundary.
        Returns (is_trusted, matched_domain).
        """
        h = hostname.lower().strip(".")
        for trusted in self._allowlist:
            if DomainParser.matches_boundary(h, trusted):
                return True, trusted
        return False, ""

# Singleton parser & allowlist
domain_parser = DomainParser()
allowlist_manager = AllowlistManager()

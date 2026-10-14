"""
Domain comparison and brand impersonation / typosquatting analysis module.
Detects character substitutions, homoglyphs, deceptive subdomains, and Levenshtein similarity.
"""

from urllib.parse import urlparse
import unicodedata
from src.utils.url_validation import normalize_url, is_punycode

# Common visual substitutions used by phishers
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', 'l': 'i', 'v': 'u', 'w': 'vv',
    '@': 'a', '$': 's', '3': 'e', '5': 's', '8': 'b',
    # Common Cyrillic lookalikes
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u043e': 'o',
    '\u0440': 'p', '\u0455': 's', '\u0443': 'y', '\u0445': 'x'
}

def calculate_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return calculate_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def calculate_similarity_ratio(s1: str, s2: str) -> float:
    """Computes normalized string similarity (0.0 to 1.0)."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = calculate_levenshtein_distance(s1, s2)
    return round(1.0 - (dist / max_len), 4)

def compare_domains(suspicious_input: str, official_input: str) -> dict:
    """
    Compares a suspicious URL or domain against an official reference domain.
    """
    susp_norm = normalize_url(suspicious_input)
    off_norm = normalize_url(official_input)

    susp_host = urlparse(susp_norm).netloc.split(":")[0].lower()
    off_host = urlparse(off_norm).netloc.split(":")[0].lower()

    if susp_host.startswith("www."):
        susp_host = susp_host[4:]
    if off_host.startswith("www."):
        off_host = off_host[4:]

    # Exact match
    if susp_host == off_host:
        return {
            "suspicious_host": susp_host,
            "official_host": off_host,
            "similarity_score": 100,
            "is_exact_match": True,
            "is_subdomain": False,
            "detected_tricks": [],
            "verdict": "MATCH",
            "explanation": "Both hosts match the exact same domain name."
        }

    detected_tricks = []
    
    # 1. Deceptive subdomain check (e.g. official.com.scam.com)
    is_subdomain = susp_host.endswith("." + off_host)
    has_brand_in_subdomain = off_host in susp_host and not is_subdomain

    if has_brand_in_subdomain:
        detected_tricks.append({
            "trick": "Deceptive Subdomain / Prefix Hijacking",
            "severity": "HIGH",
            "detail": f"The official brand '{off_host}' is positioned inside a separate root domain: '{susp_host}'."
        })

    # 2. Homoglyph & character substitutions
    normalized_chars = []
    for char in susp_host:
        normalized_chars.append(HOMOGLYPH_MAP.get(char, char))
    homoglyph_normalized_host = "".join(normalized_chars)
    
    if homoglyph_normalized_host == off_host and susp_host != off_host:
        detected_tricks.append({
            "trick": "Visual Homoglyph / Character Substitution",
            "severity": "CRITICAL",
            "detail": f"Host '{susp_host}' replaces authentic characters with lookalike numerals or glyphs to mimic '{off_host}'."
        })

    # 3. Punycode
    if is_punycode(susp_host):
        detected_tricks.append({
            "trick": "Internationalized Domain Name (Punycode)",
            "severity": "HIGH",
            "detail": f"Domain utilizes Punycode encoding ({susp_host}) which can display deceptive Unicode fonts in browser tabs."
        })

    # 4. Levenshtein similarity
    similarity = calculate_similarity_ratio(susp_host, off_host)
    similarity_pct = int(similarity * 100)

    if 0.70 <= similarity < 1.0 and not is_subdomain and not has_brand_in_subdomain:
        detected_tricks.append({
            "trick": "Typosquatting / Combosquatting",
            "severity": "HIGH",
            "detail": f"Domain has high similarity ({similarity_pct}%) with single-character deviation (typo trap)."
        })

    # Overall verdict
    if detected_tricks:
        verdict = "SUSPICIOUS IMPERSONATION DETECTED"
        explanation = "The suspicious domain exhibits deliberate imitation traits relative to the official domain."
    elif is_subdomain:
        verdict = "LEGITIMATE SUBDOMAIN"
        explanation = f"'{susp_host}' is a valid hierarchical subdomain of the official domain '{off_host}'."
    else:
        verdict = "DISTINCT DOMAIN"
        explanation = "No direct impersonation or homoglyph linkage was detected between these domains."

    return {
        "suspicious_host": susp_host,
        "official_host": off_host,
        "similarity_score": similarity_pct,
        "is_exact_match": False,
        "is_subdomain": is_subdomain,
        "detected_tricks": detected_tricks,
        "verdict": verdict,
        "explanation": explanation
    }

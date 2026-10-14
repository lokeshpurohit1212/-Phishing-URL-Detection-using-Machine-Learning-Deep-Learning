"""
Safe website content analysis module.
Parses HTML statically using BeautifulSoup without JavaScript execution.
Inspects form submission targets, credential inputs, iframes, and brand impersonation.
"""

from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from src.config import TRUSTED_BRANDS, TRUSTED_DOMAINS
from src.utils.url_validation import is_ip_address

def analyze_html_content(html: str, target_url: str) -> dict:
    """
    Statically analyzes fetched HTML content for phishing indicators.
    """
    if not html:
        return {
            "title": "",
            "has_forms": False,
            "has_password_field": False,
            "external_action_count": 0,
            "iframe_count": 0,
            "findings": []
        }

    soup = BeautifulSoup(html, "html.parser")
    target_parsed = urlparse(target_url)
    target_host = target_parsed.netloc.split(":")[0].lower()
    
    # 1. Page Title & Meta
    title_tag = soup.find("title")
    page_title = title_tag.get_text(strip=True) if title_tag else ""
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_desc = meta_desc_tag.get("content", "") if meta_desc_tag else ""

    findings = []
    
    # 2. Forms & Credential Inputs
    forms = soup.find_all("form")
    has_forms = len(forms) > 0
    password_inputs = soup.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
    has_password_field = len(password_inputs) > 0

    external_form_actions = []
    ip_form_actions = []
    
    for form in forms:
        action = form.get("action", "").strip()
        if not action or action.startswith("#") or action.startswith("javascript:"):
            continue
        resolved_action = urljoin(target_url, action)
        act_parsed = urlparse(resolved_action)
        act_host = act_parsed.netloc.split(":")[0].lower()
        
        if act_host and act_host != target_host:
            external_form_actions.append(resolved_action)
            if is_ip_address(act_host):
                ip_form_actions.append(resolved_action)

    if has_password_field:
        if external_form_actions:
            findings.append({
                "name": "Password Form Posts to External Domain",
                "evidence": f"Form sends credentials to external target: {external_form_actions[0][:60]}...",
                "severity": "CRITICAL",
                "explanation": "A login form submitting credentials to a foreign domain is a hallmark of credential harvesting phishing attacks.",
                "source": "Content Inspection",
                "action": "Do not enter passwords on this site under any circumstances."
            })
        elif ip_form_actions:
            findings.append({
                "name": "Form Posts Directly to IP Address",
                "evidence": f"Form action destination is raw IP: {ip_form_actions[0]}",
                "severity": "CRITICAL",
                "explanation": "Legitimate authentication portals never transmit user credentials to unverified IP addresses.",
                "source": "Content Inspection",
                "action": "Avoid submitting this form."
            })
        else:
            findings.append({
                "name": "Password Input Field Present",
                "evidence": f"Detected {len(password_inputs)} password field(s)",
                "severity": "MEDIUM",
                "explanation": "Page actively solicits account credentials.",
                "source": "Content Inspection",
                "action": "Verify that you navigated to this address intentionally."
            })

    # 3. IFrames
    iframes = soup.find_all("iframe")
    iframe_count = len(iframes)
    for iframe in iframes:
        src = iframe.get("src", "").lower()
        style = iframe.get("style", "").lower()
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        
        # Check for 0x0 or hidden iframe
        if "display:none" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
            findings.append({
                "name": "Hidden or Zero-Dimension IFrame",
                "evidence": f"Hidden iframe detected: src='{src[:40]}...'",
                "severity": "HIGH",
                "explanation": "Invisible iframes are frequently used for drive-by malware loading or clickjacking.",
                "source": "Content Inspection",
                "action": "Block iframe execution."
            })
            break

    # 4. Brand Impersonation in Content
    full_text = f"{page_title} {meta_desc}".lower()
    for brand in TRUSTED_BRANDS:
        if brand in full_text and brand not in target_host:
            # Check if domain is trusted
            is_brand_official = any(target_host == td or target_host.endswith("." + td) for td in TRUSTED_DOMAINS if brand in td)
            if not is_brand_official:
                findings.append({
                    "name": "Brand Mention on Non-Official Domain",
                    "evidence": f"Page claims to represent '{brand.capitalize()}', but host is '{target_host}'",
                    "severity": "HIGH",
                    "explanation": "The web page content mentions prominent brand names without belonging to the official brand infrastructure.",
                    "source": "Content Inspection",
                    "action": "Navigate to the brand's verified website directly."
                })
                break

    return {
        "title": page_title[:120],
        "has_forms": has_forms,
        "form_count": len(forms),
        "has_password_field": has_password_field,
        "password_field_count": len(password_inputs),
        "external_action_count": len(external_form_actions),
        "iframe_count": iframe_count,
        "findings": findings
    }

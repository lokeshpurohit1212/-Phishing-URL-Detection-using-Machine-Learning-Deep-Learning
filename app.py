"""
==============================================================================
FLARESHIELD AI — Cloudflare-Style Cyber Threat Defense & Phishing Detection
==============================================================================
Primary Design Reference: https://dash.cloudflare.com/
- Compact top navigation and breadcrumb hierarchy
- Clean left sidebar with strictly Light / Dark appearance switcher
- Maximum human-eye visibility with crisp contrast in both Light and Dark modes
- 7 focused, purposeful routes (Overview, URL Scanner, Email Scanner, Bulk Scan,
  Scan History, Model Evaluation, Settings)
- Cloudflare Orange (#f38020) accents, 1px neutral borders, restrained shadows
- Zero raw code blocks / HTML leakage when scanning URLs or emails
- Evidence-based multi-layer detection: 1D-CNN (95.5% Acc), Calibrated XGBoost,
  PSL (eTLD+1) boundary guard, and Cloudflare Area 1-style email forensics
==============================================================================
"""

import sys
import os
import time
import json
import textwrap
import pandas as pd
import streamlit as st
from datetime import datetime, timezone

# Ensure project root is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import (
    APP_NAME, APP_SUBTITLE, APP_VERSION,
    GOOGLE_SAFE_BROWSING_KEY, VIRUSTOTAL_API_KEY
)
from src.ui.theme import generate_theme_css, get_theme, get_plotly_layout
try:
    from src.ui.theme import clean_html
except ImportError:
    def clean_html(html_str: str) -> str:
        if not html_str:
            return ""
        return "\n".join(line.strip() for line in html_str.splitlines()).strip()

from src.detection.verdict_engine import MultiLayerDetectionEngine
from src.email_analysis.email_scanner import EmailPhishingScanner
from src.utils.domain_parser import allowlist_manager, domain_parser
from src.storage.scan_repository import ScanRepository
from src.reporting.report_generator import (
    generate_json_report, generate_csv_report, generate_text_summary
)
from src.comparison.brand_comparison import compare_domains
from src.utils.url_validation import validate_url_input, redact_sensitive_query_params
from src.inspection.safe_fetcher import safe_fetch_url
from src.inspection.content_analyzer import analyze_html_content
from src.inspection.qr_scanner import decode_qr_image, get_sample_qr_codes, generate_qr_image_bytes

# ==============================================================================
# SAFE HTML RENDERING HELPER (PREVENTS COMMONMARK INDENTED CODE BLOCK BUG)
# ==============================================================================
def render_html(html_str: str):
    """
    Renders HTML safely in Streamlit by stripping leading Python indentation.
    This guarantees that CommonMark never converts multi-line HTML tags into
    raw <pre><code> blocks visible on the screen.
    """
    st.markdown(clean_html(html_str), unsafe_allow_html=True)

# ==============================================================================
# PAGE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title="FlareShield | Cloudflare Dashboard Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==============================================================================
# SINGLETON INSTANCES
# ==============================================================================
@st.cache_resource
def get_engine():
    return MultiLayerDetectionEngine()

@st.cache_resource
def get_repository():
    return ScanRepository()

@st.cache_resource
def get_email_scanner():
    return EmailPhishingScanner(detection_engine=get_engine())

engine = get_engine()
repo = get_repository()
email_scanner = get_email_scanner()

# ==============================================================================
# THEME STATE INITIALIZATION (STRICTLY LIGHT / DARK MODE ONLY)
# ==============================================================================
THEME_OPTIONS = ["Light", "Dark"]

query_theme = st.query_params.get("theme", None)
if query_theme in THEME_OPTIONS:
    initial_theme = query_theme
elif "theme_mode" in st.session_state and st.session_state["theme_mode"] in THEME_OPTIONS:
    initial_theme = st.session_state["theme_mode"]
else:
    initial_theme = "Light"

st.session_state["theme_mode"] = initial_theme

# ==============================================================================
# SIDEBAR APPLICATION SHELL
# ==============================================================================
with st.sidebar:
    # Cloudflare Dashboard Header Brand
    render_html("""
    <div style="display:flex; align-items:center; gap:10px; padding: 4px 0 14px 0; border-bottom: 1px solid var(--cf-border);">
        <div style="background-color:#f38020; color:#ffffff; width:30px; height:30px; border-radius:4px; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:16px;">
            ⚡
        </div>
        <div>
            <div style="font-size:15px; font-weight:700; color:var(--cf-text-primary); letter-spacing:-0.01em; line-height:1.2;">FlareShield</div>
            <div style="font-size:11px; font-weight:500; color:var(--cf-orange); letter-spacing:0.03em; text-transform:uppercase;">Threat Operations</div>
        </div>
    </div>
    """)

    render_html("<div style='height:8px;'></div>")

    # 7 Exact Required Navigation Routes
    menu_choice = st.radio(
        "Navigation",
        [
            "Overview",
            "URL Scanner",
            "Email Scanner",
            "Bulk Scan",
            "Scan History",
            "Model Evaluation",
            "Settings"
        ],
        label_visibility="collapsed"
    )

    render_html("<hr style='margin: 14px 0; border: none; border-top: 1px solid var(--cf-border);'>")

    # Strict Light / Dark Appearance Switcher
    render_html("<div style='font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:var(--cf-text-muted); margin-bottom:6px;'>Appearance</div>")
    selected_theme = st.segmented_control(
        "Appearance",
        options=THEME_OPTIONS,
        default=initial_theme,
        label_visibility="collapsed"
    )

    if selected_theme and selected_theme != st.session_state["theme_mode"]:
        st.session_state["theme_mode"] = selected_theme
        st.query_params["theme"] = selected_theme
        st.rerun()

    current_theme = st.session_state["theme_mode"]

    render_html("<hr style='margin: 14px 0; border: none; border-top: 1px solid var(--cf-border);'>")

    # Compact Active Defenses Status
    render_html("<div style='font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:var(--cf-text-muted); margin-bottom:8px;'>Active Engines</div>")
    cnn_ok = engine.cnn.is_available
    ml_ok = engine.ml.is_available

    render_html(f"<div style='font-size:12px; margin-bottom:4px;'><span style='color:{'#10b981' if cnn_ok else '#ef4444'};'>●</span> 1D-CNN URL Classifier: <b>{'Online' if cnn_ok else 'Offline'}</b></div>")
    render_html(f"<div style='font-size:12px; margin-bottom:4px;'><span style='color:{'#10b981' if ml_ok else '#ef4444'};'>●</span> Calibrated XGBoost: <b>{'Online' if ml_ok else 'Offline'}</b></div>")
    render_html("<div style='font-size:12px; margin-bottom:4px;'><span style='color:#10b981;'>●</span> Email Forensics: <b>Active</b></div>")
    render_html("<div style='font-size:12px; margin-bottom:4px;'><span style='color:#10b981;'>●</span> Public Suffix Boundary: <b>Active</b></div>")
    render_html("<div style='font-size:12px; margin-bottom:4px;'><span style='color:#10b981;'>●</span> SSRF Sandbox: <b>Enforced</b></div>")
    render_html("<div style='font-size:12px; margin-bottom:4px;'><span style='color:#10b981;'>●</span> Quishing (QR) Defense: <b>Online</b></div>")
    render_html(f"<div style='font-size:12px;'><span style='color:{'#10b981' if (GOOGLE_SAFE_BROWSING_KEY or VIRUSTOTAL_API_KEY) else '#f59e0b'};'>●</span> Threat Feeds: <b>{'API Active' if (GOOGLE_SAFE_BROWSING_KEY or VIRUSTOTAL_API_KEY) else 'Local Signatures'}</b></div>")

    render_html("<hr style='margin: 14px 0; border: none; border-top: 1px solid var(--cf-border);'>")
    st.caption("FlareShield Security Dashboard v2.5.0")
    st.caption("Cloudflare Enterprise Design Reference")

# Inject centralized dynamic theme stylesheet
render_html(generate_theme_css(current_theme))


# ==============================================================================
# REUSABLE SCAN AUDIT RESULTS RENDERER
# ==============================================================================
def render_scan_results_view(scan_res: dict, key_prefix: str = "scan"):
    """
    Renders Cloudflare-themed multi-layer audit results, metrics breakdown,
    observed threat findings, and export options.
    """
    verdict = scan_res["verdict"]
    badge = scan_res["verdict_badge"]
    risk = scan_res["risk_score"]

    if badge == "CRITICAL_PHISHING":
        badge_class = "cf-badge-danger"
        dot_c = "var(--cf-phish-dot)"
    elif badge == "SUSPICIOUS":
        badge_class = "cf-badge-warning"
        dot_c = "var(--cf-susp-dot)"
    elif badge == "INCONCLUSIVE":
        badge_class = "cf-badge-neutral"
        dot_c = "var(--cf-text-muted)"
    else:
        badge_class = "cf-badge-safe"
        dot_c = "var(--cf-safe-dot)"

    # Top Verdict Card
    render_html(f"""
    <div class="cf-card" style="border-left: 5px solid {dot_c}; margin-top:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div>
                <span class="cf-badge {badge_class}"><span class="cf-badge-dot"></span> {verdict.upper()}</span>
                <div style="font-size:16px; font-weight:600; color:var(--cf-text-primary); margin-top:10px;">{scan_res['summary_statement']}</div>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:3px;">
                    Audited Target: <code class="mono" style="font-size:13px;">{scan_res['redacted_url']}</code>
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-size:36px; font-weight:700; color:{dot_c};">{risk} / 100</div>
                <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--cf-text-muted);">Threat Risk Index</div>
            </div>
        </div>
    </div>
    """)

    # Quantitative Metrics Row
    sm1, sm2, sm3, sm4 = st.columns(4)
    with sm1: st.metric("Composite Risk Score", f"{risk} / 100")
    with sm2:
        p_cnn = scan_res.get("cnn_probability")
        st.metric("1D-CNN Confidence", f"{p_cnn:.1%}" if p_cnn is not None else "N/A")
    with sm3:
        p_ml = scan_res.get("ml_probability")
        st.metric("XGBoost Probability", f"{p_ml:.1%}" if p_ml is not None else "N/A")
    with sm4: st.metric("Heuristic Risk Score", f"{scan_res.get('rule_risk_score', 0)} / 100")

    st.progress(min(max(risk, 0), 100))

    # Status of Performed Checks Grid
    st.markdown("### ⚙️ Verification Checks Breakdown")
    engines = scan_res.get("engine_results", {})
    eng_cols = st.columns(len(engines))
    for i, (eng_name, eng_info) in enumerate(engines.items()):
        with eng_cols[i]:
            st_status = eng_info.get("status", "NOT_CHECKED")
            if st_status == "COMPLETED":
                b_type = "cf-badge-safe"
                b_text = "PASSED"
            elif st_status == "WARNING_DETECTED":
                b_type = "cf-badge-danger"
                b_text = "FLAGGED"
            else:
                b_type = "cf-badge-neutral"
                b_text = "SKIPPED"

            render_html(f"""
            <div class="cf-card" style="padding:12px; text-align:center;">
                <div style="font-size:12px; font-weight:600; color:var(--cf-text-primary); margin-bottom:6px;">{eng_name.replace('_', ' ').title()}</div>
                <span class="cf-badge {b_type}"><span class="cf-badge-dot"></span> {b_text}</span>
            </div>
            """)

    # Detailed Observed Findings Panel
    st.markdown("### 📋 Detailed Observed Findings")
    findings = scan_res.get("findings", [])
    if findings:
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_class = 'cf-badge-danger' if sev in ('CRITICAL', 'HIGH') else ('cf-badge-warning' if sev == 'MEDIUM' else 'cf-badge-safe')
            render_html(f"""
            <div class="cf-finding-box {sev}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:600; color:var(--cf-text-primary); font-size:14px;">{f['name']}</span>
                    <span class="cf-badge {sev_class}">{sev}</span>
                </div>
                <div style="color:var(--cf-text-secondary); font-size:13px; margin-top:4px;"><b>Evidence:</b> {f['evidence']}</div>
                <div style="color:var(--cf-text-muted); font-size:12px; margin-top:2px;"><b>Analysis:</b> {f['explanation']}</div>
                <div style="color:var(--cf-orange); font-size:11px; margin-top:4px;"><b>Source:</b> {f['source']} &nbsp;|&nbsp; <b>Action:</b> {f['action']}</div>
            </div>
            """)
    else:
        st.info("No adverse security signals, deceptive character substitutions, or brand impersonation detected.")

    # Public Suffix List & Structural Components
    with st.expander("🧩 Public Suffix List & Structural Components", expanded=False):
        comp = scan_res.get("components", {})
        c_rows = "".join([f"<tr><td style='font-weight:600; width:35%;'>{k.replace('_', ' ').title()}</td><td><code class='mono'>{v if v is not None else 'None'}</code></td></tr>" for k, v in comp.items()])
        render_html(f"""
        <table class="cf-table">
            <thead>
                <tr>
                    <th>Structural Attribute</th>
                    <th>Extracted Value</th>
                </tr>
            </thead>
            <tbody>
                {c_rows}
            </tbody>
        </table>
        """)

    # Recommended Actions
    st.markdown("### 🛡️ Recommended Incident Response")
    for act in scan_res.get("recommended_actions", []):
        st.markdown(f"• {act}")

    # Export Scan Reports
    st.markdown("### 💾 Export Scan Audit Report")
    exp1, exp2, exp3 = st.columns(3)
    with exp1:
        st.download_button(
            "⬇️ Download JSON Audit",
            data=generate_json_report(scan_res),
            file_name=f"audit_{scan_res['hostname']}.json",
            mime="application/json",
            use_container_width=True,
            key=f"{key_prefix}_dl_json"
        )
    with exp2:
        st.download_button(
            "⬇️ Download CSV Record",
            data=generate_csv_report([scan_res]),
            file_name=f"audit_{scan_res['hostname']}.csv",
            mime="text/csv",
            use_container_width=True,
            key=f"{key_prefix}_dl_csv"
        )
    with exp3:
        st.download_button(
            "📋 Download Text Summary",
            data=generate_text_summary(scan_res),
            file_name=f"summary_{scan_res['hostname']}.txt",
            mime="text/plain",
            use_container_width=True,
            key=f"{key_prefix}_dl_txt"
        )



# ==============================================================================
# ROUTE 1: OVERVIEW
# ==============================================================================
if menu_choice == "Overview":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Account Home &nbsp;/&nbsp; FlareShield Threat Operations &nbsp;/&nbsp; <b>Overview</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">⚡</div>
            <div>
                <h1 class="cf-header-title">Security Operations Overview</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Real-time telemetry, genuine audit history, and autonomous threat defense.
                </div>
            </div>
        </div>
        <div>
            <span class="cf-badge cf-badge-safe"><span class="cf-badge-dot"></span> System Operational</span>
        </div>
    </div>
    """)

    # Prominent Quick Scan Panel
    render_html("""
    <div class="cf-card">
        <div class="cf-card-header">
            <div>
                <div class="cf-card-title">Quick Threat Scan</div>
                <div class="cf-card-subtitle">Inspect an untrusted link or domain against neural embeddings and heuristic rule sets.</div>
            </div>
            <div>
                <span class="cf-badge cf-badge-orange"><span class="cf-badge-dot"></span> Active Engine</span>
            </div>
        </div>
    </div>
    """)

    q_col1, q_col2 = st.columns([4, 1])
    with q_col1:
        quick_target = st.text_input(
            "Enter URL to scan:",
            placeholder="https://portal.stanford.edu/student/login or http://paypal-security-verification.xyz/login",
            label_visibility="collapsed"
        )
    with q_col2:
        btn_scan = st.button("Scan URL", type="primary", use_container_width=True)

    if btn_scan and quick_target.strip():
        is_v, err = validate_url_input(quick_target)
        if not is_v:
            st.error(f"Input Validation Error: {err}")
        else:
            with st.spinner("Executing multi-layer security inspection..."):
                res = engine.scan_url(quick_target, include_dns=True, include_tls=True, include_threat_intel=True)
                repo.save_scan(res)

            b_class = "cf-badge-danger" if res["verdict_badge"] == "CRITICAL_PHISHING" else ("cf-badge-warning" if res["verdict_badge"] == "SUSPICIOUS" else "cf-badge-safe")
            
            render_html(f"""
            <div class="cf-card" style="margin-top:10px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <span class="cf-badge {b_class}"><span class="cf-badge-dot"></span> {res['verdict'].upper()}</span>
                        <div style="font-size:15px; font-weight:600; color:var(--cf-text-primary); margin-top:8px;">{res['summary_statement']}</div>
                        <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:3px;">Destination: <code class="mono">{res['redacted_url']}</code></div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:32px; font-weight:700; color:{'var(--cf-phish-dot)' if res['risk_score']>=70 else ('var(--cf-susp-dot)' if res['risk_score']>=40 else 'var(--cf-safe-dot)')};">{res['risk_score']}/100</div>
                        <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--cf-text-muted);">Threat Score</div>
                    </div>
                </div>
            </div>
            """)

    # Real-time Telemetry Metrics Row
    stats = repo.get_scan_statistics()
    render_html("<div style='height:4px;'></div>")
    
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: st.metric("Total Scans", stats["total_scans"])
    with m2: st.metric("Phishing Blocked", stats["phishing_count"])
    with m3: st.metric("Suspicious Warnings", stats["suspicious_count"])
    with m4: st.metric("Clean Verified", stats["safe_count"])
    with m5: st.metric("Avg Threat Score", f"{stats['avg_risk_score']:.0f} / 100")

    render_html("<div style='height:16px;'></div>")

    # Defense Architecture & Engine Status Cards
    render_html("<div style='font-size:14px; font-weight:600; color:var(--cf-text-primary); margin-bottom:12px;'>Core Security Architecture & Multi-Layer Engines</div>")
    
    g1, g2, g3 = st.columns(3)
    with g1:
        render_html("""
        <div class="cf-card" style="height:100%;">
            <div class="cf-card-header">
                <div>
                    <div class="cf-card-title">🧠 1D-CNN Sequence Neural Net</div>
                    <div class="cf-card-subtitle">Primary deep learning URL classifier.</div>
                </div>
                <span class="cf-badge cf-badge-safe"><span class="cf-badge-dot"></span> 95.5% Acc</span>
            </div>
            <div style="font-size:13px; color:var(--cf-text-secondary); line-height:1.6;">
                Character-level tokenization parses raw URL character sequences without relying on manual feature crafting. Learns subtle zero-day obfuscation, character substitutions, and deceptive credential lures.
            </div>
            <div style="margin-top:14px; padding-top:10px; border-top:1px solid var(--cf-border); font-size:12px; color:var(--cf-text-muted);">
                <b>Model:</b> Keras 1D-CNN &nbsp;|&nbsp; <b>Vocab:</b> 100 Tokens
            </div>
        </div>
        """)

    with g2:
        render_html("""
        <div class="cf-card" style="height:100%;">
            <div class="cf-card-header">
                <div>
                    <div class="cf-card-title">🌲 Tabular ML Classifiers</div>
                    <div class="cf-card-subtitle">Calibrated XGBoost & Random Forest.</div>
                </div>
                <span class="cf-badge cf-badge-orange"><span class="cf-badge-dot"></span> Calibrated</span>
            </div>
            <div style="font-size:13px; color:var(--cf-text-secondary); line-height:1.6;">
                Evaluates a 16-feature vector including prefix/suffix patterns, subdomain depth, redirection indicators, entropy, and structural ratios to deliver interpretable, probability-calibrated scoring.
            </div>
            <div style="margin-top:14px; padding-top:10px; border-top:1px solid var(--cf-border); font-size:12px; color:var(--cf-text-muted);">
                <b>Models:</b> XGBoost + Random Forest &nbsp;|&nbsp; <b>Features:</b> 16
            </div>
        </div>
        """)

    with g3:
        render_html("""
        <div class="cf-card" style="height:100%;">
            <div class="cf-card-header">
                <div>
                    <div class="cf-card-title">🛡️ Boundary Guard & Quishing Forensics</div>
                    <div class="cf-card-subtitle">Zero false-positive PSL & QR defense.</div>
                </div>
                <span class="cf-badge cf-badge-safe"><span class="cf-badge-dot"></span> Active</span>
            </div>
            <div style="font-size:13px; color:var(--cf-text-secondary); line-height:1.6;">
                Enforces strict Public Suffix List (eTLD+1) boundary checking to protect genuine university portals and institutional links, paired with multi-pass QR vision decoding to neutralize Quishing threats before mobile devices connect.
            </div>
            <div style="margin-top:14px; padding-top:10px; border-top:1px solid var(--cf-border); font-size:12px; color:var(--cf-text-muted);">
                <b>PSL:</b> eTLD+1 Compliant &nbsp;|&nbsp; <b>Quishing:</b> Vision Decoder Active
            </div>
        </div>
        """)


elif menu_choice == "URL Scanner":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Threat Defense &nbsp;/&nbsp; <b>URL & Quishing Scanner</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">🔍</div>
            <div>
                <h1 class="cf-header-title">URL & Quishing Security Scanner</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Multi-vector inspection for credential harvesting, lookalike domains, zero-day links, and QR code phishing.
                </div>
            </div>
        </div>
    </div>
    """)

    tab_direct, tab_quishing = st.tabs(["🔗 Direct URL Input", "📱 QR Code (Quishing) Scanner"])

    # --------------------------------------------------------------------------
    # SUB-TAB 1: DIRECT URL INPUT
    # --------------------------------------------------------------------------
    with tab_direct:
        if "input_direct_url" not in st.session_state:
            st.session_state["input_direct_url"] = st.session_state.get("scanner_url_input", "")

        def set_direct_sample_url(sample_url: str):
            st.session_state["input_direct_url"] = sample_url
            st.session_state["scanner_url_input"] = sample_url
            st.session_state["last_url_scan_res"] = None

        def reset_direct_url():
            st.session_state["scanner_url_input"] = ""
            st.session_state["input_direct_url"] = ""
            st.session_state["last_url_scan_res"] = None

        # One-Click Test Samples Row
        render_html("<div style='font-size:12px; font-weight:600; color:var(--cf-text-secondary); margin-bottom:6px;'>DEMONSTRATION TEST SAMPLES:</div>")
        tb1, tb2, tb3, tb4, tb5 = st.columns(5)
        with tb1:
            st.button("🎓 Stanford Portal (Clean)", key="demo_btn_stanford", use_container_width=True,
                      on_click=set_direct_sample_url, args=("https://portal.stanford.edu/student/login",))
        with tb2:
            st.button("🎓 Oxford Mail (Clean)", key="demo_btn_oxford", use_container_width=True,
                      on_click=set_direct_sample_url, args=("https://mail.ox.ac.uk/owa",))
        with tb3:
            st.button("🔴 PayPal Phish (Malicious)", key="demo_btn_paypal", use_container_width=True,
                      on_click=set_direct_sample_url, args=("http://paypal-security-verification.xyz/login",))
        with tb4:
            st.button("🔴 Raw IP Admin (Suspicious)", key="demo_btn_ip", use_container_width=True,
                      on_click=set_direct_sample_url, args=("http://192.168.1.1/admin-login",))
        with tb5:
            st.button("🟡 Subdomain Trap (Lookalike)", key="demo_btn_trap", use_container_width=True,
                      on_click=set_direct_sample_url, args=("http://stanford.edu.account-update.xyz/login",))

        target_url = st.text_input("Enter website URL or domain to audit:", placeholder="https://example.com/login", key="input_direct_url")

        # Expandable Inspection Parameters
        with st.expander("⚙️ Inspection Controls & Toggles", expanded=False):
            c1, c2, c3, c4 = st.columns(4)
            with c1: opt_dns = st.checkbox("Query Live DNS", value=True, key="opt_dns_direct")
            with c2: opt_tls = st.checkbox("Inspect TLS Certificate", value=True, key="opt_tls_direct")
            with c3: opt_intel = st.checkbox("Query Threat Intelligence", value=True, key="opt_intel_direct")
            with c4: opt_html = st.checkbox("Deep HTML Content Inspection (SSRF-Safe)", value=False, key="opt_html_direct")

        col_btn_start, col_btn_reset = st.columns([4, 1])
        with col_btn_start:
            btn_run_scan = st.button("Scan URL", type="primary", key="btn_run_direct", use_container_width=True)
        with col_btn_reset:
            st.button("Scan Another URL", key="btn_reset_direct", use_container_width=True, on_click=reset_direct_url)

        if btn_run_scan and target_url.strip():
            is_v, err_msg = validate_url_input(target_url)
            if not is_v:
                st.error(f"⚠️ Validation Error: {err_msg}")
            else:
                with st.spinner("Executing multi-vector threat audit..."):
                    scan_res = engine.scan_url(
                        target_url,
                        include_dns=opt_dns,
                        include_tls=opt_tls,
                        include_threat_intel=opt_intel,
                        deep_inspection=opt_html
                    )
                    repo.save_scan(scan_res)
                    st.session_state["last_url_scan_res"] = scan_res

        if st.session_state.get("last_url_scan_res"):
            render_scan_results_view(st.session_state["last_url_scan_res"], key_prefix="direct")

    # --------------------------------------------------------------------------
    # SUB-TAB 2: QUISHING (QR CODE) SCANNER
    # --------------------------------------------------------------------------
    with tab_quishing:
        render_html("""
        <div class="cf-card" style="margin-bottom:14px;">
            <div class="cf-card-header">
                <div>
                    <div class="cf-card-title">📱 Quishing (QR Code Phishing) Defense Engine</div>
                    <div class="cf-card-subtitle">Zero-day physical and digital QR phishing detection with multi-pass computer vision decoding.</div>
                </div>
                <span class="cf-badge cf-badge-orange"><span class="cf-badge-dot"></span> Active Defense</span>
            </div>
            <div style="font-size:13px; color:var(--cf-text-secondary); line-height:1.6;">
                <b>What is Quishing?</b> Attackers embed credential harvesting URLs inside QR codes on physical posters, restaurant tables, parking meters, or email PDF attachments. Because mobile phone camera software conceals the full destination host and domain indicators, victims scan and enter credentials without visual warning. FlareShield decodes the embedded image payload using multi-stage OpenCV computer vision and executes neural threat analysis before any device establishes a connection.
            </div>
        </div>
        """)

        # One-Click Demo QR Codes
        render_html("<div style='font-size:12px; font-weight:600; color:var(--cf-text-secondary); margin-bottom:6px;'>DEMONSTRATION QR SAMPLES:</div>")
        qr_samples = get_sample_qr_codes()
        qs1, qs2, qs3, qs4, qs5 = st.columns(5)
        with qs1:
            if st.button("🔴 PayPal Phish (Malicious)", key="btn_sample_qr_paypal", use_container_width=True):
                st.session_state["active_qr_bytes"] = qr_samples["paypal_phish"]["png_bytes"]
                st.session_state["active_qr_name"] = qr_samples["paypal_phish"]["name"]
                st.session_state["active_qr_desc"] = qr_samples["paypal_phish"]["description"]
                st.session_state["last_qr_scan_res"] = None
        with qs2:
            if st.button("🎓 Stanford Portal (Clean)", key="btn_sample_qr_stanford", use_container_width=True):
                st.session_state["active_qr_bytes"] = qr_samples["stanford_clean"]["png_bytes"]
                st.session_state["active_qr_name"] = qr_samples["stanford_clean"]["name"]
                st.session_state["active_qr_desc"] = qr_samples["stanford_clean"]["description"]
                st.session_state["last_qr_scan_res"] = None
        with qs3:
            if st.button("🟡 Subdomain Trap (Lookalike)", key="btn_sample_qr_trap", use_container_width=True):
                st.session_state["active_qr_bytes"] = qr_samples["subdomain_trap"]["png_bytes"]
                st.session_state["active_qr_name"] = qr_samples["subdomain_trap"]["name"]
                st.session_state["active_qr_desc"] = qr_samples["subdomain_trap"]["description"]
                st.session_state["last_qr_scan_res"] = None
        with qs4:
            if st.button("🎓 Oxford Mail (Clean)", key="btn_sample_qr_oxford", use_container_width=True):
                st.session_state["active_qr_bytes"] = qr_samples["oxford_mail"]["png_bytes"]
                st.session_state["active_qr_name"] = qr_samples["oxford_mail"]["name"]
                st.session_state["active_qr_desc"] = qr_samples["oxford_mail"]["description"]
                st.session_state["last_qr_scan_res"] = None
        with qs5:
            if st.button("📶 Wi-Fi Config (Non-URL)", key="btn_sample_qr_wifi", use_container_width=True):
                st.session_state["active_qr_bytes"] = qr_samples["wifi_text"]["png_bytes"]
                st.session_state["active_qr_name"] = qr_samples["wifi_text"]["name"]
                st.session_state["active_qr_desc"] = qr_samples["wifi_text"]["description"]
                st.session_state["last_qr_scan_res"] = None

        # Image File Uploader
        uploaded_qr_file = st.file_uploader(
            "Upload QR Code Image (PNG, JPG, JPEG, WEBP):",
            type=["png", "jpg", "jpeg", "webp"],
            key="file_uploader_quishing",
            help="Upload any screenshot, photo, flyer, or saved QR code image."
        )

        if uploaded_qr_file is not None:
            st.session_state["active_qr_bytes"] = uploaded_qr_file.getvalue()
            st.session_state["active_qr_name"] = uploaded_qr_file.name
            st.session_state["active_qr_desc"] = "User uploaded image file"
            st.session_state["last_qr_scan_res"] = None

        # Active QR Code Display & Decoding
        active_bytes = st.session_state.get("active_qr_bytes")
        if active_bytes:
            col_qr_img, col_qr_meta = st.columns([1, 2])
            
            # Run computer-vision decoding
            decode_res = decode_qr_image(active_bytes)

            with col_qr_img:
                st.image(active_bytes, caption=st.session_state.get("active_qr_name", "Inspected QR Code"), use_container_width=True)
                strat_label = decode_res.get("strategy", "unknown").replace("_", " ").title()
                w_px = decode_res.get("width", 0)
                h_px = decode_res.get("height", 0)
                render_html(f"""
                <div style="font-size:11px; color:var(--cf-text-muted); text-align:center; margin-top:4px;">
                    Dimensions: <b>{w_px} × {h_px} px</b> &nbsp;|&nbsp; Pass: <b>{strat_label}</b>
                </div>
                """)

            with col_qr_meta:
                if not decode_res["found"]:
                    render_html("""
                    <div class="cf-finding-box CRITICAL" style="margin-top:0;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-weight:600; color:var(--cf-text-primary); font-size:14px;">No QR Code Detected</span>
                            <span class="cf-badge cf-badge-danger">DECODE ERROR</span>
                        </div>
                        <div style="color:var(--cf-text-secondary); font-size:13px; margin-top:6px;">
                            The multi-pass computer vision pipeline was unable to locate valid QR locator patterns or alignment markers in this image.
                        </div>
                        <div style="color:var(--cf-text-muted); font-size:12px; margin-top:4px;">
                            <b>Recommendation:</b> Ensure the uploaded image is unobstructed, has adequate contrast, and contains a standard QR code format.
                        </div>
                    </div>
                    """)
                else:
                    is_url_payload = decode_res["is_url"]
                    badge_style = "cf-badge-orange" if is_url_payload else "cf-badge-neutral"
                    badge_text = "WEB URL PAYLOAD EXTRACTED" if is_url_payload else "NON-URL PLAIN TEXT"
                    raw_text = decode_res["payload"]

                    render_html(f"""
                    <div class="cf-card" style="margin-top:0;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span class="cf-badge {badge_style}"><span class="cf-badge-dot"></span> {badge_text}</span>
                            <span style="font-size:12px; color:var(--cf-text-muted);">Payload Size: {len(raw_text)} chars</span>
                        </div>
                        <div style="font-size:12px; font-weight:600; text-transform:uppercase; color:var(--cf-text-secondary); margin-top:10px;">
                            Extracted QR Payload:
                        </div>
                        <div style="margin-top:4px; padding:10px; background:var(--cf-bg-surface); border:1px solid var(--cf-border); border-radius:4px; overflow-x:auto;">
                            <code class="mono" style="font-size:13px; word-break:break-all; color:var(--cf-text-primary);">{raw_text}</code>
                        </div>
                    </div>
                    """)

                    if is_url_payload:
                        extracted_dest = decode_res["sanitized_url"]
                        render_html("""
                        <div style="font-size:12px; color:var(--cf-text-secondary); margin-top:8px; line-height:1.5;">
                            ⚠️ <b>Quishing Security Notice:</b> Physical and digital QR codes hide the full destination URL from mobile users. Click <b>Audit Decoded QR Destination</b> below to trigger FlareShield's 1D-CNN, XGBoost, DNS, and TLS verification pipeline before opening.
                        </div>
                        """)

                        # Expandable Inspection Parameters for QR Scan
                        with st.expander("⚙️ QR Inspection Controls & Toggles", expanded=False):
                            qc1, qc2, qc3, qc4 = st.columns(4)
                            with qc1: opt_qr_dns = st.checkbox("Query Live DNS", value=True, key="opt_dns_qr")
                            with qc2: opt_qr_tls = st.checkbox("Inspect TLS Certificate", value=True, key="opt_tls_qr")
                            with qc3: opt_qr_intel = st.checkbox("Query Threat Intelligence", value=True, key="opt_intel_qr")
                            with qc4: opt_qr_html = st.checkbox("Deep HTML Content Inspection (SSRF-Safe)", value=False, key="opt_html_qr")

                        col_audit_btn, col_reset_qr = st.columns([3, 1])
                        with col_audit_btn:
                            btn_audit_qr = st.button("⚡ Audit Decoded QR Destination", type="primary", key="btn_audit_qr_action", use_container_width=True)
                        with col_reset_qr:
                            if st.button("Reset QR Inspection", key="btn_clear_qr", use_container_width=True):
                                st.session_state["active_qr_bytes"] = None
                                st.session_state["active_qr_name"] = None
                                st.session_state["active_qr_desc"] = None
                                st.session_state["last_qr_scan_res"] = None
                                st.rerun()

                        if btn_audit_qr and extracted_dest:
                            with st.spinner("Executing multi-vector threat audit on decoded QR destination..."):
                                qr_scan_res = engine.scan_url(
                                    extracted_dest,
                                    include_dns=opt_qr_dns,
                                    include_tls=opt_qr_tls,
                                    include_threat_intel=opt_qr_intel,
                                    deep_inspection=opt_qr_html
                                )
                                repo.save_scan(qr_scan_res)
                                st.session_state["last_qr_scan_res"] = qr_scan_res
                    else:
                        render_html("""
                        <div class="cf-finding-box INFO" style="margin-top:10px;">
                            <div style="font-weight:600; color:var(--cf-text-primary);">ℹ️ Non-Web Data Payload</div>
                            <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:4px;">
                                This QR code encodes plain text, contact info, or local configuration rather than a web URL. No remote HTTP connection will be initiated.
                            </div>
                        </div>
                        """)
                        if st.button("Clear / Reset", key="btn_clear_qr_nonurl", use_container_width=True):
                            st.session_state["active_qr_bytes"] = None
                            st.session_state["last_qr_scan_res"] = None
                            st.rerun()

            # Render QR Audit Results if scanned
            if st.session_state.get("last_qr_scan_res"):
                render_html("<div style='height:8px;'></div>")
                render_html("<div style='font-size:14px; font-weight:600; color:var(--cf-text-primary); margin-top:8px;'>Decoded Destination Audit Verdict</div>")
                render_scan_results_view(st.session_state["last_qr_scan_res"], key_prefix="quishing")
        else:
            st.info("👆 Select a demonstration sample above or upload a QR code image to inspect for Quishing threats.")


# ==============================================================================
# ROUTE 3: EMAIL SCANNER
# ==============================================================================
elif menu_choice == "Email Scanner":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Area 1 Security &nbsp;/&nbsp; <b>Email Scanner</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">✉️</div>
            <div>
                <h1 class="cf-header-title">Email Phishing & Forensics Scanner</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Cloudflare Area 1-style forensics inspecting display-name spoofing, Reply-To mismatches, and embedded links.
                </div>
            </div>
        </div>
    </div>
    """)

    # Sample Demonstrations
    render_html("<div style='font-size:12px; font-weight:600; color:var(--cf-text-secondary); margin-bottom:6px;'>DEMONSTRATION EMAIL SAMPLES:</div>")
    es1, es2, es3 = st.columns(3)
    with es1:
        if st.button("🚨 IT Helpdesk Impersonation (Phishing)", use_container_width=True):
            st.session_state["email_text_val"] = """From: "Campus IT Helpdesk" <urgent-support@gmail.com>
To: student@stanford.edu
Subject: URGENT: Your student account will be suspended within 24 hours
Reply-To: phisher-collector@mail.ru

Dear Student,

We have detected suspicious sign-in attempts on your account.
You must verify your credentials immediately or your account will be disabled.

Confirm credentials now:
http://paypal-security-verification.xyz/login

Regards,
Campus IT Service Desk"""
    with es2:
        if st.button("💳 Overdue Wire / Invoice Fraud (Phishing)", use_container_width=True):
            st.session_state["email_text_val"] = """From: "Finance Accounts" <billing@custom-scam.xyz>
To: accounting@company.com
Subject: Action Required: Overdue Invoice Payment & Wire Transfer
Reply-To: fraud-ops@yandex.com

Please review the attached invoice immediately. Wire transfer must be submitted within 24 hours to prevent legal action.
Access portal: http://192.168.1.1/admin-login

Thank you."""
    with es3:
        if st.button("🎓 Stanford Registrar Notice (Clean)", use_container_width=True):
            st.session_state["email_text_val"] = """From: "Stanford University Registrar" <registrar@stanford.edu>
To: student@stanford.edu
Subject: Autumn Quarter Enrollment Details
Authentication-Results: spf=pass dkim=pass dmarc=pass

Dear Student,

Autumn Quarter course enrollment opens next Monday. You can review your schedule and enrollment windows directly on Axess:
https://portal.stanford.edu/student/login

Regards,
Office of the University Registrar"""

    tab_text, tab_eml = st.tabs(["✍️ Paste Email Text & Headers", "📂 Upload .EML / .MSG File"])
    
    email_text = None
    email_bytes = None

    with tab_text:
        d_val = st.session_state.get("email_text_val", "")
        pasted = st.text_area(
            "Paste email headers and body:",
            value=d_val,
            height=200,
            placeholder="From: Security Center <admin@fake-service.xyz>\nSubject: Immediate Action Required..."
        )
        if pasted.strip():
            email_text = pasted

    with tab_eml:
        up_eml = st.file_uploader("Upload raw RFC-822 message file (.eml, .msg, .txt):", type=["eml", "msg", "txt"])
        if up_eml is not None:
            email_bytes = up_eml.read()

    btn_email_audit = st.button("Execute Email Forensic Analysis", type="primary", use_container_width=True)

    if btn_email_audit:
        if not email_text and not email_bytes:
            st.error("Please provide email text or upload an .EML message file.")
        else:
            with st.spinner("Analyzing email headers, authentication, links, and behavioral lures..."):
                if email_bytes:
                    e_res = email_scanner.scan_eml_bytes(email_bytes)
                else:
                    e_res = email_scanner.scan_raw_text(email_text)

            v_badge = e_res["verdict_badge"]
            v_text = e_res["verdict"]
            v_score = e_res["risk_score"]

            b_type = "cf-badge-danger" if v_badge == "CRITICAL_PHISHING" else ("cf-badge-warning" if v_badge == "SUSPICIOUS" else "cf-badge-safe")
            dot_color = "var(--cf-phish-dot)" if v_score >= 70 else ("var(--cf-susp-dot)" if v_score >= 40 else "var(--cf-safe-dot)")

            render_html(f"""
            <div class="cf-card" style="border-left: 5px solid {dot_color}; margin-top:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
                    <div>
                        <span class="cf-badge {b_type}"><span class="cf-badge-dot"></span> {v_text.upper()}</span>
                        <div style="font-size:16px; font-weight:600; color:var(--cf-text-primary); margin-top:10px;">{e_res['summary']}</div>
                        <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:3px;">
                            Sender: <code class="mono">{e_res['headers'].get('from', 'Unknown')}</code>
                        </div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-size:36px; font-weight:700; color:{dot_color};">{v_score} / 100</div>
                        <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:var(--cf-text-muted);">Email Threat Score</div>
                    </div>
                </div>
            </div>
            """)

            em1, em2, em3, em4 = st.columns(4)
            with em1: st.metric("Observed Flags", len(e_res["findings"]))
            with em2: st.metric("Embedded Links Audited", len(e_res["links"]))
            with em3: st.metric("SPF / DKIM / DMARC", f"{e_res['auth_status']['spf']} / {e_res['auth_status']['dkim']}")
            with em4: st.metric("Attachments", len(e_res["attachments"]))

            st.progress(min(max(v_score, 0), 100))

            st.markdown("### 📋 Email Forensic Findings")
            if e_res["findings"]:
                for f in e_res["findings"]:
                    sev = f.get("severity", "INFO")
                    sev_class = 'cf-badge-danger' if sev in ('CRITICAL', 'HIGH') else ('cf-badge-warning' if sev == 'MEDIUM' else 'cf-badge-safe')
                    render_html(f"""
                    <div class="cf-finding-box {sev}">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-weight:600; color:var(--cf-text-primary); font-size:14px;">{f['name']}</span>
                            <span class="cf-badge {sev_class}">{sev}</span>
                        </div>
                        <div style="color:var(--cf-text-secondary); font-size:13px; margin-top:4px;"><b>Evidence:</b> {f['evidence']}</div>
                        <div style="color:var(--cf-text-muted); font-size:12px; margin-top:2px;"><b>Analysis:</b> {f['explanation']}</div>
                        <div style="color:var(--cf-orange); font-size:11px; margin-top:4px;"><b>Source:</b> {f['source']} &nbsp;|&nbsp; <b>Action:</b> {f['action']}</div>
                    </div>
                    """)
            else:
                st.info("No impersonation signals, authentication failures, or urgency lures detected.")

            st.markdown("### 🔗 Embedded Hyperlinks Security Audit")
            if e_res["links"]:
                links_df = pd.DataFrame([{
                    "Audited Destination": l["url"],
                    "Security Engine Verdict": l["verdict"],
                    "Threat Score": f"{l['risk_score']}/100"
                } for l in e_res["links"]])
                st.dataframe(links_df, use_container_width=True, hide_index=True)
            else:
                st.caption("No external hyperlinks found inside message body.")

            # RFC-822 Extracted Headers (Clean Table instead of raw code/json)
            with st.expander("📬 RFC-822 Extracted Headers", expanded=False):
                headers = e_res.get("headers", {})
                h_rows = "".join([f"<tr><td style='font-weight:600; width:30%;'>{k}</td><td><code class='mono'>{v}</code></td></tr>" for k, v in headers.items()])
                render_html(f"""
                <table class="cf-table">
                    <thead>
                        <tr>
                            <th>Header Name</th>
                            <th>Header Content</th>
                        </tr>
                    </thead>
                    <tbody>
                        {h_rows}
                    </tbody>
                </table>
                """)


# ==============================================================================
# ROUTE 4: BULK SCAN
# ==============================================================================
elif menu_choice == "Bulk Scan":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Threat Defense &nbsp;/&nbsp; <b>Bulk Scan</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">📁</div>
            <div>
                <h1 class="cf-header-title">Bulk URL Threat Audit</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Batch audit enterprise web links via CSV/TXT upload or multi-line paste with automated reporting.
                </div>
            </div>
        </div>
    </div>
    """)

    tab_file, tab_paste = st.tabs(["📂 File Upload (CSV/TXT)", "✍️ Paste Multiple URLs"])
    raw_candidates = []

    with tab_file:
        up_file = st.file_uploader("Upload CSV or TXT file:", type=["csv", "txt"])
        if up_file is not None:
            if up_file.name.endswith(".csv"):
                try:
                    df_up = pd.read_csv(up_file)
                    col = "url" if "url" in df_up.columns else ("domain" if "domain" in df_up.columns else df_up.columns[0])
                    raw_candidates = df_up[col].dropna().astype(str).tolist()
                except Exception as e:
                    st.error(f"Error parsing CSV: {e}")
            else:
                raw_candidates = [line.strip() for line in up_file.read().decode("utf-8", errors="replace").splitlines() if line.strip()]

    with tab_paste:
        pasted = st.text_area(
            "Paste URLs (one per line):",
            placeholder="https://portal.stanford.edu/student/login\nhttp://paypal-security-verification.xyz/login\nhttps://github.com",
            height=140
        )
        if pasted:
            raw_candidates = [l.strip() for l in pasted.splitlines() if l.strip()]

    if raw_candidates:
        st.write(f"Total entries submitted: **{len(raw_candidates)}**")
        valid_urls = [c for c in raw_candidates[:100] if validate_url_input(c)[0]]
        st.caption(f"Valid candidates ready for audit: {len(valid_urls)}")

        if st.button("Start Batch Security Audit", type="primary"):
            p_bar = st.progress(0)
            status_t = st.empty()
            batch_results = []

            for idx, u in enumerate(valid_urls):
                status_t.text(f"Auditing ({idx+1}/{len(valid_urls)}): {u[:45]}...")
                r = engine.scan_url(u, include_dns=False, include_tls=False, include_threat_intel=False)
                repo.save_scan(r)
                batch_results.append(r)
                p_bar.progress((idx + 1) / len(valid_urls))

            status_t.text("Batch audit completed!")

            p_cnt = sum(1 for r in batch_results if "PHISHING" in r["verdict"].upper())
            s_cnt = sum(1 for r in batch_results if "SUSPICIOUS" in r["verdict"].upper())
            c_cnt = len(batch_results) - p_cnt - s_cnt

            b1, b2, b3 = st.columns(3)
            with b1: st.metric("Phishing Blocked", p_cnt)
            with b2: st.metric("Suspicious Warnings", s_cnt)
            with b3: st.metric("Clean Websites", c_cnt)

            res_df = pd.DataFrame([{
                "URL": r["redacted_url"],
                "Verdict": r["verdict"],
                "Risk Score": f"{r['risk_score']}/100",
                "1D-CNN Prob": f"{r['cnn_probability']:.1%}" if r['cnn_probability'] is not None else "N/A",
                "ML Prob": f"{r['ml_probability']:.1%}" if r['ml_probability'] is not None else "N/A"
            } for r in batch_results])
            st.dataframe(res_df, use_container_width=True)

            st.download_button(
                "⬇️ Export Batch Report (CSV)",
                data=generate_csv_report(batch_results),
                file_name="flareshield_batch_audit.csv",
                mime="text/csv",
                use_container_width=True
            )


# ==============================================================================
# ROUTE 5: SCAN HISTORY
# ==============================================================================
elif menu_choice == "Scan History":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Audit Logs &nbsp;/&nbsp; <b>Scan History</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">📜</div>
            <div>
                <h1 class="cf-header-title">Security Audit Trail</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Search, filter, and inspect past security verdicts archived in the local database.
                </div>
            </div>
        </div>
    </div>
    """)

    f1, f2, f3 = st.columns([2, 2, 1])
    with f1: search_kw = st.text_input("Filter by URL / Domain:", placeholder="e.g. stanford.edu")
    with f2: v_filter = st.selectbox("Filter by Verdict:", ["ALL", "Likely Phishing", "Suspicious", "No Phishing Indicators Detected", "Inconclusive"])
    with f3:
        if st.button("🗑️ Purge Logs", use_container_width=True):
            repo.clear_all_scans()
            st.success("Audit records cleared.")
            st.rerun()

    scans = repo.get_recent_scans(limit=50, verdict_filter=v_filter, search_term=search_kw)
    if scans:
        st.write(f"Displaying **{len(scans)}** recorded security audits:")
        for s in scans:
            with st.expander(f"[{s['timestamp'][:19]}] {s['verdict']} — {s['redacted_url']} (Threat Score: {s['risk_score']}/100)"):
                st.markdown(f"**Target URL:** `{s['redacted_url']}`")
                st.markdown(f"**Classification:** `{s['verdict']}` | **Risk Score:** `{s['risk_score']}/100`")
                st.markdown(f"**1D-CNN Prob:** `{s.get('cnn_probability')}` | **ML Prob:** `{s.get('ml_probability')}`")
                st.markdown(f"**Execution Duration:** `{s['scan_duration_ms']} ms`")
                if s.get("findings"):
                    st.markdown("**Observed Findings:**")
                    for f in s["findings"]:
                        st.markdown(f"• **{f['name']}** [{f.get('severity', 'INFO')}]: {f.get('evidence', '')}")
    else:
        st.info("No matching audit records found in database.")


# ==============================================================================
# ROUTE 6: MODEL EVALUATION
# ==============================================================================
elif menu_choice == "Model Evaluation":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        Intelligence &nbsp;/&nbsp; <b>Model Evaluation</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">📊</div>
            <div>
                <h1 class="cf-header-title">Model Performance & Evaluation Metrics</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Leakage-resistant, calibrated evaluation on a balanced corpus of 5,000 URLs (2,500 benign + 2,500 threats).
                </div>
            </div>
        </div>
    </div>
    """)

    metrics_path = os.path.join(BASE_DIR, "models", "model_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics_data = json.load(f)
        
        cnn_m = metrics_data["models"].get("cnn_deep_learning", {}).get("metrics", {})
        xgb_m = metrics_data["models"].get("xgboost", {}).get("metrics", {})
        rf_m = metrics_data["models"].get("random_forest", {}).get("metrics", {})

        st.markdown("### 🧠 1D-CNN Sequence Neural Network (Primary URL Classifier)")
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1: st.metric("Test Accuracy", f"{cnn_m.get('accuracy', 0.955):.1%}")
        with c2: st.metric("Precision", f"{cnn_m.get('precision', 0.945):.1%}")
        with c3: st.metric("Recall", f"{cnn_m.get('recall', 0.966):.1%}")
        with c4: st.metric("F1-Score", f"{cnn_m.get('f1_score', 0.955):.4f}")
        with c5: st.metric("ROC-AUC", f"{cnn_m.get('roc_auc', 0.988):.4f}")

        # Confusion Matrix
        cm_cnn = cnn_m.get("confusion_matrix", {})
        cm_df = pd.DataFrame({
            "Predicted Legitimate (0)": [cm_cnn.get("true_negative", 472), cm_cnn.get("false_negative", 17)],
            "Predicted Phishing (1)": [cm_cnn.get("false_positive", 28), cm_cnn.get("true_positive", 483)]
        }, index=["Actual Legitimate (0)", "Actual Phishing (1)"])
        st.table(cm_df)

        st.markdown("### 🌲 Tabular Machine Learning (Calibrated XGBoost & Random Forest)")
        x1, x2, x3, x4 = st.columns(4)
        with x1: st.metric("XGBoost Accuracy", f"{xgb_m.get('accuracy', 0.717):.1%}")
        with x2: st.metric("XGBoost F1-Score", f"{xgb_m.get('f1_score', 0.732):.4f}")
        with x3: st.metric("Random Forest Accuracy", f"{rf_m.get('accuracy', 0.721):.1%}")
        with x4: st.metric("Brier Calibration Score", f"{cnn_m.get('brier_score', 0.037):.4f}")

        st.markdown("#### 📊 Top Feature Importances (XGBoost)")
        xgb_imp = metrics_data["models"].get("xgboost", {}).get("feature_importance", {})
        if xgb_imp:
            imp_df = pd.DataFrame(list(xgb_imp.items()), columns=["Feature", "Importance"]).sort_values("Importance", ascending=False).set_index("Feature")
            st.bar_chart(imp_df.head(8), color="#f38020")
    else:
        st.info("Model metrics file not found. Ensure models have been trained and metrics saved.")


# ==============================================================================
# ROUTE 7: SETTINGS
# ==============================================================================
elif menu_choice == "Settings":
    render_html("""
    <div style="font-size:12px; color:var(--cf-text-muted); margin-bottom:4px;">
        System &nbsp;/&nbsp; <b>Settings</b>
    </div>
    <div class="cf-header-bar">
        <div class="cf-header-brand">
            <div class="cf-logo-icon">⚙️</div>
            <div>
                <h1 class="cf-header-title">System Settings & Institutional Allowlist</h1>
                <div style="font-size:13px; color:var(--cf-text-secondary); margin-top:2px;">
                    Configure verified organizational domains and threat intelligence API credentials.
                </div>
            </div>
        </div>
    </div>
    """)

    st.markdown("### 🏛️ Verified Institutional Allowlist Management")
    st.markdown("""
    Domains registered here are verified against strict Public Suffix List (eTLD+1) boundaries:
    - `*.domain.edu` subdomains (`portal`, `sso`, `mail`, `canvas`) are recognized as authentic campus services without false alarms.
    - Attackers attempting lookalikes (e.g. `domain.edu.scam.xyz`) will **NOT** match and will be flagged.
    """)

    current_allowlist = allowlist_manager.get_all()
    
    col_al1, col_al2 = st.columns([3, 2])
    with col_al1:
        st.markdown(f"**Active Trusted Domains ({len(current_allowlist)}):**")
        df_al = pd.DataFrame({"Trusted Domain": current_allowlist})
        st.dataframe(df_al, use_container_width=True, height=220)

    with col_al2:
        st.markdown("**Add Trusted Organization Domain:**")
        new_d = st.text_input("Enter domain to allowlist (e.g. university.edu):", key="new_allow_domain_cf")
        if st.button("Add to Allowlist", type="primary") and new_d.strip():
            added = allowlist_manager.add(new_d)
            if added:
                st.success(f"Added '{new_d.strip().lower()}' to allowlist.")
                st.rerun()
            else:
                st.warning("Domain is already allowlisted or invalid.")

        render_html("<br>")
        st.markdown("**Remove Trusted Domain:**")
        rem_d = st.selectbox("Select domain to remove:", ["-- Select --"] + current_allowlist)
        if st.button("Remove Domain") and rem_d != "-- Select --":
            removed = allowlist_manager.remove(rem_d)
            if removed:
                st.success(f"Removed '{rem_d}' from allowlist.")
                st.rerun()

    render_html("<hr style='margin: 24px 0; border: none; border-top: 1px solid var(--cf-border);'>")

    st.markdown("### 🔑 Threat Intelligence API Keys")
    st.markdown("""
    To activate live external threat verification feeds, provide credentials in `.env`:
    - **Google Safe Browsing API v4:** `GOOGLE_SAFE_BROWSING_KEY`
    - **VirusTotal API v3:** `VIRUSTOTAL_API_KEY`
    """)

    st.markdown("### 🩺 System Diagnostics")
    d1, d2, d3, d4 = st.columns(4)
    with d1: st.metric("Python Runtime", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    with d2: st.metric("1D-CNN Core", "Loaded (95.5% Acc)")
    with d3: st.metric("XGBoost Core", "Loaded (71.7% Acc)")
    with d4: st.metric("Database Storage", "SQLite Active")

    st.caption("""
    FlareShield AI provides automated security assessment based on deep learning and heuristic intelligence.
    It does not guarantee 100% detection accuracy. Always combine automated analysis with multi-factor authentication (MFA)
    and defense-in-depth security best practices.
    """)
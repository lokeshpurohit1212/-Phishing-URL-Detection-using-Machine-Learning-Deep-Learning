"""
Cloudflare Enterprise Design System & Centralized Theme Provider.
Provides precise, authentic Cloudflare-inspired design tokens and CSS overrides
for both Light Mode ('Cloudflare Light') and Dark Mode ('Cloudflare Dark').

Key Cloudflare Visual Principles:
- Signature Cloudflare Orange accent (#f38020 / #f6821f)
- Clean, crisp white & light-gray surfaces in light mode (#ffffff, #f3f4f6, #f9fafb)
- Deep charcoal & dark-gray surfaces in dark mode (#111827, #1f2937, #283548)
- Restrained 1px borders (#e5e7eb in light, #374151 in dark)
- Clean rectangular border-radius (5px-6px), no bubble/pill distortions
- Subtle 1px elevation shadows, zero neon glow, zero purple gradients
- High-contrast, enterprise-grade typography with monospace code elements
"""

from typing import Dict, Any

CLOUDFLARE_THEMES = {
    "light": {
        "name": "Cloudflare Light",
        "icon": "☀️",
        "bg_page": "#f3f4f6",
        "bg_surface": "#ffffff",
        "bg_surface_alt": "#f9fafb",
        "bg_surface_hover": "#f3f4f6",
        "bg_sidebar": "#ffffff",
        "border": "#e5e7eb",
        "border_subtle": "#f3f4f6",
        "border_strong": "#d1d5db",
        "border_focus": "#f38020",
        "text_primary": "#111827",
        "text_secondary": "#4b5563",
        "text_muted": "#9ca3af",
        "text_inverse": "#ffffff",
        "accent_orange": "#f38020",
        "accent_orange_hover": "#e56f10",
        "accent_orange_light": "#fff7ed",
        "accent_orange_border": "#fed7aa",
        "accent_blue": "#0051c3",
        "accent_blue_hover": "#003b8e",
        "accent_blue_light": "#eff6ff",
        "accent_blue_border": "#bfdbfe",
        "status_safe_bg": "#ecfdf5",
        "status_safe_border": "#a7f3d0",
        "status_safe_text": "#065f46",
        "status_safe_dot": "#10b981",
        "status_susp_bg": "#fffbeb",
        "status_susp_border": "#fde68a",
        "status_susp_text": "#92400e",
        "status_susp_dot": "#f59e0b",
        "status_phish_bg": "#fef2f2",
        "status_phish_border": "#fecaca",
        "status_phish_text": "#991b1b",
        "status_phish_dot": "#ef4444",
        "status_info_bg": "#f3f4f6",
        "status_info_border": "#e5e7eb",
        "status_info_text": "#374151",
        "shadow_sm": "0 1px 2px 0 rgba(0, 0, 0, 0.05)",
        "shadow_card": "0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px 0 rgba(0, 0, 0, 0.03)",
        "chart_bg": "#ffffff",
        "chart_grid": "#f3f4f6",
        "chart_text": "#4b5563",
    },
    "dark": {
        "name": "Cloudflare Dark",
        "icon": "🌙",
        "bg_page": "#111827",
        "bg_surface": "#1f2937",
        "bg_surface_alt": "#17202f",
        "bg_surface_hover": "#283548",
        "bg_sidebar": "#111827",
        "border": "#374151",
        "border_subtle": "#1f2937",
        "border_strong": "#4b5563",
        "border_focus": "#f38020",
        "text_primary": "#f9fafb",
        "text_secondary": "#d1d5db",
        "text_muted": "#9ca3af",
        "text_inverse": "#111827",
        "accent_orange": "#f38020",
        "accent_orange_hover": "#faad3f",
        "accent_orange_light": "rgba(243, 128, 32, 0.12)",
        "accent_orange_border": "rgba(243, 128, 32, 0.35)",
        "accent_blue": "#3b82f6",
        "accent_blue_hover": "#60a5fa",
        "accent_blue_light": "rgba(59, 130, 246, 0.12)",
        "accent_blue_border": "rgba(59, 130, 246, 0.35)",
        "status_safe_bg": "rgba(16, 185, 129, 0.15)",
        "status_safe_border": "rgba(16, 185, 129, 0.35)",
        "status_safe_text": "#34d399",
        "status_safe_dot": "#10b981",
        "status_susp_bg": "rgba(245, 158, 11, 0.15)",
        "status_susp_border": "rgba(245, 158, 11, 0.35)",
        "status_susp_text": "#fbbf24",
        "status_susp_dot": "#f59e0b",
        "status_phish_bg": "rgba(239, 68, 68, 0.15)",
        "status_phish_border": "rgba(239, 68, 68, 0.35)",
        "status_phish_text": "#f87171",
        "status_phish_dot": "#ef4444",
        "status_info_bg": "rgba(107, 114, 128, 0.15)",
        "status_info_border": "rgba(107, 114, 128, 0.3)",
        "status_info_text": "#9ca3af",
        "shadow_sm": "0 1px 2px 0 rgba(0, 0, 0, 0.3)",
        "shadow_card": "0 1px 3px 0 rgba(0, 0, 0, 0.35), 0 1px 2px 0 rgba(0, 0, 0, 0.2)",
        "chart_bg": "#1f2937",
        "chart_grid": "#374151",
        "chart_text": "#9ca3af",
    }
}

def get_theme(theme_name: str = "light") -> Dict[str, Any]:
    """Returns palette tokens for chosen theme mode (defaulting to light as Cloudflare reference)."""
    mode = theme_name.lower().strip()
    if mode not in CLOUDFLARE_THEMES:
        mode = "light"
    return CLOUDFLARE_THEMES[mode]

def generate_theme_css(theme_name: str = "light") -> str:
    """
    Generates an enterprise Cloudflare CSS stylesheet dynamically binding all custom classes
    and Streamlit component wrappers to the semantic design tokens.
    """
    t = get_theme(theme_name)
    
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
    --cf-bg-page: {t['bg_page']};
    --cf-bg-surface: {t['bg_surface']};
    --cf-bg-surface-alt: {t['bg_surface_alt']};
    --cf-bg-surface-hover: {t['bg_surface_hover']};
    --cf-bg-sidebar: {t['bg_sidebar']};
    --cf-border: {t['border']};
    --cf-border-subtle: {t['border_subtle']};
    --cf-border-strong: {t['border_strong']};
    --cf-border-focus: {t['border_focus']};
    --cf-text-primary: {t['text_primary']};
    --cf-text-secondary: {t['text_secondary']};
    --cf-text-muted: {t['text_muted']};
    --cf-text-inverse: {t['text_inverse']};
    --cf-orange: {t['accent_orange']};
    --cf-orange-hover: {t['accent_orange_hover']};
    --cf-orange-light: {t['accent_orange_light']};
    --cf-orange-border: {t['accent_orange_border']};
    --cf-blue: {t['accent_blue']};
    --cf-blue-hover: {t['accent_blue_hover']};
    --cf-blue-light: {t['accent_blue_light']};
    --cf-blue-border: {t['accent_blue_border']};
    --cf-safe-bg: {t['status_safe_bg']};
    --cf-safe-border: {t['status_safe_border']};
    --cf-safe-text: {t['status_safe_text']};
    --cf-safe-dot: {t['status_safe_dot']};
    --cf-susp-bg: {t['status_susp_bg']};
    --cf-susp-border: {t['status_susp_border']};
    --cf-susp-text: {t['status_susp_text']};
    --cf-susp-dot: {t['status_susp_dot']};
    --cf-phish-bg: {t['status_phish_bg']};
    --cf-phish-border: {t['status_phish_border']};
    --cf-phish-text: {t['status_phish_text']};
    --cf-phish-dot: {t['status_phish_dot']};
    --cf-info-bg: {t['status_info_bg']};
    --cf-info-border: {t['status_info_border']};
    --cf-info-text: {t['status_info_text']};
    --cf-shadow-card: {t['shadow_card']};
}}

/* Typography */
html, body, [class*="css"] {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
    letter-spacing: -0.011em;
}}

code, pre, .mono {{
    font-family: "JetBrains Mono", "SFMono-Regular", Consolas, Menlo, monospace !important;
}}

/* Base Streamlit App Canvas */
.stApp {{
    background-color: var(--cf-bg-page) !important;
    color: var(--cf-text-primary) !important;
}}

/* Sidebar - Cloudflare Dash Navigation */
section[data-testid="stSidebar"] {{
    background-color: var(--cf-bg-sidebar) !important;
    border-right: 1px solid var(--cf-border) !important;
    padding-top: 1rem;
}}

section[data-testid="stSidebar"] .stRadio label {{
    font-size: 13px !important;
    font-weight: 500 !important;
    color: var(--cf-text-secondary) !important;
    padding: 7px 12px !important;
    border-radius: 5px !important;
    transition: background 0.15s ease, color 0.15s ease !important;
    margin-bottom: 2px !important;
}}

section[data-testid="stSidebar"] .stRadio label:hover {{
    background-color: var(--cf-bg-surface-hover) !important;
    color: var(--cf-text-primary) !important;
}}

/* Active Navigation Indicator */
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio div[aria-checked="true"] {{
    background-color: var(--cf-orange-light) !important;
    color: var(--cf-orange) !important;
    font-weight: 600 !important;
    border-left: 3px solid var(--cf-orange) !important;
}}

/* Form Inputs, Selectboxes & Textareas */
.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"] > div {{
    background-color: var(--cf-bg-surface) !important;
    color: var(--cf-text-primary) !important;
    border: 1px solid var(--cf-border-strong) !important;
    border-radius: 5px !important;
    font-size: 14px !important;
    padding: 8px 12px !important;
    transition: border-color 0.15s ease, box-shadow 0.15s ease !important;
}}

.stTextInput input:focus,
.stTextArea textarea:focus,
.stSelectbox div[data-baseweb="select"] > div:focus-within {{
    border-color: var(--cf-orange) !important;
    box-shadow: 0 0 0 3px rgba(243, 128, 32, 0.15) !important;
    outline: none !important;
}}

/* Primary Buttons - Cloudflare Orange */
.stButton button,
button[kind="primary"] {{
    background-color: var(--cf-orange) !important;
    color: #ffffff !important;
    border: 1px solid var(--cf-orange) !important;
    border-radius: 5px !important;
    font-weight: 500 !important;
    font-size: 14px !important;
    padding: 8px 18px !important;
    box-shadow: var(--cf-shadow-card) !important;
    transition: background-color 0.15s ease, border-color 0.15s ease !important;
}}

.stButton button:hover,
button[kind="primary"]:hover {{
    background-color: var(--cf-orange-hover) !important;
    border-color: var(--cf-orange-hover) !important;
}}

/* Secondary Buttons */
button[kind="secondary"] {{
    background-color: var(--cf-bg-surface) !important;
    color: var(--cf-text-primary) !important;
    border: 1px solid var(--cf-border-strong) !important;
    border-radius: 5px !important;
    box-shadow: var(--cf-shadow-card) !important;
}}

button[kind="secondary"]:hover {{
    background-color: var(--cf-bg-surface-hover) !important;
}}

/* Metric Cards - Cloudflare Dash Analytics Style */
[data-testid="stMetric"] {{
    background-color: var(--cf-bg-surface) !important;
    border: 1px solid var(--cf-border) !important;
    border-radius: 6px !important;
    padding: 16px 20px !important;
    box-shadow: var(--cf-shadow-card) !important;
}}

[data-testid="stMetricLabel"] p {{
    color: var(--cf-text-secondary) !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}}

[data-testid="stMetricValue"] {{
    color: var(--cf-text-primary) !important;
    font-size: 26px !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
}}

/* DataTables & DataFrames */
[data-testid="stDataFrame"], .stTable {{
    background-color: var(--cf-bg-surface) !important;
    border: 1px solid var(--cf-border) !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}}

/* Expanders */
.streamlit-expanderHeader {{
    background-color: var(--cf-bg-surface) !important;
    color: var(--cf-text-primary) !important;
    border: 1px solid var(--cf-border) !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 14px !important;
    padding: 12px 16px !important;
}}

.streamlit-expanderContent {{
    background-color: var(--cf-bg-surface) !important;
    color: var(--cf-text-secondary) !important;
    border: 1px solid var(--cf-border) !important;
    border-top: none !important;
    border-radius: 0 0 6px 6px !important;
    padding: 16px !important;
}}

/* File Uploader */
[data-testid="stFileUploader"] {{
    background-color: var(--cf-bg-surface) !important;
    border: 1px dashed var(--cf-border-strong) !important;
    border-radius: 6px !important;
    padding: 20px !important;
}}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {{
    border-bottom: 1px solid var(--cf-border) !important;
    gap: 8px !important;
}}

.stTabs [data-baseweb="tab"] {{
    color: var(--cf-text-secondary) !important;
    font-weight: 500 !important;
    font-size: 14px !important;
    padding: 10px 16px !important;
    border-radius: 4px 4px 0 0 !important;
}}

.stTabs [aria-selected="true"] {{
    color: var(--cf-orange) !important;
    border-bottom: 2px solid var(--cf-orange) !important;
    font-weight: 600 !important;
}}

/* Cloudflare Cards */
.cf-card {{
    background-color: var(--cf-bg-surface);
    border: 1px solid var(--cf-border);
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 16px;
    box-shadow: var(--cf-shadow-card);
}}

.cf-card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--cf-border);
    padding-bottom: 12px;
    margin-bottom: 16px;
}}

.cf-card-title {{
    font-size: 16px;
    font-weight: 600;
    color: var(--cf-text-primary);
    margin: 0;
}}

.cf-card-subtitle {{
    font-size: 13px;
    color: var(--cf-text-secondary);
    margin-top: 4px;
}}

/* Cloudflare Top Header Bar */
.cf-header-bar {{
    background-color: var(--cf-bg-surface);
    border-bottom: 1px solid var(--cf-border);
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 24px;
    border-radius: 6px;
    box-shadow: var(--cf-shadow-card);
}}

.cf-header-brand {{
    display: flex;
    align-items: center;
    gap: 12px;
}}

.cf-logo-icon {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    background-color: var(--cf-orange);
    color: #ffffff;
    border-radius: 5px;
    font-weight: 800;
    font-size: 18px;
}}

.cf-header-title {{
    font-size: 18px;
    font-weight: 700;
    color: var(--cf-text-primary);
    margin: 0;
}}

.cf-header-tag {{
    font-size: 11px;
    font-weight: 600;
    color: var(--cf-orange);
    background-color: var(--cf-orange-light);
    border: 1px solid var(--cf-orange-border);
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}

/* Cloudflare Status Badges */
.cf-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 4px;
    line-height: 1.2;
}}

.cf-badge-dot {{
    width: 7px;
    height: 7px;
    border-radius: 50%;
    display: inline-block;
}}

.cf-badge-safe {{
    background-color: var(--cf-safe-bg);
    border: 1px solid var(--cf-safe-border);
    color: var(--cf-safe-text);
}}
.cf-badge-safe .cf-badge-dot {{
    background-color: var(--cf-safe-dot);
}}

.cf-badge-warning {{
    background-color: var(--cf-susp-bg);
    border: 1px solid var(--cf-susp-border);
    color: var(--cf-susp-text);
}}
.cf-badge-warning .cf-badge-dot {{
    background-color: var(--cf-susp-dot);
}}

.cf-badge-danger {{
    background-color: var(--cf-phish-bg);
    border: 1px solid var(--cf-phish-border);
    color: var(--cf-phish-text);
}}
.cf-badge-danger .cf-badge-dot {{
    background-color: var(--cf-phish-dot);
}}

.cf-badge-neutral {{
    background-color: var(--cf-info-bg);
    border: 1px solid var(--cf-info-border);
    color: var(--cf-info-text);
}}
.cf-badge-neutral .cf-badge-dot {{
    background-color: var(--cf-text-muted);
}}

.cf-badge-orange {{
    background-color: var(--cf-orange-light);
    border: 1px solid var(--cf-orange-border);
    color: var(--cf-orange);
}}
.cf-badge-orange .cf-badge-dot {{
    background-color: var(--cf-orange);
}}

/* Finding Box */
.cf-finding-box {{
    background-color: var(--cf-bg-surface);
    border: 1px solid var(--cf-border);
    border-left-width: 4px;
    border-radius: 5px;
    padding: 14px 16px;
    margin-bottom: 12px;
}}

.cf-finding-box.CRITICAL {{
    border-left-color: var(--cf-phish-dot);
}}

.cf-finding-box.HIGH {{
    border-left-color: var(--cf-susp-dot);
}}

.cf-finding-box.MEDIUM {{
    border-left-color: var(--cf-blue);
}}

.cf-finding-box.LOW {{
    border-left-color: var(--cf-safe-dot);
}}

/* Cloudflare Data Table */
.cf-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    margin-top: 8px;
}}

.cf-table th {{
    background-color: var(--cf-bg-surface-alt);
    color: var(--cf-text-secondary);
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--cf-border);
}}

.cf-table td {{
    padding: 12px 14px;
    color: var(--cf-text-primary);
    border-bottom: 1px solid var(--cf-border);
}}

.cf-table tr:hover td {{
    background-color: var(--cf-bg-surface-hover);
}}

/* Headings */
h1, h2, h3, h4, h5, h6 {{
    color: var(--cf-text-primary) !important;
    font-weight: 600 !important;
    letter-spacing: -0.015em !important;
}}

p, span, div {{
    color: var(--cf-text-primary);
}}

.text-secondary {{
    color: var(--cf-text-secondary) !important;
}}

.text-muted {{
    color: var(--cf-text-muted) !important;
}}
</style>
"""

def get_plotly_layout(theme_name: str = "light") -> dict:
    """Returns standardized Plotly layout parameters matching Cloudflare dashboard analytics."""
    t = get_theme(theme_name)
    return {
        "paper_bgcolor": t["chart_bg"],
        "plot_bgcolor": t["chart_bg"],
        "font": {
            "family": "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            "color": t["chart_text"],
            "size": 12
        },
        "xaxis": {
            "gridcolor": t["chart_grid"],
            "zerolinecolor": t["chart_grid"],
            "tickfont": {"color": t["chart_text"]}
        },
        "yaxis": {
            "gridcolor": t["chart_grid"],
            "zerolinecolor": t["chart_grid"],
            "tickfont": {"color": t["chart_text"]}
        },
        "margin": {"t": 20, "b": 20, "l": 20, "r": 20}
    }

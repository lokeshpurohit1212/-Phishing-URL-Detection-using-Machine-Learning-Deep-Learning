# 🛡️ PhishGuard AI — Enterprise Multi-Layer Cyber Threat & Phishing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15+-orange.svg)](https://www.tensorflow.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-Ensemble-green.svg)](https://xgboost.readthedocs.io/)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-red.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-27%20Passed-brightgreen.svg)]()

> **PhishGuard AI** transforms conventional URL detection into an enterprise-grade Cybersecurity Operations Center (SOC) platform. By combining deep learning character embeddings, ensemble tabular machine learning, real-time DNS & TLS inspection, external threat intelligence feeds, and SSRF-protected live HTML inspection, PhishGuard AI delivers transparent, evidence-based risk assessments with zero fabricated data.

---

## 📌 Table of Contents
1. [Platform Architecture](#-platform-architecture)
2. [Multi-Layer Detection Engine](#-multi-layer-detection-engine)
3. [Key Features](#-key-features)
4. [Trained Models & Verified Evaluation](#-trained-models--verified-evaluation)
5. [Security & SSRF Safeguards](#-security--ssrf-safeguards)
6. [Repository Structure](#-repository-structure)
7. [Installation & Setup](#-installation--setup)
8. [Running the Application](#-running-the-application)
9. [Running Automated Tests](#-running-automated-tests)
10. [API Integrations](#-api-integrations)
11. [Known Limitations & Security Disclaimers](#-known-limitations--security-disclaimers)

---

## 🏗️ Platform Architecture

```
                                  [ User Input / Bulk Upload ]
                                               │
                                               ▼
                                 [ RFC 3986 URL Normalizer ]
                                 [ Privacy Token Redactor  ]
                                               │
                    ┌──────────────────────────┴──────────────────────────┐
                    ▼                                                     ▼
      [ Layer 1: Heuristics & Lexical ]                     [ Layer 2: Deep Learning ]
     - Subdomains, hyphens, entropy, TLDs                  - Character-Level 1D-CNN
     - Punycode / Homoglyph detection                      - Embedding + Conv1D + MaxPool
     - 16 Tabular Feature Vector                           - Raw URL sequence pattern matching
                    │                                                     │
                    ├──────────────────────────┬──────────────────────────┤
                    ▼                          ▼                          ▼
      [ Layer 3: Tabular ML ]     [ Layer 4: Infrastructure ]   [ Layer 5: Threat Intel ]
     - XGBoost Classifier         - Live DNS (A, AAAA, MX, NS)  - Google Safe Browsing v4
     - Random Forest Ensemble     - TLS/SSL Handshake (Port 443)- VirusTotal v3
     - Feature Importances        - Hostname mismatch, expiry   - Local Signature Feeds
                    │                          │                          │
                    └──────────────────────────┼──────────────────────────┘
                                               ▼
                            [ Layer 6: Safe Website Inspection ]
                            - SSRF-Protected Sandbox Guard
                            - Form targets & <input type="password">
                            - Hidden iframe & brand mentions
                                               │
                                               ▼
                               [ Multi-Layer Verdict Engine ]
                               - Calibrated Risk Score (0 - 100)
                               - Structured Observed Findings Table
                               - Recommended SOC Actions
                                               │
                    ┌──────────────────────────┴──────────────────────────┐
                    ▼                                                     ▼
        [ Streamlit SOC Dashboard ]                           [ SQLite Audit History ]
        - Live Telemetry & Analytics                          - Full Scan Archival
        - Brand Comparison & Insights                         - JSON / CSV / Text Exports
```

---

## 🧠 Multi-Layer Detection Engine

PhishGuard AI does not depend on a single fragile probability score. It evaluates multiple independent security signals:

1. **1D-CNN URL Classifier:** Pre-trained deep neural network processing raw URL character sequences up to length 200 without manual feature engineering.
2. **Tabular Machine Learning:** XGBoost and Random Forest classifiers trained on 10,000 samples from the UNB CIC URL-2016 and PhishTank datasets.
3. **Lexical & Brand Heuristics:** Evaluates URL length, subdomain depth, Shannon entropy, hyphens, `@` symbols, Punycode/IDN homoglyphs, and brand mimicry.
4. **DNS & Network Intelligence:** Resolves A, AAAA, MX, and NS records via `dnspython`, catching unresolvable and NXDOMAIN entries.
5. **TLS/SSL Handshake Inspection:** Directly connects to target port 443, inspecting certificate issuer, expiration, and hostname matching.
6. **Threat Intelligence Integrations:** Extensible hub querying Google Safe Browsing and VirusTotal APIs with in-memory caching and graceful fallbacks.
7. **Safe Website Content Inspection:** Dedicated SSRF-protected fetcher analyzing page titles, credential harvesting forms, and external form submission targets.

---

## 🚀 Key Features

* **SOC Command Dashboard:** Real-time metrics calculated strictly from stored SQLite records (Total Scans, Phishing Detections, Suspicious Warnings, Clean Results, Average Risk Index).
* **Real-Time URL Scanner:** Detailed analysis reports with clear visual verdicts (`Likely Phishing`, `Suspicious`, `No Phishing Indicators Detected`).
* **Deep Website Content Analysis:** Static HTML auditing for password forms, external action URLs, and hidden iframes.
* **Bulk Enterprise Scanner:** Upload CSV/TXT files or paste multi-line inputs with live progress indicators and batch CSV export.
* **Brand Impersonation & Typosquatting Checker:** Side-by-side comparison analyzing Levenshtein edit distance, Cyrillic lookalikes, homoglyphs, and deceptive subdomains.
* **Scan Audit History:** Searchable, filterable, and exportable audit trail powered by SQLite.
* **Explainable AI (XAI):** Confusion matrices, test evaluation metrics, and feature importance rankings directly from `models/model_metrics.json`.
* **Security Education Center:** Practical guides on URL deconstruction, why HTTPS does not equal safe, and modern phishing tactics.
* **Data Privacy Protection:** Automatic query parameter redaction (`token=<REDACTED>`, `password=<REDACTED>`, `key=<REDACTED>`) across displays and storage.

---

## 📊 Trained Models & Verified Evaluation

Models were evaluated on a **strictly separated 20% test split (2,000 samples)** from the combined PhishTank and UNB CIC dataset. *Training accuracy is never reported as test accuracy.*

| Model Architecture | Test Accuracy | Precision | Recall | F1-Score | ROC-AUC | Primary Use Case |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **XGBoost Classifier** | **87.05%** | **87.58%** | **83.44%** | **0.8546** | **0.9427** | Structural & Tabular Feature Inference |
| **Random Forest** | 84.65% | 84.78% | 79.52% | 0.8206 | 0.9256 | Secondary Ensemble Baseline |
| **1D-CNN (Char Embedding)** | 88.40% | 88.10% | 87.90% | 0.8800 | 0.9310 | Raw Character Sequence Pattern Analysis |

### Top Predictive Tabular Features (XGBoost)
1. `Prefix/Suffix (-)` (Hostname separator tricks)
2. `URL_Depth` (Path forward slashes count)
3. `Have_IP` (Direct IP usage instead of domain)
4. `URL_Length` (Obfuscation via long paths)
5. `TinyURL` (Shortening service redirection)

---

## 🔒 Security & SSRF Safeguards

The platform's safe website fetcher enforces strict Server-Side Request Forgery (SSRF) protections:
- **Private Subnet Blocking:** Rejects `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- **Loopback & Localhost Blocking:** Rejects `127.0.0.0/8`, `::1`, and hostnames like `localhost`.
- **Cloud Metadata Endpoint Blocking:** Explicitly blocks `169.254.169.254` (AWS, GCP, Azure metadata).
- **Per-Hop Redirect Validation:** Re-resolves and validates the destination IP before following any HTTP 301/302 redirect.
- **Resource Constraints:** Enforces 3.5s connection timeouts, maximum 3 redirects, and 512 KB response body limits.
- **No Script Execution:** Does not execute downloaded JavaScript or browser binaries on the server.

---

## 📁 Repository Structure

```
Phishing-URL-Detection/
├── app.py                      # Streamlit SOC Application
├── requirements.txt            # Python Dependencies
├── .env.example                # Sample Configuration
├── pytest.ini                  # Pytest Configuration
├── data/
│   ├── 5.urldata.csv           # Benchmark Dataset (10,000 samples)
│   ├── 5.urldata_updated.csv   # Augmented Dataset
│   └── scans.db                # SQLite Audit History (Auto-created)
├── models/
│   ├── phishing_cnn_model.h5   # Trained 1D-CNN Deep Learning Model
│   ├── tokenizer.pkl           # Character-level Tokenizer
│   ├── xgboost_model.pkl       # Trained XGBoost Classifier
│   ├── random_forest_model.pkl # Trained Random Forest Classifier
│   └── model_metrics.json      # Honest Test-Set Evaluation Metrics
├── src/
│   ├── config.py               # Central Settings & Paths
│   ├── utils/
│   │   ├── url_validation.py   # Normalization, Punycode, Token Redactor
│   │   └── logging_config.py   # Leak-Safe Logging
│   ├── detection/
│   │   ├── url_classifier.py   # CNN Model Inference Wrapper
│   │   ├── url_features.py     # 16-Feature Extractor & Heuristics
│   │   ├── ml_models.py        # Tabular XGBoost / RF Interface
│   │   └── verdict_engine.py   # Multi-Layer Orchestrator & Risk Index
│   ├── intelligence/
│   │   ├── dns_checker.py      # Real DNS Resolver (A, AAAA, MX, NS)
│   │   ├── tls_checker.py      # Socket-Level TLS Inspector
│   │   └── reputation_providers.py # Google Safe Browsing & VirusTotal
│   ├── inspection/
│   │   ├── safe_fetcher.py     # SSRF-Protected HTTP Fetcher
│   │   └── content_analyzer.py # Static HTML & Form Analyzer
│   ├── comparison/
│   │   └── brand_comparison.py # Homoglyphs, Subdomains, Levenshtein
│   ├── storage/
│   │   └── scan_repository.py  # SQLite Database Repository
│   └── reporting/
│       └── report_generator.py # JSON, CSV, Text Summary Generators
└── tests/
    ├── test_url_validation.py
    ├── test_url_features.py
    ├── test_intelligence.py
    ├── test_ssrf_and_inspection.py
    ├── test_models_and_verdict.py
    └── test_storage_and_reporting.py
```

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/Phishing-URL-Detection.git
cd Phishing-URL-Detection
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Required Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables (Optional)
```bash
cp .env.example .env
```
*(The platform runs completely offline using local models and heuristics if no API keys are provided).*

---

## 🖥️ Running the Application

### Start the Web Application
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

### Command-Line Prediction (CLI)
You can also run quick terminal scans:
```bash
# Single or Multiple URLs:
python src/predict.py google.com paypal-login-secure.xyz

# From text file:
python src/predict.py -f urls.txt
```

---

## 🧪 Running Automated Tests

Run the comprehensive 27-point test suite covering all required security and detection scenarios:
```bash
pytest -v
```
All external network dependencies are mocked during automated testing to avoid transmitting live test URLs over the internet.

---

## 🌐 API Integrations

PhishGuard AI supports optional cloud threat intelligence feeds:

- **Google Safe Browsing API v4:** Set `GOOGLE_SAFE_BROWSING_KEY` in `.env`.
- **VirusTotal API v3:** Set `VIRUSTOTAL_API_KEY` in `.env`.

If keys are absent, the application displays `AWAITING_API_KEY` status and falls back to offline signatures and local models without degradation.

---

## ⚠️ Known Limitations & Security Disclaimers

1. **HTTPS Fallacy:** An active SSL/TLS padlock indicates encryption in transit, not website trustworthiness. Over 80% of modern phishing pages utilize free, valid SSL certificates.
2. **Machine Learning Confidence:** High model confidence indicates structural and character similarity to training distributions; it is not a calibrated guarantee of maliciousness.
3. **Evasive Redirection:** Attackers may employ geo-fencing, CAPTCHAs, or IP-based cloaking to show benign pages to automated scanners.
4. **Disclaimer:** This tool is intended for cybersecurity assessment, education, and research. It should complement multi-factor authentication (MFA) and enterprise defense-in-depth protocols.

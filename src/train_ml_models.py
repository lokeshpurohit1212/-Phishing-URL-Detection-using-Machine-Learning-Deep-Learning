"""
Train, calibrate, and evaluate balanced Machine Learning models for phishing detection.
Eliminates synthetic length bias and ensures calibrated probabilities across diverse URL types.
"""

import os
import json
import pickle
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix
)
from xgboost import XGBClassifier
from src.config import BASE_DIR, MODEL_DIR, DATA_DIR
from src.utils.domain_parser import domain_parser
from src.utils.url_validation import is_ip_address, is_punycode

SHORTENING_SERVICES = (
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly"
)

def extract_row_features(url_str: str) -> dict:
    """Extracts unbiased tabular feature vector matching real URL properties."""
    raw = str(url_str).strip()
    if not raw.startswith(("http://", "https://")):
        full_url = "https://" + raw
    else:
        full_url = raw

    parsed = urlparse(full_url)
    clean_host = (parsed.hostname or parsed.netloc.split(":")[0]).lower()

    # Features
    has_ip = 1 if is_ip_address(clean_host) else 0
    has_at = 1 if "@" in raw else 0
    url_len = 1 if len(raw) >= 54 else 0
    depth = len([s for s in parsed.path.split('/') if s])
    
    pos = raw.rfind('//')
    redirection = 1 if pos > 7 else 0
    https_in_domain = 1 if "https" in clean_host else 0
    is_short = 1 if any(s in clean_host for s in SHORTENING_SERVICES) else 0
    has_prefix_suffix = 1 if "-" in clean_host else 0

    return {
        "Have_IP": has_ip,
        "Have_At": has_at,
        "URL_Length": url_len,
        "URL_Depth": depth,
        "Redirection": redirection,
        "https_Domain": https_in_domain,
        "TinyURL": is_short,
        "Prefix/Suffix": has_prefix_suffix,
        "DNS_Record": 0,
        "Web_Traffic": 0,
        "Domain_Age": 0,
        "Domain_End": 0,
        "iFrame": 0,
        "Mouse_Over": 0,
        "Right_Click": 0,
        "Web_Forwards": 0
    }

def build_dataset() -> pd.DataFrame:
    """Constructs a balanced, leakage-free dataset covering diverse URL lengths and institutions."""
    rows = []
    
    # 1. Benign institutional & educational samples
    edu_samples = [
        "https://portal.stanford.edu/student/login",
        "https://mail.ox.ac.uk/owa",
        "https://sso.iitm.ac.in/auth/callback?client_id=portal",
        "https://canvas.mit.edu/courses/1042/assignments",
        "https://admissions.harvard.edu/apply",
        "https://student.berkeley.edu/myacademic/grades",
        "https://webmail.ucla.edu/login.php",
        "https://library.cam.ac.uk/search?q=cybersecurity",
        "https://www.iitd.ac.in/academics/curriculum",
        "https://cmu.edu/hub/registration",
        "https://columbia.edu/students/portal",
        "https://instructure.com/login/canvas",
        "https://blackboard.com/portal/login"
    ]
    for u in edu_samples:
        feat = extract_row_features(u)
        feat["Label"] = 0
        rows.append(feat)

    # 2. Sample from Benign_list_big_final.csv (Diverse real benign URLs)
    benign_csv = DATA_DIR / "1.Benign_list_big_final.csv"
    if benign_csv.exists():
        df_b = pd.read_csv(benign_csv, header=None, nrows=6000)
        urls_b = df_b[0].dropna().unique().tolist()
        for u in urls_b[:4987]:
            feat = extract_row_features(u)
            feat["Label"] = 0
            rows.append(feat)

    # 3. Sample from 2.online-valid.csv (Real verified phishing URLs)
    phish_csv = DATA_DIR / "2.online-valid.csv"
    if phish_csv.exists():
        df_p = pd.read_csv(phish_csv, nrows=6000)
        urls_p = df_p["url"].dropna().unique().tolist()
        for u in urls_p[:5000]:
            feat = extract_row_features(u)
            feat["Label"] = 1
            rows.append(feat)

    df_balanced = pd.DataFrame(rows).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df_balanced

def train_and_evaluate():
    print("Building balanced, leakage-free URL dataset...")
    df = build_dataset()
    print(f"Dataset shape: {df.shape}")
    print(f"Class distribution:\n{df['Label'].value_counts()}")

    X = df.drop(columns=["Label"])
    y = df["Label"].astype(int)
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")

    # 1. Base XGBoost
    base_xgb = XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.08,
        eval_metric="logloss",
        random_state=42
    )
    # Calibrated Classifier (Platt scaling via sigmoid) to output true calibrated probabilities
    print("Training and calibrating XGBoost...")
    xgb_calibrated = CalibratedClassifierCV(base_xgb, method="sigmoid", cv=3)
    xgb_calibrated.fit(X_train, y_train)

    xgb_preds = xgb_calibrated.predict(X_test)
    xgb_probs = xgb_calibrated.predict_proba(X_test)[:, 1]

    # 2. Random Forest
    print("Training Random Forest...")
    base_rf = RandomForestClassifier(n_estimators=120, max_depth=8, random_state=42)
    rf_calibrated = CalibratedClassifierCV(base_rf, method="sigmoid", cv=3)
    rf_calibrated.fit(X_train, y_train)

    rf_preds = rf_calibrated.predict(X_test)
    rf_probs = rf_calibrated.predict_proba(X_test)[:, 1]

    # Train a single uncalibrated tree to obtain exact feature importances
    base_xgb.fit(X_train, y_train)
    xgb_importances = {feat: round(float(imp), 4) for feat, imp in zip(feature_names, base_xgb.feature_importances_)}
    xgb_importances = dict(sorted(xgb_importances.items(), key=lambda item: item[1], reverse=True))

    def evaluate_model(y_true, y_pred, y_prob):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        return {
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
            "brier_score": round(float(brier_score_loss(y_true, y_prob)), 4),
            "false_positive_rate": round(float(fp / (fp + tn)), 4) if (fp + tn) > 0 else 0.0,
            "false_negative_rate": round(float(fn / (fn + tp)), 4) if (fn + tp) > 0 else 0.0,
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        }

    xgb_metrics = evaluate_model(y_test, xgb_preds, xgb_probs)
    rf_metrics = evaluate_model(y_test, rf_preds, rf_probs)

    # Save models
    with open(MODEL_DIR / "xgboost_model.pkl", "wb") as f:
        pickle.dump(xgb_calibrated, f)
    with open(MODEL_DIR / "random_forest_model.pkl", "wb") as f:
        pickle.dump(rf_calibrated, f)
    with open(MODEL_DIR / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    metrics_summary = {
        "dataset": {
            "source": "Balanced PhishTank Verified & Legitimate Datasets",
            "total_samples": len(df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "features": feature_names
        },
        "models": {
            "xgboost": {
                "name": "Calibrated XGBoost Classifier",
                "metrics": xgb_metrics,
                "feature_importance": xgb_importances
            },
            "random_forest": {
                "name": "Calibrated Random Forest",
                "metrics": rf_metrics
            },
            "cnn_deep_learning": {
                "name": "Convolutional Neural Network (Char-Level)",
                "details": {
                    "architecture": "1D-CNN (Embedding + Conv1D + MaxPool + Dense)",
                    "vocab_size": 41,
                    "max_length": 200,
                    "calibration": "Domain-contextualized temperature scaling"
                }
            }
        }
    }

    with open(MODEL_DIR / "model_metrics.json", "w") as f:
        json.dump(metrics_summary, f, indent=2)

    print("\nModel training and calibration completed!")
    print(f"XGBoost Test Accuracy: {xgb_metrics['accuracy']:.2%}")
    print(f"XGBoost Precision:     {xgb_metrics['precision']:.2%}")
    print(f"XGBoost Recall:        {xgb_metrics['recall']:.2%}")
    print(f"XGBoost F1-Score:      {xgb_metrics['f1_score']:.4f}")
    print(f"XGBoost Brier Score:   {xgb_metrics['brier_score']:.4f} (lower is better, <0.1 is well-calibrated)")
    print(f"XGBoost False Positives: {xgb_metrics['confusion_matrix']['false_positive']} / {xgb_metrics['confusion_matrix']['true_negative'] + xgb_metrics['confusion_matrix']['false_positive']}")

if __name__ == "__main__":
    train_and_evaluate()

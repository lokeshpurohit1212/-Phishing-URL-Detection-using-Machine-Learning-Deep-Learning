"""
Tabular Machine Learning Model Wrapper.
Integrates trained XGBoost and Random Forest classifiers.
"""

import os
import json
import pickle
import pandas as pd
from pathlib import Path
from src.config import XGBOOST_MODEL_PATH, RANDOM_FOREST_MODEL_PATH, METRICS_PATH
from src.utils.logging_config import logger

class TabularMLDetector:
    """Wrapper for trained XGBoost & Random Forest phishing classifiers."""
    
    _instance = None
    _xgb_model = None
    _rf_model = None
    _metrics = None
    _feature_names = None
    _is_loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TabularMLDetector, cls).__new__(cls)
            cls._instance._load_models()
        return cls._instance

    def _load_models(self):
        try:
            if Path(XGBOOST_MODEL_PATH).exists():
                with open(XGBOOST_MODEL_PATH, "rb") as f:
                    self._xgb_model = pickle.load(f)

            if Path(RANDOM_FOREST_MODEL_PATH).exists():
                with open(RANDOM_FOREST_MODEL_PATH, "rb") as f:
                    self._rf_model = pickle.load(f)

            if Path(METRICS_PATH).exists():
                with open(METRICS_PATH, "r") as f:
                    self._metrics = json.load(f)

            feats_path = Path(XGBOOST_MODEL_PATH).parent / "feature_names.json"
            if feats_path.exists():
                with open(feats_path, "r") as f:
                    self._feature_names = json.load(f)
            else:
                self._feature_names = [
                    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                    'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
                ]

            self._is_loaded = (self._xgb_model is not None or self._rf_model is not None)
            logger.info("Tabular ML Models loaded successfully.")
        except Exception as e:
            self._is_loaded = False
            logger.error(f"Failed to load ML models: {e}")

    @property
    def is_available(self) -> bool:
        return self._is_loaded

    @property
    def metrics(self) -> dict:
        return self._metrics or {}

    def predict(self, tabular_feature_dict: dict, model_type: str = "xgboost") -> dict:
        """
        Predicts phishing probability using the specified tabular model.
        Returns probability, prediction label, and top contributing feature importances.
        """
        model = self._xgb_model if model_type == "xgboost" else self._rf_model
        model_name = "XGBoost" if model_type == "xgboost" else "Random Forest"

        if not model:
            return {
                "available": False,
                "model_name": model_name,
                "probability": None,
                "label": "UNAVAILABLE",
                "top_features": {},
                "error": "Model file not found"
            }

        try:
            # Build 1-row DataFrame with strict column order
            row_data = {feat: [tabular_feature_dict.get(feat, 0)] for feat in self._feature_names}
            df = pd.DataFrame(row_data)

            prob = float(model.predict_proba(df)[0, 1])
            label = "PHISHING" if prob >= 0.50 else "LEGITIMATE"

            # Feature importance map from saved metrics or model
            imp_dict = {}
            if self._metrics and "models" in self._metrics:
                m_key = "xgboost" if model_type == "xgboost" else "random_forest"
                imp_dict = self._metrics["models"].get(m_key, {}).get("feature_importance", {})
            elif hasattr(model, "feature_importances_"):
                imp_dict = {
                    feat: round(float(imp), 4)
                    for feat, imp in zip(self._feature_names, model.feature_importances_)
                }

            return {
                "available": True,
                "model_name": model_name,
                "probability": round(prob, 4),
                "label": label,
                "confidence": round(abs(prob - 0.5) * 2.0, 4),
                "top_features": imp_dict,
                "error": None
            }
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return {
                "available": False,
                "model_name": model_name,
                "probability": None,
                "label": "ERROR",
                "top_features": {},
                "error": str(e)
            }

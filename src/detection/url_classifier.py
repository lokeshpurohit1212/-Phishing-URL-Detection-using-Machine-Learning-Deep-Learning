"""
CNN Deep Learning URL Classifier.
Integrates the existing trained 1D-CNN character-level neural network.
"""

import pickle
import numpy as np
from pathlib import Path
from src.config import CNN_MODEL_PATH, TOKENIZER_PATH
from src.utils.logging_config import logger

class CNNURLClassifier:
    """Wrapper for the pre-trained Character-level 1D-CNN Phishing Detection Model."""
    
    _instance = None
    _model = None
    _tokenizer = None
    _is_loaded = False
    _load_error = None
    MAX_LENGTH = 200

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CNNURLClassifier, cls).__new__(cls)
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        try:
            if not Path(CNN_MODEL_PATH).exists():
                self._load_error = f"CNN model file not found at {CNN_MODEL_PATH}"
                logger.warning(self._load_error)
                return

            if not Path(TOKENIZER_PATH).exists():
                self._load_error = f"Tokenizer file not found at {TOKENIZER_PATH}"
                logger.warning(self._load_error)
                return

            import tensorflow as tf
            from tensorflow.keras.preprocessing.sequence import pad_sequences
            self._pad_sequences = pad_sequences

            self._model = tf.keras.models.load_model(str(CNN_MODEL_PATH))
            with open(TOKENIZER_PATH, "rb") as f:
                self._tokenizer = pickle.load(f)

            self._is_loaded = True
            logger.info("CNN Phishing Model and Tokenizer successfully loaded.")
        except Exception as e:
            self._is_loaded = False
            self._load_error = f"Failed to initialize CNN model: {str(e)}"
            logger.error(self._load_error)

    @property
    def is_available(self) -> bool:
        return self._is_loaded

    @property
    def load_error(self) -> str:
        return self._load_error

    def predict(self, url: str) -> dict:
        """
        Classify a single URL using the trained CNN.
        Returns prediction probability and confidence.
        """
        if not self._is_loaded:
            return {
                "available": False,
                "probability": None,
                "label": "UNAVAILABLE",
                "confidence": 0.0,
                "error": self._load_error or "Model not loaded"
            }

        try:
            clean_url = (
                url.lower()
                .replace("https://", "")
                .replace("http://", "")
                .rstrip("/")
            )

            sequence = self._tokenizer.texts_to_sequences([clean_url])
            padded = self._pad_sequences(
                sequence,
                maxlen=self.MAX_LENGTH,
                padding="post"
            )

            raw_prob = float(self._model.predict(padded, verbose=0)[0][0])
            # Bound probability to [0.0, 1.0]
            probability = max(0.0, min(1.0, raw_prob))
            
            # Confidence represents distance from decision threshold (0.5)
            confidence = abs(probability - 0.5) * 2.0  # Scale 0 to 1

            label = "PHISHING" if probability >= 0.50 else "LEGITIMATE"

            return {
                "available": True,
                "probability": round(probability, 4),
                "label": label,
                "confidence": round(confidence, 4),
                "error": None
            }
        except Exception as e:
            logger.error(f"Error predicting with CNN for URL: {str(e)}")
            return {
                "available": False,
                "probability": None,
                "label": "ERROR",
                "confidence": 0.0,
                "error": str(e)
            }

    def batch_predict(self, urls: list[str]) -> list[dict]:
        """Classifies multiple URLs efficiently in batch."""
        if not self._is_loaded or not urls:
            return [self.predict(u) for u in urls]

        try:
            clean_urls = [
                u.lower().replace("https://", "").replace("http://", "").rstrip("/")
                for u in urls
            ]
            sequences = self._tokenizer.texts_to_sequences(clean_urls)
            padded = self._pad_sequences(sequences, maxlen=self.MAX_LENGTH, padding="post")
            raw_probs = self._model.predict(padded, verbose=0).flatten()

            results = []
            for prob in raw_probs:
                p = max(0.0, min(1.0, float(prob)))
                results.append({
                    "available": True,
                    "probability": round(p, 4),
                    "label": "PHISHING" if p >= 0.50 else "LEGITIMATE",
                    "confidence": round(abs(p - 0.5) * 2.0, 4),
                    "error": None
                })
            return results
        except Exception as e:
            logger.error(f"Batch prediction error: {str(e)}")
            return [self.predict(u) for u in urls]

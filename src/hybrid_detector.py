import os
import pickle
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences

try:
    from src.risk_analyzer import analyze_url
except ImportError:
    from risk_analyzer import analyze_url


# ==============================
# LOAD CNN MODEL
# ==============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_cnn_model.h5")
TOKENIZER_PATH = os.path.join(BASE_DIR, "models", "tokenizer.pkl")

model = tf.keras.models.load_model(MODEL_PATH)

with open(TOKENIZER_PATH, "rb") as f:
    tokenizer = pickle.load(f)

MAX_LENGTH = 200


def get_cnn_prediction(url):

    # Remove protocol for CNN
    clean_url = (
        url.lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    sequence = tokenizer.texts_to_sequences([clean_url])

    padded = pad_sequences(
        sequence,
        maxlen=MAX_LENGTH,
        padding="post"
    )

    probability = float(model.predict(padded, verbose=0)[0][0])

    return probability


def hybrid_predict(url):

    # --------------------------------
    # 1. CNN Prediction
    # --------------------------------

    cnn_probability = get_cnn_prediction(url)

    # --------------------------------
    # 2. Rule-Based Risk Analysis
    # --------------------------------

    risk_result = analyze_url(url)

    risk_score = risk_result["risk_score"]
    trusted = risk_result["trusted"]

    # Convert risk score to probability
    rule_probability = risk_score / 100

    # --------------------------------
    # 3. Hybrid Score
    # --------------------------------

    hybrid_probability = (
        0.65 * cnn_probability
        + 0.35 * rule_probability
    )

    # --------------------------------
    # 4. Trusted Domain Adjustment
    # --------------------------------

    if trusted:
        hybrid_probability = min(
            hybrid_probability,
            0.20
        )

    # --------------------------------
    # 5. High-Risk Rule Adjustment
    # --------------------------------

    if not trusted and risk_score >= 70:

        hybrid_probability = max(
            hybrid_probability,
            0.75
        )

    # --------------------------------
    # 6. Final Classification
    # --------------------------------

    if hybrid_probability >= 0.70:
        prediction = "PHISHING"

    elif hybrid_probability >= 0.40:
        prediction = "SUSPICIOUS"

    else:
        prediction = "LEGITIMATE"

    return {
        "url": url,
        "cnn_probability": round(cnn_probability, 3),
        "rule_risk_score": risk_score,
        "hybrid_probability": round(
            hybrid_probability, 3
        ),
        "prediction": prediction,
        "trusted": trusted,
        "reasons": risk_result["reasons"]
    }


# ==============================
# TEST
# ==============================

if __name__ == "__main__":

    test_urls = [
        "google.com",
        "github.com",
        "youtube.com",
        "paypal.com",
        "paypal-login-secure.xyz",
        "http://192.168.1.100/login",
        "google.verify.account.security-login.xyz"
    ]

    for url in test_urls:

        result = hybrid_predict(url)

        print("\n" + "=" * 55)
        print("URL:", result["url"])
        print("CNN Probability:", result["cnn_probability"])
        print("Rule Risk Score:", result["rule_risk_score"])
        print("Hybrid Probability:", result["hybrid_probability"])
        print("Prediction:", result["prediction"])
        print("Trusted:", result["trusted"])

        print("Reasons:")

        if result["reasons"]:
            for reason in result["reasons"]:
                print("-", reason)

        else:
            print("- No major suspicious patterns detected")
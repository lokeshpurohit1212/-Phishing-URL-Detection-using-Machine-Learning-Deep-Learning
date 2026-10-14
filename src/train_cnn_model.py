"""
Retrain and calibrate the 1D-CNN Character Sequence Neural Network.
Incorporates representative institutional, commercial, and verified phishing URLs
to eliminate false positive bias against academic domains and legitimate paths.
"""

import os
import pickle
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, brier_score_loss

from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Input, Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "models")
DATA_DIR = os.path.join(BASE_DIR, "data")

def clean_url_for_cnn(u: str) -> str:
    """Normalize and clean URL for character tokenizer."""
    return (
        str(u).lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
        .strip()
    )

def prepare_data():
    urls = []
    labels = []

    # 1. Academic & Institutional Legitimate Domains & Portals
    academic_samples = [
        "stanford.edu", "portal.stanford.edu/student/login", "cs.stanford.edu",
        "mit.edu", "canvas.mit.edu/courses/1042", "news.mit.edu/research",
        "harvard.edu", "admissions.harvard.edu/apply", "alumni.harvard.edu",
        "ox.ac.uk", "mail.ox.ac.uk/owa", "ox.ac.uk/admissions/graduate",
        "cam.ac.uk", "library.cam.ac.uk/search", "cam.ac.uk/study",
        "berkeley.edu", "student.berkeley.edu/grades", "calnet.berkeley.edu/auth",
        "ucla.edu", "webmail.ucla.edu/login.php", "my.ucla.edu",
        "iitm.ac.in", "sso.iitm.ac.in/auth/callback", "academic.iitm.ac.in",
        "iitd.ac.in", "home.iitd.ac.in/academics", "webmail.iitd.ac.in",
        "iitb.ac.in", "portal.iitb.ac.in/asc", "cmu.edu/hub/registration",
        "columbia.edu", "princeton.edu", "yale.edu", "cornell.edu",
        "utoronto.ca", "instructure.com/login/canvas", "blackboard.com/login",
        "moodle.org", "edx.org", "coursera.org", "khanacademy.org"
    ]
    for u in academic_samples:
        urls.append(clean_url_for_cnn(u))
        labels.append(0)

    # 2. Legitimate sites from legitimate_sites.csv
    legit_csv = os.path.join(BASE_DIR, "legitimate_sites.csv")
    if os.path.exists(legit_csv):
        df_legit = pd.read_csv(legit_csv)
        for dom in df_legit["Domain"].dropna().tolist():
            urls.append(clean_url_for_cnn(dom))
            labels.append(0)

    # 3. Benign URLs from 1.Benign_list_big_final.csv
    benign_big = os.path.join(DATA_DIR, "1.Benign_list_big_final.csv")
    if os.path.exists(benign_big):
        df_b = pd.read_csv(benign_big, header=None, nrows=4000)
        for u in df_b[0].dropna().tolist():
            urls.append(clean_url_for_cnn(u))
            labels.append(0)

    # 4. Legit from 5.urldata.csv
    urldata = os.path.join(DATA_DIR, "5.urldata.csv")
    if os.path.exists(urldata):
        df_u = pd.read_csv(urldata)
        for dom in df_u[df_u["Label"] == 0]["Domain"].dropna().head(3000).tolist():
            urls.append(clean_url_for_cnn(dom))
            labels.append(0)

    # 5. Verified Phishing URLs from 2.online-valid.csv
    phish_valid = os.path.join(DATA_DIR, "2.online-valid.csv")
    if os.path.exists(phish_valid):
        df_pv = pd.read_csv(phish_valid, nrows=4000)
        for u in df_pv["url"].dropna().tolist():
            urls.append(clean_url_for_cnn(u))
            labels.append(1)

    # 6. Phishing from 5.urldata.csv
    if os.path.exists(urldata):
        for dom in df_u[df_u["Label"] == 1]["Domain"].dropna().head(3000).tolist():
            urls.append(clean_url_for_cnn(dom))
            labels.append(1)

    # Combine into DataFrame & deduplicate
    df = pd.DataFrame({"url": urls, "label": labels})
    df.drop_duplicates(subset=["url"], inplace=True)
    
    # Balance classes equally
    phish_df = df[df["label"] == 1]
    legit_df = df[df["label"] == 0]
    n_samples = min(len(phish_df), len(legit_df))
    
    balanced_df = pd.concat([
        legit_df.sample(n_samples, random_state=42),
        phish_df.sample(n_samples, random_state=42)
    ]).sample(frac=1.0, random_state=42).reset_index(drop=True)

    print(f"Total balanced dataset: {len(balanced_df)} samples ({n_samples} per class).")
    return balanced_df["url"].tolist(), balanced_df["label"].values

def train_cnn():
    urls, labels = prepare_data()
    
    max_vocab_size = 100
    max_length = 200

    tokenizer = Tokenizer(
        num_words=max_vocab_size,
        char_level=True,
        oov_token="<OOV>"
    )
    tokenizer.fit_on_texts(urls)
    sequences = tokenizer.texts_to_sequences(urls)
    X = pad_sequences(sequences, maxlen=max_length, padding="post", truncating="post")
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Train size: {len(X_train)}, Test size: {len(X_test)}")

    model = Sequential([
        Input(shape=(max_length,)),
        Embedding(input_dim=max_vocab_size, output_dim=32),
        Conv1D(filters=64, kernel_size=5, activation="relu"),
        GlobalMaxPooling1D(),
        Dense(64, activation="relu"),
        Dropout(0.5),
        Dense(1, activation="sigmoid")
    ])

    model.compile(
        loss="binary_crossentropy",
        optimizer="adam",
        metrics=["accuracy"]
    )

    print("Training CNN model...")
    model.fit(
        X_train,
        y_train,
        epochs=6,
        batch_size=64,
        validation_split=0.15,
        verbose=1
    )

    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob >= 0.5).astype(int)
    auc = roc_auc_score(y_test, y_prob)
    brier = brier_score_loss(y_test, y_prob)

    print(f"\nCNN Test Accuracy: {acc:.4f}, ROC-AUC: {auc:.4f}, Brier Score: {brier:.4f}")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Save retrained model and tokenizer
    model_path = os.path.join(MODEL_DIR, "phishing_cnn_model.h5")
    tokenizer_path = os.path.join(MODEL_DIR, "tokenizer.pkl")

    model.save(model_path)
    with open(tokenizer_path, "wb") as f:
        pickle.dump(tokenizer, f)

    print(f"\nModel and tokenizer saved successfully to {MODEL_DIR}!")

if __name__ == "__main__":
    train_cnn()

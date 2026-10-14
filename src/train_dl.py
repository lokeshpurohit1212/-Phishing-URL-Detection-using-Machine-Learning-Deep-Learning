import os
import pandas as pd
import numpy as np
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    Input,
    Embedding,
    Conv1D,
    GlobalMaxPooling1D,
    Dense,
    Dropout
)

import pickle
import matplotlib.pyplot as plt


# ==============================
# 1. PROJECT PATHS
# ==============================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR,
    "data",
    "5.urldata_updated.csv"
)

MODEL_DIR = os.path.join(BASE_DIR, "models")

print("Loading dataset from:")
print(DATA_PATH)


# ==============================
# 2. LOAD DATASET
# ==============================

df = pd.read_csv(DATA_PATH)

print("\nCSV loaded successfully!")
print("Dataset shape:", df.shape)
print("Columns:", df.columns.tolist())

df = df[["Domain", "Label"]]
df.dropna(inplace=True)

urls = df["Domain"].astype(str)
labels = df["Label"].astype(int).values

print("\nTotal URLs:", len(urls))
print("Label distribution:")
print(df["Label"].value_counts())


# ==============================
# 3. TOKENIZATION
# ==============================

max_vocab_size = 100
max_length = 200

tokenizer = Tokenizer(
    num_words=max_vocab_size,
    char_level=True,
    oov_token="<OOV>"
)

tokenizer.fit_on_texts(urls)

sequences = tokenizer.texts_to_sequences(urls)

X = pad_sequences(
    sequences,
    maxlen=max_length,
    padding="post",
    truncating="post"
)

y = labels


# ==============================
# 4. TRAIN / TEST SPLIT
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==============================
# 5. BUILD CNN MODEL
# ==============================

model = Sequential([
    Input(shape=(max_length,)),

    Embedding(
        input_dim=max_vocab_size,
        output_dim=32
    ),

    Conv1D(
        filters=64,
        kernel_size=5,
        activation="relu"
    ),

    GlobalMaxPooling1D(),

    Dense(
        64,
        activation="relu"
    ),

    Dropout(0.5),

    Dense(
        1,
        activation="sigmoid"
    )
])


model.compile(
    loss="binary_crossentropy",
    optimizer="adam",
    metrics=["accuracy"]
)

print("\nMODEL SUMMARY")
model.summary()


# ==============================
# 6. TRAIN MODEL
# ==============================

history = model.fit(
    X_train,
    y_train,
    epochs=5,
    batch_size=64,
    validation_split=0.20
)


# ==============================
# 7. EVALUATE MODEL
# ==============================

loss, accuracy = model.evaluate(
    X_test,
    y_test,
    verbose=0
)

print(f"\nTest Loss: {loss:.4f}")
print(f"Test Accuracy: {accuracy:.4f}")


# Predictions
y_prob = model.predict(X_test)
y_pred = (y_prob > 0.5).astype("int32").flatten()


print("\nCLASSIFICATION REPORT")
print(
    classification_report(
        y_test,
        y_pred
    )
)


print("\nCONFUSION MATRIX")
print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


# ==============================
# 8. SAVE MODEL
# ==============================

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)

model_path = os.path.join(
    MODEL_DIR,
    "phishing_cnn_model.h5"
)

model.save(model_path)

print("\nModel saved successfully:")
print(model_path)


# ==============================
# 9. SAVE TOKENIZER
# ==============================

tokenizer_path = os.path.join(
    MODEL_DIR,
    "tokenizer.pkl"
)

with open(
    tokenizer_path,
    "wb"
) as f:

    pickle.dump(
        tokenizer,
        f
    )

print("\nTokenizer saved successfully:")
print(tokenizer_path)


# ==============================
# 10. PLOT ACCURACY
# ==============================

plt.figure(figsize=(8, 5))

plt.plot(
    history.history["accuracy"],
    label="Training Accuracy"
)

plt.plot(
    history.history["val_accuracy"],
    label="Validation Accuracy"
)

plt.title("SafeBrowse CNN Model Accuracy")
plt.xlabel("Epoch")
plt.ylabel("Accuracy")

plt.legend()

plt.grid()

plt.show()
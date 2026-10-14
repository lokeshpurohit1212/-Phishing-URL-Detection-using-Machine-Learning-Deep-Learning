import os
import pandas as pd
import pickle

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier


# ==============================
# 1. Load Feature-Based Dataset
# ==============================

DATA_PATH = "data/5.urldata.csv"

df = pd.read_csv(DATA_PATH)

df = df.dropna()

X = df.drop(["Label", "Domain"], axis=1)
y = df["Label"]


# ==============================
# 2. Train/Test Split
# ==============================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


# ==============================
# 3. Train XGBoost
# ==============================

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric="logloss"
)

model.fit(X_train, y_train)


# ==============================
# 4. Evaluate
# ==============================

accuracy = model.score(X_test, y_test)

print(f"\nXGBoost Test Accuracy: {accuracy:.4f}")

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# ==============================
# 5. Save Model
# ==============================

os.makedirs("models", exist_ok=True)

with open("models/xgboost_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\nXGBoost model saved successfully!")

import matplotlib.pyplot as plt

plt.bar(range(len(model.feature_importances_)), model.feature_importances_)
plt.title("Feature Importance")
plt.show()
"""
Trains the URL-maliciousness classifier on data/url_dataset.csv
(produced by prepare_url_dataset.py) and saves the fitted model to
app/models/url_model.joblib

Model: SGDClassifier(loss="log_loss") -- chosen (not RandomForest) specifically
because it supports .partial_fit(), which the backend's online-learning
feedback loop depends on.

Run:  python train_url_model.py
"""
import os
import sys
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))  # so we can import app.ml.url_features

from app.ml.url_features import features_to_vector, FEATURE_ORDER  # noqa: E402

DATA_DIR = os.path.join(HERE, "..", "app", "data")
MODEL_DIR = os.path.join(HERE, "..", "app", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET = os.path.join(DATA_DIR, "url_dataset.csv")
MODEL_OUT = os.path.join(MODEL_DIR, "url_model.joblib")


def main():
    if not os.path.exists(DATASET):
        print(f"[X] {DATASET} not found. Run prepare_url_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(DATASET).dropna(subset=["url", "label"])
    print(f"[*] Loaded {len(df)} rows.")

    print("[*] Extracting lexical/structural features for every URL...")
    X = df["url"].apply(features_to_vector).tolist()
    y = df["label"].astype(int).tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = SGDClassifier(loss="log_loss", max_iter=1000, random_state=42, class_weight="balanced")
    clf.fit(X_train_s, y_train)

    preds = clf.predict(X_test_s)
    probs = clf.predict_proba(X_test_s)[:, 1]
    print("\n[Evaluation on held-out test set]")
    print(classification_report(y_test, preds, target_names=["benign", "malicious"]))
    try:
        print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")
    except ValueError:
        pass

    joblib.dump(
        {"model": clf, "scaler": scaler, "feature_order": FEATURE_ORDER},
        MODEL_OUT,
    )
    print(f"\n[+] Saved trained model to {MODEL_OUT}")


if __name__ == "__main__":
    main()

"""
Trains the malware-API-call-sequence classifier on data/api_dataset.csv
(produced by prepare_api_dataset.py) and saves the fitted vectorizer +
model to app/models/api_model.joblib

Model: TfidfVectorizer(analyzer="word", ngram_range=(1,3)) + SGDClassifier
-- word-level (not char-level) n-grams are used here because each token IS
a whole API call name (e.g. "VirtualAllocEx"), so word n-grams capture
call *sequences/motifs* (e.g. "VirtualAllocEx WriteProcessMemory
CreateRemoteThread" as a 3-gram) the same way the heuristic layer's
pattern-matching does, just learned statistically instead of hardcoded.
Same partial_fit-friendly design as the URL/text models for the online
feedback loop.

Run:  python train_api_model.py
"""
import os
import sys
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))  # so we can import app.ml.api_features

from app.ml.api_features import normalize_call_sequence  # noqa: E402

DATA_DIR = os.path.join(HERE, "..", "app", "data")
MODEL_DIR = os.path.join(HERE, "..", "app", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET = os.path.join(DATA_DIR, "api_dataset.csv")
MODEL_OUT = os.path.join(MODEL_DIR, "api_model.joblib")


def main():
    if not os.path.exists(DATASET):
        print(f"[X] {DATASET} not found. Run prepare_api_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(DATASET).dropna(subset=["api_sequence", "label"])
    df["api_sequence"] = df["api_sequence"].apply(normalize_call_sequence)
    df = df[df["api_sequence"].str.strip().astype(bool)]
    print(f"[*] Loaded {len(df)} rows.")

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["api_sequence"], df["label"].astype(int), test_size=0.2, random_state=42,
        stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(analyzer="word", ngram_range=(1, 3), max_features=30000)
    X_train = vectorizer.fit_transform(X_train_raw)
    X_test = vectorizer.transform(X_test_raw)

    clf = SGDClassifier(loss="log_loss", max_iter=1000, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]
    print("\n[Evaluation on held-out test set]")
    print(classification_report(y_test, preds, target_names=["benign", "malware"]))
    try:
        print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")
    except ValueError:
        pass

    joblib.dump({"model": clf, "vectorizer": vectorizer}, MODEL_OUT)
    print(f"\n[+] Saved trained model to {MODEL_OUT}")


if __name__ == "__main__":
    main()

"""
Trains the text-maliciousness classifier (spam/phishing vs. benign) on
data/text_dataset.csv (produced by prepare_text_dataset.py) and saves the
fitted vectorizer + model to app/models/text_model.joblib

Model: TfidfVectorizer(char_wb n-grams) + SGDClassifier(loss="log_loss")
-- same partial_fit-friendly design as the URL model, so the feedback loop
can incrementally retrain it too.

Run:  python train_text_model.py
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
DATA_DIR = os.path.join(HERE, "..", "app", "data")
MODEL_DIR = os.path.join(HERE, "..", "app", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET = os.path.join(DATA_DIR, "text_dataset.csv")
MODEL_OUT = os.path.join(MODEL_DIR, "text_model.joblib")


def main():
    if not os.path.exists(DATASET):
        print(f"[X] {DATASET} not found. Run prepare_text_dataset.py first.")
        sys.exit(1)

    df = pd.read_csv(DATASET).dropna(subset=["text", "label"])
    df = df[df["text"].str.strip().astype(bool)]
    print(f"[*] Loaded {len(df)} rows.")

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df["text"], df["label"].astype(int), test_size=0.2, random_state=42,
        stratify=df["label"]
    )

    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=20000)
    X_train = vectorizer.fit_transform(X_train_raw)
    X_test = vectorizer.transform(X_test_raw)

    clf = SGDClassifier(loss="log_loss", max_iter=1000, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]
    print("\n[Evaluation on held-out test set]")
    print(classification_report(y_test, preds, target_names=["benign", "malicious"]))
    try:
        print(f"ROC-AUC: {roc_auc_score(y_test, probs):.4f}")
    except ValueError:
        pass

    joblib.dump({"model": clf, "vectorizer": vectorizer}, MODEL_OUT)
    print(f"\n[+] Saved trained model to {MODEL_OUT}")


if __name__ == "__main__":
    main()

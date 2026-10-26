"""
Builds data/text_dataset.csv with columns: text,label
(label=1 malicious/spam/phishing, 0 benign)

This version works directly off Kaggle datasets you've already downloaded
yourself -- no Kaggle CLI, no downloads, no credentials needed at all.

Place your two downloaded CSVs at:
    backend/app/data/sms_spam_raw.csv        (the SMS Spam Collection dataset)
    backend/app/data/phishing_email_raw.csv  (the phishing-email dataset)

Either file is optional -- if only one exists, the script uses just that one
(a single real source is fine; it just won't fabricate the missing one).
Column names are auto-detected (case-insensitive) from common variants used
by these datasets, so you generally don't need to rename anything.

USAGE
-----
python prepare_text_dataset.py
python prepare_text_dataset.py --sms /path/to/sms.csv --phishing /path/to/phish.csv
"""
import os
import sys
import argparse
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "app", "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_SMS = os.path.join(DATA_DIR, "sms_spam_raw.csv")
DEFAULT_PHISHING = os.path.join(DATA_DIR, "phishing_email_raw.csv")
OUTPUT = os.path.join(DATA_DIR, "text_dataset.csv")


def load_sms_spam(path):
    if not path or not os.path.exists(path):
        print(f"[!] SMS spam file not found at {path}, skipping this source.")
        return pd.DataFrame(columns=["text", "label"])

    df = pd.read_csv(path, encoding="latin-1")
    cols = {c.lower(): c for c in df.columns}
    label_col = cols.get("v1") or cols.get("label") or cols.get("category")
    text_col = cols.get("v2") or cols.get("text") or cols.get("message")

    if not label_col or not text_col:
        print(f"[X] Could not detect text/label columns in {path}. Columns found: {list(df.columns)}")
        return pd.DataFrame(columns=["text", "label"])

    out = df[[text_col, label_col]].rename(columns={text_col: "text", label_col: "raw_label"})
    out["label"] = out["raw_label"].astype(str).str.lower().map({"spam": 1, "ham": 0})
    result = out[["text", "label"]].dropna()
    print(f"[+] Loaded {len(result)} rows from {path}")
    return result


def load_phishing_emails(path):
    if not path or not os.path.exists(path):
        print(f"[!] Phishing email file not found at {path}, skipping this source.")
        return pd.DataFrame(columns=["text", "label"])

    df = pd.read_csv(path)
    cols = {c.lower(): c for c in df.columns}
    text_col = cols.get("email text") or cols.get("text") or cols.get("body") or df.columns[0]
    label_col = cols.get("email type") or cols.get("label") or cols.get("type") or df.columns[-1]

    out = df[[text_col, label_col]].rename(columns={text_col: "text", label_col: "raw_label"})

    def normalize_label(v):
        v = str(v).strip().lower()
        if v in ("1", "phishing email", "phishing", "spam", "malicious"):
            return 1
        if v in ("0", "safe email", "safe", "ham", "benign", "legitimate"):
            return 0
        return None

    out["label"] = out["raw_label"].apply(normalize_label)
    result = out[["text", "label"]].dropna()
    print(f"[+] Loaded {len(result)} rows from {path}")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sms", default=DEFAULT_SMS, help="Path to the SMS spam CSV")
    parser.add_argument("--phishing", default=DEFAULT_PHISHING, help="Path to the phishing-email CSV")
    args = parser.parse_args()

    sms = load_sms_spam(args.sms)
    phish = load_phishing_emails(args.phishing)

    combined = pd.concat([sms, phish], ignore_index=True)
    if combined.empty:
        print("[X] No text data available. Place your downloaded CSV(s) at the paths above")
        print(f"    ({DEFAULT_SMS} and/or {DEFAULT_PHISHING}) or pass --sms / --phishing, and re-run.")
        sys.exit(1)

    combined["label"] = combined["label"].astype(int)
    combined = combined.drop_duplicates(subset="text").sample(frac=1, random_state=42).reset_index(drop=True)
    combined.to_csv(OUTPUT, index=False)
    n_mal = (combined["label"] == 1).sum()
    n_ben = (combined["label"] == 0).sum()
    print(f"[+] Wrote {len(combined)} rows ({n_mal} malicious / {n_ben} benign) to {OUTPUT}")


if __name__ == "__main__":
    main()

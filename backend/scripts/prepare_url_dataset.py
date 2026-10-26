"""
Builds data/url_dataset.csv with columns: url,label,source_type
(label: 1 = malicious, 0 = benign)

This version works directly off a Kaggle URL-classification dataset you've
already downloaded yourself -- no downloads, no API keys, nothing else
needed from this script. It expects the common 4-class format used by
datasets like Kaggle's "Malicious URLs dataset" (url, type), where type is
one of: benign, defacement, malware, phishing.

Mapping:
  benign                      -> label 0 (safe)
  defacement / malware /      -> label 1 (malicious)
  phishing

SETUP
-----
Place your downloaded CSV at:
    backend/app/data/url_raw.csv
(or pass a different path with --input, see below)

It must have at least two columns whose names contain "url" and
"type"/"label"/"result" respectively (case-insensitive) -- the script
auto-detects them. If your column names are completely different, just
rename them in the CSV or edit COLUMN OVERRIDES below.

USAGE
-----
python prepare_url_dataset.py
python prepare_url_dataset.py --input /path/to/your_file.csv
"""
import os
import sys
import argparse
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "app", "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_INPUT = os.path.join(DATA_DIR, "url_raw.csv")
OUTPUT = os.path.join(DATA_DIR, "url_dataset.csv")

# If your CSV's column names don't get auto-detected, set them explicitly here.
COLUMN_OVERRIDES = {
    "url_col": None,   # e.g. "URL"
    "type_col": None,  # e.g. "Type"
}

BENIGN_VALUES = {"benign", "good", "safe", "legitimate", "0"}
MALICIOUS_VALUES = {"defacement", "malware", "phishing", "malicious", "bad", "1"}


def detect_column(df, keywords):
    for col in df.columns:
        low = col.lower()
        if any(k in low for k in keywords):
            return col
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to your downloaded Kaggle CSV")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[X] Could not find {args.input}")
        print("    Place your downloaded Kaggle CSV there, or re-run with --input <path>.")
        sys.exit(1)

    df = pd.read_csv(args.input)
    print(f"[*] Loaded {len(df)} rows from {args.input}")
    print(f"[*] Columns found: {list(df.columns)}")

    url_col = COLUMN_OVERRIDES["url_col"] or detect_column(df, ["url"])
    type_col = COLUMN_OVERRIDES["type_col"] or detect_column(df, ["type", "label", "result", "class"])

    if not url_col or not type_col:
        print("[X] Could not auto-detect the URL/type columns.")
        print(f"    Detected url_col={url_col}, type_col={type_col}")
        print("    Set COLUMN_OVERRIDES at the top of this script to the exact column names and re-run.")
        sys.exit(1)

    print(f"[*] Using url column: '{url_col}', type/label column: '{type_col}'")

    df = df[[url_col, type_col]].rename(columns={url_col: "url", type_col: "source_type"})
    df["source_type"] = df["source_type"].astype(str).str.strip().str.lower()

    print(f"[*] Class distribution before mapping:\n{df['source_type'].value_counts()}")

    def map_label(v):
        if v in BENIGN_VALUES:
            return 0
        if v in MALICIOUS_VALUES:
            return 1
        return None

    df["label"] = df["source_type"].apply(map_label)
    unmapped = df["label"].isna().sum()
    if unmapped:
        print(f"[!] {unmapped} rows had an unrecognized type value and will be dropped.")
        print("    Add any missing category names to BENIGN_VALUES/MALICIOUS_VALUES above if needed.")

    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset="url")

    # Balance classes so the classifier isn't biased toward the majority class
    # (this dataset is typically ~65% benign / 35% malicious across 3 attack types)
    n_mal = (df["label"] == 1).sum()
    n_ben = (df["label"] == 0).sum()
    n = min(n_mal, n_ben)
    balanced = pd.concat([
        df[df["label"] == 1].sample(n=n, random_state=42),
        df[df["label"] == 0].sample(n=n, random_state=42),
    ]).sample(frac=1, random_state=42).reset_index(drop=True)

    balanced.to_csv(OUTPUT, index=False)
    print(f"\n[+] Wrote {len(balanced)} rows ({n} malicious / {n} benign) to {OUTPUT}")
    print(f"    (Original malicious breakdown preserved in 'source_type' column for reference)")


if __name__ == "__main__":
    main()


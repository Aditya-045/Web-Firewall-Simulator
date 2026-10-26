"""
Builds data/api_dataset.csv with columns: api_sequence,label
(label=1 malware, 0 benign)

This version works directly off a malware API call-sequence dataset you've
already downloaded from Kaggle yourself -- no Kaggle CLI, no downloads, no
credentials needed at all.

Place your downloaded CSV at:
    backend/app/data/api_raw.csv
(or pass a different path with --input)

Handles both common shapes used by these datasets:
  (a) a single column of space/comma-separated call names + a label column, or
  (b) many numbered columns (t_1, t_2, ... t_100) each holding one call in
      the sequence, + a label column.
Column names are auto-detected; if detection fails for your specific file,
set COLUMN_OVERRIDES below to the exact column names.

USAGE
-----
python prepare_api_dataset.py
python prepare_api_dataset.py --input /path/to/your_file.csv
"""
import os
import sys
import argparse
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "..", "app", "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_INPUT = os.path.join(DATA_DIR, "api_raw.csv")
OUTPUT = os.path.join(DATA_DIR, "api_dataset.csv")

# If your CSV's column names don't get auto-detected, set them explicitly here.
COLUMN_OVERRIDES = {
    "sequence_col": None,  # e.g. "api_sequence" -- only used for shape (a)
    "label_col": None,     # e.g. "malware"
}


def _wide_columns_to_sequence(df, label_col):
    """Handle the 't_1, t_2, ... t_N' one-call-per-column dataset shape."""
    call_cols = [c for c in df.columns if c != label_col]
    return df[call_cols].astype(str).apply(
        lambda row: " ".join(v for v in row if v and v.lower() != "nan"), axis=1
    )


def load_api_dataset(path):
    if not os.path.exists(path):
        print(f"[X] Could not find {path}")
        print("    Place your downloaded Kaggle CSV there, or re-run with --input <path>.")
        return pd.DataFrame(columns=["api_sequence", "label"])

    df = pd.read_csv(path)
    print(f"[*] Loaded {len(df)} rows from {path}")
    print(f"[*] Columns found: {list(df.columns)}")

    cols_lower = {c.lower(): c for c in df.columns}

    label_col = (
        COLUMN_OVERRIDES["label_col"]
        or cols_lower.get("malware")
        or cols_lower.get("label")
        or cols_lower.get("class")
        or df.columns[-1]
    )

    # Shape (a): a single free-text sequence column already exists
    seq_col = (
        COLUMN_OVERRIDES["sequence_col"]
        or cols_lower.get("api_sequence")
        or cols_lower.get("api_calls")
        or cols_lower.get("sequence")
    )
    if seq_col and seq_col in df.columns:
        print(f"[*] Detected single sequence column: '{seq_col}', label column: '{label_col}'")
        out = df[[seq_col, label_col]].rename(columns={seq_col: "api_sequence", label_col: "raw_label"})
    else:
        # Shape (b): many t_1..t_N columns, one call per column
        print(f"[*] No single sequence column found -- treating as wide one-call-per-column format,")
        print(f"    using '{label_col}' as the label column and all other columns as call sequence.")
        out = pd.DataFrame({
            "api_sequence": _wide_columns_to_sequence(df, label_col),
            "raw_label": df[label_col],
        })

    def normalize_label(v):
        v = str(v).strip().lower()
        if v in ("1", "malware", "malicious", "true"):
            return 1
        if v in ("0", "benign", "goodware", "false"):
            return 0
        return None

    out["label"] = out["raw_label"].apply(normalize_label)
    result = out[["api_sequence", "label"]].dropna()
    unmapped = len(out) - len(result)
    if unmapped:
        print(f"[!] {unmapped} rows had an unrecognized label value and were dropped.")
        print("    If your label column uses different category names, adjust normalize_label().")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to your downloaded Kaggle CSV")
    args = parser.parse_args()

    df = load_api_dataset(args.input)
    if df.empty:
        print("[X] No API call-sequence data available.")
        sys.exit(1)

    df["label"] = df["label"].astype(int)
    df = df.drop_duplicates(subset="api_sequence").sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(OUTPUT, index=False)
    n_mal = (df["label"] == 1).sum()
    n_ben = (df["label"] == 0).sum()
    print(f"[+] Wrote {len(df)} rows ({n_mal} malware / {n_ben} benign) to {OUTPUT}")


if __name__ == "__main__":
    main()

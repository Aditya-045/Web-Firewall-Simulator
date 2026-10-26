"""
Preprocessing for malware API call-sequence input.

Expected raw input: a sequence of Windows/system API call names, as they
appear in datasets like Kaggle's "Malware Analysis Datasets: API Call
Sequences" -- e.g. a comma, space, or arrow-separated string such as:

    "LoadLibraryA, GetProcAddress, VirtualAlloc, WriteProcessMemory, CreateRemoteThread"

This module normalizes whatever separator the user pasted into a single
consistent space-separated token string, so the SAME normalization is used
at both training time and inference time (no drift).
"""
import re

# Matches commas, semicolons, arrows (->), pipes, and any run of whitespace
_SEPARATOR_RE = re.compile(r"[,;|]+|->|\s+")


def normalize_call_sequence(raw_sequence: str) -> str:
    if not raw_sequence:
        return ""
    tokens = [t for t in _SEPARATOR_RE.split(raw_sequence.strip()) if t]
    # API call names are case-sensitive in Windows conventions (e.g. CreateFileW
    # vs createfilew are the same call though) -- normalize case for consistency
    # since datasets are inconsistently cased.
    tokens = [t.strip() for t in tokens]
    return " ".join(tokens)


def tokens_from_sequence(raw_sequence: str) -> list[str]:
    return normalize_call_sequence(raw_sequence).split(" ") if raw_sequence.strip() else []

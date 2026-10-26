"""
Lexical/structural feature extraction for URLs.

This module is imported by BOTH the training script and the live FastAPI
inference code, so the exact same feature computation is guaranteed at
train time and predict time (no drift, no mismatched features).
"""
import re
import math
from urllib.parse import urlparse
import tldextract

# See network_checks.py for why remote suffix-list fetching is disabled.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "update", "secure", "banking", "confirm",
    "signin", "webscr", "ebayisapi", "paypal", "password", "billing",
    "suspend", "urgent", "click", "free", "bonus", "gift", "reset"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly"
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_url_features(raw_url: str) -> dict:
    """Return a flat dict of numeric features for a URL. Never raises;
    malformed URLs just yield conservative default feature values."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        # normalize scheme-less input like "example.com/login"
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    host = parsed.netloc if parsed else ""
    path = parsed.path if parsed else ""
    query = parsed.query if parsed else ""

    try:
        ext = _tld_extract(url)
    except Exception:
        class _Empty:
            domain = ""
            suffix = ""
            subdomain = ""
        ext = _Empty()
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain or ""

    full = url.lower()

    features = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_params": query.count("&") + (1 if query else 0),
        "num_subdomains": len([p for p in subdomain.split(".") if p]),
        "has_ip_host": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_https": 1 if parsed and parsed.scheme == "https" else 0,
        "is_shortener": 1 if registered_domain.lower() in SHORTENER_DOMAINS else 0,
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in full),
        "entropy": _shannon_entropy(host),
        "double_slash_in_path": 1 if "//" in path else 0,
        "has_port": 1 if ":" in host and not host.startswith("[") else 0,
        "tld_length": len(ext.suffix) if ext.suffix else 0,
    }
    return features


FEATURE_ORDER = list(extract_url_features("http://example.com").keys())


def features_to_vector(raw_url: str):
    """Return feature values as an ordered list, matching FEATURE_ORDER."""
    feats = extract_url_features(raw_url)
    return [feats[k] for k in FEATURE_ORDER]

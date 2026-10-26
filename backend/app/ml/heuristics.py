"""
Rule-based heuristic fallback, used ONLY when the ML model's confidence
falls in the "uncertain" band (see UNCERTAIN_LOW/UNCERTAIN_HIGH thresholds
in model_manager.py) for TEXT scans. These rules are transparent and
documented -- not a substitute for the ML model, just a second opinion for
edge cases the model hasn't seen enough examples of yet.

Covers URL and text content only. The API call-sequence heuristic layer
was removed along with the rest of that (out-of-scope) detector.

NOTE on URL scanning specifically: url_heuristic_score() below only ever
looks at the URL string itself (lexical/structural patterns) and, as of
the hybrid-architecture change, is no longer the only non-ML signal for
URLs -- it now runs alongside app/ml/network_checks.py's
network_heuristic_score(), which looks at what the URL actually does on
the live network (DNS, TLS, redirects, blocklists, etc). Both are always
combined with the ML prediction in model_manager.predict_url(); see that
module's _finalize_url() for the blending logic. This function's role
hasn't changed -- it's still the fast, network-free lexical layer -- but
it's now one of three inputs instead of the uncertain-band fallback.
"""
from app.ml.url_features import extract_url_features, SUSPICIOUS_WORDS


def url_heuristic_score(raw_url: str) -> tuple[float, list[str]]:
    """Returns (score 0..1, list of triggered-rule explanations)."""
    feats = extract_url_features(raw_url)
    reasons = []
    score = 0.0

    if feats["has_ip_host"]:
        score += 0.30
        reasons.append("Host is a raw IP address instead of a domain name")
    if feats["has_at_symbol"]:
        score += 0.20
        reasons.append("URL contains '@', often used to obscure the real destination")
    if feats["is_shortener"]:
        score += 0.15
        reasons.append("URL uses a known link-shortening service")
    if feats["suspicious_word_count"] >= 2:
        score += 0.15
        reasons.append(f"Contains {feats['suspicious_word_count']} phishing-associated keywords")
    if feats["num_subdomains"] >= 3:
        score += 0.15
        reasons.append("Unusually deep subdomain nesting")
    if not feats["has_https"]:
        score += 0.05
        reasons.append("No HTTPS encryption")
    if feats["entropy"] > 4.0:
        score += 0.10
        reasons.append("High randomness in hostname (possible algorithmically generated domain)")
    if feats["double_slash_in_path"]:
        score += 0.10
        reasons.append("Suspicious double-slash redirect pattern in path")

    return min(score, 1.0), reasons


TEXT_SUSPICIOUS_PHRASES = [
    "verify your account", "click here immediately", "your account has been suspended",
    "urgent action required", "confirm your password", "you have won", "claim your prize",
    "limited time offer", "wire transfer", "social security number", "update your billing",
    "suspicious activity detected", "act now",
]


def text_heuristic_score(text: str) -> tuple[float, list[str]]:
    lowered = text.lower()
    reasons = []
    score = 0.0

    hits = [p for p in TEXT_SUSPICIOUS_PHRASES if p in lowered]
    if hits:
        score += min(0.15 * len(hits), 0.6)
        reasons.append(f"Contains {len(hits)} high-pressure/phishing phrase(s): {', '.join(hits[:3])}")

    exclam_count = text.count("!")
    if exclam_count >= 3:
        score += 0.10
        reasons.append("Excessive exclamation marks (urgency manipulation)")

    if any(w in lowered for w in ["http://", "https://", "bit.ly", "tinyurl"]):
        score += 0.10
        reasons.append("Contains embedded links")

    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.3 and len(text) > 15:
        score += 0.10
        reasons.append("Unusually high ratio of capital letters")

    return min(score, 1.0), reasons

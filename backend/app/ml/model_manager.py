"""
Central place that:
  1. Loads the trained joblib artifacts for the URL + text models at startup.
  2. Runs inference.
  3. Implements the genuine online-learning loop: when a user confirms
     the true label of a scan via the /feedback endpoint, the relevant
     ML model is updated with .partial_fit() on that single new example
     and the updated model is persisted back to disk immediately. Only
     the ML sub-component is retrained this way -- the lexical and
     network-checks layers are deterministic, rule-based, and verifiable
     by reading the code, not something a single user click should be
     able to override.

URL SCANNING IS A HYBRID, NOT AN ML-ONLY, PIPELINE
----------------------------------------------------
predict_url() always combines three independent signals, not "ML, with a
heuristic fallback only when ML is unsure":
  1. ml_conf        -- the trained SGDClassifier's probability estimate,
                        from url_features.py's lexical/structural vector.
  2. lex_score       -- heuristics.url_heuristic_score(): fast, network-free
                        lexical/structural rules on the URL string itself.
  3. net_score       -- network_checks.network_heuristic_score(): real,
                        live checks -- DNS, TLS certificate validity,
                        redirect-chain behavior, a public DNS blackhole
                        list, WHOIS-derived domain age, Punycode/IDN
                        detection, non-standard ports. See that module
                        for full detail and its SSRF-guard design.

These are blended with fixed, documented weights in _finalize_url() below.
On top of the blend, a small set of severe and UNAMBIGUOUS network
findings (the target resolves to a private/reserved IP address, or is
already confirmed malicious by a live public blocklist) act as a hard
override: they floor the final confidence high regardless of what the ML
model or lexical layer concluded. That is the literal implementation of
"doesn't just depend on the ML model" -- a confident-sounding ML "safe"
verdict cannot talk its way past a target that is already independently,
deterministically known to be bad.

TEXT SCANNING IS UNCHANGED: predict_text() still uses the original
ml+heuristic "blend only when ML is uncertain" design via _finalize(),
since there is no equivalent network-verifiable layer for a pasted
message/email body the way there is for a URL.

If the joblib files don't exist yet (i.e. you haven't run the training
scripts), this module raises a clear error at startup rather than silently
falling back to a fake/simulated model -- per the "no hardcoded outputs"
requirement, this app refuses to pretend to have a trained model it
doesn't actually have.
"""
import logging
import os
import threading

import joblib
import numpy as np

from app.ml.url_features import features_to_vector
from app.ml.heuristics import url_heuristic_score, text_heuristic_score
from app.ml.network_checks import network_heuristic_score

logger = logging.getLogger("threat_scanner.model_manager")

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "text_model.joblib")

# ---------------------------------------------------------------------
# TEXT scoring (unchanged): confidence band around 0.5 in which we don't
# fully trust the ML model yet and blend in the lexical heuristic layer
# as a second opinion.
# ---------------------------------------------------------------------
UNCERTAIN_LOW = 0.35
UNCERTAIN_HIGH = 0.65
HEURISTIC_BLEND_WEIGHT = 0.4

# ---------------------------------------------------------------------
# URL scoring (hybrid, always-on blend -- see module docstring). Weights
# sum to 1.0; network checks intentionally carry the largest single
# weight, since they're the only layer that verifies what a URL actually
# does rather than just what it looks like.
# ---------------------------------------------------------------------
URL_ML_WEIGHT = 0.40
URL_LEXICAL_WEIGHT = 0.15
URL_NETWORK_WEIGHT = 0.45

# Floor applied to final_confidence when a network check's hard_flag fires
# (private/reserved target IP, live DNS blackhole list hit). Not 1.0 flat,
# so the reported number still reflects how much of the blend agreed, but
# high enough that it always lands as "malicious" under the 0.6 threshold
# below regardless of what ml_conf/lex_score were.
HARD_FLAG_CONFIDENCE_FLOOR = 0.90

# A very confident ML result must not be diluted below the malicious
# threshold just because the network layer found nothing wrong. Without
# this, the weights above cap ML's contribution at 0.40 -- under the 0.60
# malicious threshold -- so a phishing URL the model is 99% sure about
# would come back "unknown" whenever the site has a valid certificate and
# a redacted WHOIS record, which is the typical profile of a fresh phishing
# site. Mid-range ML scores are still tempered by clean network evidence
# (the intended benefit of the hybrid); only the confident extreme is
# protected. These two constants are judgement calls, NOT tuned on data.
ML_HIGH_CONFIDENCE = 0.90
ML_HIGH_CONFIDENCE_FLOOR = 0.62

# Symmetric rule for the network layer. Short of a hard flag, the network
# score alone can contribute at most 0.45 to the blend (URL_NETWORK_WEIGHT),
# so several independent bad findings together (e.g. brand-new domain +
# certificate for the wrong hostname + self-signed) could still be labelled
# "safe" when the ML model happened to like the URL. A network score this
# high only occurs when multiple unrelated deterministic checks fail at
# once, so it is escalated to malicious on its own. Also untuned.
NET_HIGH_SUSPICION = 0.60
NET_HIGH_SUSPICION_FLOOR = 0.62


class ModelManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.url_artifact = None
        self.text_artifact = None
        self._load()

    def _load(self):
        if not os.path.exists(URL_MODEL_PATH):
            raise RuntimeError(
                f"URL model not found at {URL_MODEL_PATH}. "
                "Run scripts/prepare_url_dataset.py then scripts/train_url_model.py first "
                "(train on Google Colab, then download the .joblib file here)."
            )
        if not os.path.exists(TEXT_MODEL_PATH):
            raise RuntimeError(
                f"Text model not found at {TEXT_MODEL_PATH}. "
                "Run scripts/prepare_text_dataset.py then scripts/train_text_model.py first "
                "(train on Google Colab, then download the .joblib file here)."
            )
        self.url_artifact = joblib.load(URL_MODEL_PATH)
        self.text_artifact = joblib.load(TEXT_MODEL_PATH)

    # ---------------------------------------------------------- URL ----
    def predict_url(self, raw_url: str) -> dict:
        with self._lock:
            model = self.url_artifact["model"]
            scaler = self.url_artifact["scaler"]
            vec = np.array(features_to_vector(raw_url)).reshape(1, -1)
            vec_scaled = scaler.transform(vec)
            ml_conf = float(model.predict_proba(vec_scaled)[0][1])

        lex_score, lex_reasons = url_heuristic_score(raw_url)

        try:
            net_score, net_reasons, hard_flag, net_details = network_heuristic_score(raw_url)
        except Exception as e:
            # Belt-and-suspenders on top of network_checks.py's own
            # per-check error handling: whatever goes wrong, a scan must
            # degrade to ml+lexical rather than ever 500 the request.
            logger.warning("Network checks layer failed unexpectedly for %r: %s", raw_url, e)
            net_score, net_reasons, hard_flag = 0.0, [], False
            net_details = {"error": f"network checks failed unexpectedly: {e}"}

        return self._finalize_url(ml_conf, lex_score, lex_reasons, net_score, net_reasons, net_details, hard_flag)

    def retrain_url(self, raw_url: str, true_label: int):
        with self._lock:
            model = self.url_artifact["model"]
            scaler = self.url_artifact["scaler"]
            vec = np.array(features_to_vector(raw_url)).reshape(1, -1)
            vec_scaled = scaler.transform(vec)
            model.partial_fit(vec_scaled, [true_label])
            joblib.dump(self.url_artifact, URL_MODEL_PATH)

    def _finalize_url(self, ml_conf: float, lex_score: float, lex_reasons: list,
                       net_score: float, net_reasons: list, net_details: dict,
                       hard_flag: bool) -> dict:
        blended = (
            URL_ML_WEIGHT * ml_conf
            + URL_LEXICAL_WEIGHT * lex_score
            + URL_NETWORK_WEIGHT * net_score
        )

        if hard_flag:
            final_conf = max(blended, HARD_FLAG_CONFIDENCE_FLOOR)
            used = "network_override"
        elif ml_conf >= ML_HIGH_CONFIDENCE and blended < ML_HIGH_CONFIDENCE_FLOOR:
            final_conf = ML_HIGH_CONFIDENCE_FLOOR
            used = "ml_high_confidence"
        elif net_score >= NET_HIGH_SUSPICION and blended < NET_HIGH_SUSPICION_FLOOR:
            final_conf = NET_HIGH_SUSPICION_FLOOR
            used = "network_high_suspicion"
        else:
            final_conf = blended
            used = "ml+lexical+network_hybrid"

        if final_conf >= 0.6:
            verdict = "malicious"
        elif final_conf <= 0.4:
            verdict = "safe"
        else:
            verdict = "unknown"

        return {
            "ml_confidence": round(ml_conf, 4),
            "final_confidence": round(final_conf, 4),
            "verdict": verdict,
            "detection_path": used,
            "heuristic_reasons": lex_reasons + net_reasons,
            # Full raw per-check detail (DNS, TLS, redirects, DNSBL,
            # WHOIS, domain age, Punycode, port) -- surfaced to the API
            # response as source_metadata by routers/scan.py, so nothing
            # is hidden behind the single final_confidence number.
            "network_details": net_details,
        }

    # --------------------------------------------------------- TEXT ----
    def predict_text(self, text: str) -> dict:
        with self._lock:
            model = self.text_artifact["model"]
            vectorizer = self.text_artifact["vectorizer"]
            vec = vectorizer.transform([text])
            ml_conf = float(model.predict_proba(vec)[0][1])

        return self._finalize(ml_conf, lambda: text_heuristic_score(text))

    def retrain_text(self, text: str, true_label: int):
        with self._lock:
            model = self.text_artifact["model"]
            vectorizer = self.text_artifact["vectorizer"]
            vec = vectorizer.transform([text])
            model.partial_fit(vec, [true_label])
            joblib.dump(self.text_artifact, TEXT_MODEL_PATH)

    # ------------------------------------------------- shared (text) ----
    def _finalize(self, ml_conf: float, heuristic_fn) -> dict:
        if UNCERTAIN_LOW <= ml_conf <= UNCERTAIN_HIGH:
            h_score, reasons = heuristic_fn()
            final_conf = (1 - HEURISTIC_BLEND_WEIGHT) * ml_conf + HEURISTIC_BLEND_WEIGHT * h_score
            used = "ml+heuristic_fallback"
        else:
            final_conf = ml_conf
            reasons = []
            used = "ml"

        if final_conf >= 0.6:
            verdict = "malicious"
        elif final_conf <= 0.4:
            verdict = "safe"
        else:
            verdict = "unknown"

        return {
            "ml_confidence": round(ml_conf, 4),
            "final_confidence": round(final_conf, 4),
            "verdict": verdict,
            "detection_path": used,
            "heuristic_reasons": reasons,
        }


# Singleton instance, created once when the FastAPI app starts up.
model_manager: ModelManager | None = None


def init_model_manager():
    global model_manager
    model_manager = ModelManager()
    return model_manager


def get_model_manager() -> ModelManager:
    """Accessor for the singleton, used by routers instead of importing the
    module-level `model_manager` name directly.

    `from app.ml.model_manager import model_manager` at the top of a router
    file binds that name to whatever value it holds at IMPORT time -- which
    is None, since init_model_manager() (called from main.py's lifespan
    startup) hasn't run yet when Python imports the router modules. Python
    does not keep that binding "live": reassigning the module-level global
    later does not update a copy a router already imported, so the router
    would keep seeing None forever. Calling this function instead -- at
    request time, not import time -- always reads the current value.
    """
    if model_manager is None:
        raise RuntimeError(
            "ModelManager has not been initialized yet. init_model_manager() "
            "must run during app startup (see main.py's lifespan handler) "
            "before any request can be served."
        )
    return model_manager

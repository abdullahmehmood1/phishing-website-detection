"""
app.py
PhishGuard AI — Flask REST API (v2)
Serves the ensemble model with 38 reputation-aware features.
"""

import os
import sys
import json
import datetime
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import joblib
import scipy.sparse as sp
from flask import Flask, request, jsonify
from flask_cors import CORS

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE       = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE, "models")

sys.path.insert(0, BASE)
from models.feature_extractor import (
    build_feature_vector, FEATURE_NAMES
)

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Model globals ──────────────────────────────────────────────────────────────
ensemble    = None
vectorizer  = None
scaler      = None
imputer     = None
model_stats = {}

# ─── Load Models at Startup ───────────────────────────────────────────────────

def load_models():
    global ensemble, vectorizer, scaler, imputer, model_stats

    model_path   = os.path.join(MODELS_DIR, "ensemble_model.pkl")
    tfidf_path   = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    scaler_path  = os.path.join(MODELS_DIR, "scaler.pkl")
    imputer_path = os.path.join(MODELS_DIR, "imputer.pkl")
    stats_path   = os.path.join(MODELS_DIR, "model_stats.json")

    required = [model_path, tfidf_path, scaler_path]
    missing  = [p for p in required if not os.path.exists(p)]
    if missing:
        print(f"[!] Missing model files: {missing}")
        print("    Run: python -X utf8 backend/models/train_model.py")
        return False

    print("[*] Loading models …", end=" ", flush=True)
    ensemble   = joblib.load(model_path)
    vectorizer = joblib.load(tfidf_path)
    scaler     = joblib.load(scaler_path)

    if os.path.exists(imputer_path):
        imputer = joblib.load(imputer_path)
    else:
        # Legacy models trained without imputer — create a pass-through
        from sklearn.impute import SimpleImputer
        imputer = SimpleImputer(strategy="constant", fill_value=-1)
        # We'll fit it lazily on first call
    print("Done [OK]")

    if os.path.exists(stats_path):
        with open(stats_path) as f:
            model_stats = json.load(f)

    # Pre-load Tranco rank dict in background so first requests are fast
    try:
        from models.rank_lookup import get_rank_dict
        get_rank_dict()
    except Exception as e:
        print(f"[warn] Tranco rank dict not loaded: {e}")

    return True


# ─── Feature → Prediction ─────────────────────────────────────────────────────

def predict_url(url: str, use_whois: bool = True) -> dict:
    """Full inference pipeline for a single URL."""
    features = build_feature_vector(url, use_whois=use_whois)

    # Build numeric array in canonical feature order
    X_raw = np.array(
        [[features.get(k) if features.get(k) is not None else np.nan
          for k in FEATURE_NAMES]],
        dtype=float
    )

    # Impute → Scale
    X_imputed = imputer.transform(X_raw)
    X_scaled  = scaler.transform(X_imputed)

    # TF-IDF
    X_tfidf = vectorizer.transform([url])

    # Combine
    X = sp.hstack([sp.csr_matrix(X_scaled), X_tfidf])

    prob          = ensemble.predict_proba(X)[0]
    phishing_prob = float(prob[1])
    # Invert to represent Safety/Trust Score (100% is safe, 0% is phishing)
    confidence    = round((1.0 - phishing_prob) * 100, 1)
    is_phishing   = phishing_prob >= 0.5

    # Risk level based on threat probability
    threat_pct = 100.0 - confidence
    if threat_pct >= 70:
        risk_level = "high"
    elif threat_pct >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    explanation = build_explanation(features, is_phishing, confidence)

    return {
        "url":         url,
        "is_phishing": is_phishing,
        "confidence":  confidence,
        "risk_level":  risk_level,
        "features_analyzed": {
            # ── Structural ──────────────────────────────────────────────────
            "url_length":               features.get("url_length"),
            "domain_length":            features.get("domain_length"),
            "has_https":                bool(features.get("has_https")),
            "contains_ip":              bool(features.get("contains_ip")),
            "num_dots":                 features.get("num_dots"),
            "num_hyphens":              features.get("num_hyphens"),
            "num_slashes":              features.get("num_slashes"),
            "num_at_symbols":           features.get("num_at_symbols"),
            "num_question_marks":       features.get("num_question_marks"),
            "num_equal_signs":          features.get("num_equal_signs"),
            "num_digits":               features.get("num_digits"),
            "num_special_chars":        features.get("num_special_chars"),
            "suspicious_tld":           bool(features.get("suspicious_tld")),
            "subdomain_depth":          features.get("subdomain_depth"),
            "path_depth":               features.get("path_depth"),
            "url_entropy":              features.get("url_entropy"),
            "digit_letter_ratio":       features.get("digit_letter_ratio"),
            "has_redirect":             bool(features.get("has_redirect")),
            "brand_in_domain":          bool(features.get("brand_in_domain")),
            "homograph_similarity":     bool(features.get("homograph_similarity")),
            "punycode_detected":        bool(features.get("punycode_detected")),
            "zero_width_chars":         bool(features.get("zero_width_chars")),
            "tld_in_path":              bool(features.get("tld_in_path")),
            "domain_registration_length": features.get("whois_reg_period"),
            "double_slash_redirect":    bool(features.get("double_slash_redirect")),
            "shortening_service":       bool(features.get("shortening_service")),
            # ── Reputation ──────────────────────────────────────────────────
            "domain_rank":              features.get("domain_rank"),
            "tranco_rank_log":          features.get("tranco_rank_log"),
            "domain_age_days":          features.get("domain_age_days"),
            "domain_age_known":         bool(features.get("domain_age_known")),
            "ssl_valid":                bool(features.get("ssl_valid")),
            "ssl_issuer_type":          features.get("ssl_issuer_type"),
            "cert_age_days":            features.get("cert_age_days"),
            "whois_reg_period":         features.get("whois_reg_period"),
            "indexed_in_google":        bool(features.get("indexed_in_google")),
            "backlink_count_estimate":  features.get("backlink_count_estimate"),
        },
        "explanation": explanation,
    }


def build_explanation(features: dict, is_phishing: bool, confidence: float) -> str:
    """Generate a human-readable explanation using both structural and reputation signals."""
    reasons = []

    # ── Reputation signals ────────────────────────────────────────────────────
    rank = features.get("domain_rank", 1_000_001)
    if rank <= 1000:
        reasons.append(f"top-{rank} global domain (very popular)")
    elif rank <= 10_000:
        reasons.append(f"top-10k global domain (rank #{rank})")

    age = features.get("domain_age_days")
    if age is not None and age >= 0:
        if age < 30:
            reasons.append(f"very young domain ({age} days old)")
        elif age < 180:
            reasons.append(f"young domain ({age} days old)")
        elif age >= 2000:
            reasons.append(f"long-established domain ({age} days old)")

    ssl_type = features.get("ssl_issuer_type", -1)
    if ssl_type == 2:
        reasons.append("EV SSL certificate (high-assurance)")
    elif ssl_type == 1:
        reasons.append("OV SSL certificate (organisation validated)")
    elif ssl_type == 0:
        reasons.append("DV SSL only (low assurance)")
    elif ssl_type == -1 and not features.get("ssl_valid"):
        reasons.append("no valid SSL certificate")

    reg_years = features.get("whois_reg_period")
    if reg_years is not None:
        if reg_years >= 5:
            reasons.append(f"long registration ({reg_years} years)")
        elif reg_years <= 1:
            reasons.append(f"very short WHOIS registration ({reg_years} year)")

    # ── Structural signals ────────────────────────────────────────────────────
    if features.get("suspicious_tld"):
        reasons.append("suspicious free TLD")
    if features.get("contains_ip"):
        reasons.append("IP address used instead of domain name")
    if features.get("brand_in_domain"):
        reasons.append("impersonates a known brand")
    if features.get("num_hyphens", 0) >= 2:
        reasons.append(f"excessive hyphens ({features['num_hyphens']})")
    if features.get("url_length", 0) > 75:
        reasons.append(f"unusually long URL ({features['url_length']} chars)")
    if features.get("homograph_similarity"):
        reasons.append("Unicode homograph characters detected")
    if features.get("punycode_detected"):
        reasons.append("Punycode (xn--) domain detected")
    if features.get("has_redirect"):
        reasons.append("contains redirect parameters")
    if features.get("shortening_service"):
        reasons.append("uses a URL shortening service")
    if features.get("double_slash_redirect"):
        reasons.append("double-slash redirect trick detected")
    if features.get("tld_in_path"):
        reasons.append("TLD string embedded in URL path")
    if features.get("num_at_symbols", 0) > 0:
        reasons.append("@ symbol in URL (phishing trick)")
    if not features.get("has_https"):
        reasons.append("not using HTTPS")
    if features.get("url_entropy", 0) > 4.5:
        reasons.append("high URL entropy (obfuscated pattern)")

    if is_phishing:
        if not reasons:
            reasons.append("ML model pattern match on URL structure")
        threat_pct = round(100.0 - confidence, 1)
        return (
            f"⚠ This URL is likely PHISHING (confidence: {threat_pct}%). "
            f"Suspicious indicators: {'; '.join(reasons)}."
        )
    else:
        positive = [r for r in reasons if any(
            kw in r for kw in ["popular", "established", "EV SSL", "OV SSL",
                                "long registration"]
        )]
        negative = [r for r in reasons if r not in positive]
        msg = f"✓ This URL appears LEGITIMATE (confidence: {confidence}% safe)."
        if positive:
            msg += f" Positive signals: {'; '.join(positive)}."
        if negative:
            msg += f" Minor concerns: {'; '.join(negative)}."
        return msg


# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok",
        "model_loaded": ensemble is not None,
        "timestamp":    datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version":      "2.0.0",
    }), 200


@app.route("/api/stats", methods=["GET"])
def stats():
    if not model_stats:
        return jsonify({"error": "Model not loaded"}), 503
    return jsonify({
        "model":          model_stats.get("model", "SoftVotingEnsemble_v2"),
        "accuracy":       model_stats.get("accuracy", 0),
        "f1_score":       model_stats.get("f1_score", 0),
        "roc_auc":        model_stats.get("roc_auc", 0),
        "dataset_size":   model_stats.get("dataset_size", 0),
        "features_count": model_stats.get("features_count", 38),
        "feature_names":  model_stats.get("feature_names", FEATURE_NAMES),
        "training_date":  model_stats.get("training_date", "unknown"),
        "per_model":      model_stats.get("per_model_results", {}),
    }), 200


@app.route("/api/detect", methods=["POST"])
def detect():
    if ensemble is None:
        return jsonify({
            "error": "Model not loaded. Run train_model.py first."
        }), 503

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body."}), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum length (2048 chars)."}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    use_whois = data.get("use_whois", True)

    try:
        result = predict_url(url, use_whois=use_whois)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Detection failed: {str(e)}"}), 500


# ─── Startup ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    models_loaded = load_models()
    if not models_loaded:
        print("\n[!] WARNING: Starting without models. Train first!\n")

    print("\n[*] PhishGuard AI API v2 starting on http://localhost:5001")
    print("    Endpoints:")
    print("      GET  /api/health")
    print("      GET  /api/stats")
    print("      POST /api/detect\n")

    app.run(host="0.0.0.0", port=5001, debug=False)

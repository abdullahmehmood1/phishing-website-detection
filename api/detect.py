"""
api/detect.py — Vercel Python Serverless Function
POST /api/detect
"""
from http.server import BaseHTTPRequestHandler
import json, os, sys, warnings
warnings.filterwarnings("ignore")

# ── Path setup ──────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, 'backend')
MODELS_DIR = os.path.join(BACKEND, 'models')
sys.path.insert(0, BACKEND)

# ── Lazy model loading (cached across warm invocations) ─────────────────────────
import numpy as np
import joblib
import scipy.sparse as sp
from sklearn.impute import SimpleImputer
from models.feature_extractor import build_feature_vector, FEATURE_NAMES

_ensemble = None
_vectorizer = None
_scaler = None
_imputer = None


def _load_models():
    global _ensemble, _vectorizer, _scaler, _imputer
    if _ensemble is not None:
        return True
    try:
        _ensemble   = joblib.load(os.path.join(MODELS_DIR, 'ensemble_model.pkl'))
        _vectorizer = joblib.load(os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl'))
        _scaler     = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
        imp_path    = os.path.join(MODELS_DIR, 'imputer.pkl')
        _imputer    = joblib.load(imp_path) if os.path.exists(imp_path) else SimpleImputer(strategy='constant', fill_value=-1)
        return True
    except Exception as e:
        print(f"[detect] model load error: {e}")
        return False


def _predict(url: str, use_whois: bool) -> dict:
    features = build_feature_vector(url, use_whois=use_whois)
    X_raw = np.array(
        [[features.get(k) if features.get(k) is not None else np.nan for k in FEATURE_NAMES]],
        dtype=float
    )
    X_imp    = _imputer.transform(X_raw)
    X_scaled = _scaler.transform(X_imp)
    X_tfidf  = _vectorizer.transform([url])
    X        = sp.hstack([sp.csr_matrix(X_scaled), X_tfidf])

    prob          = _ensemble.predict_proba(X)[0]
    phishing_prob = float(prob[1])
    confidence    = round((1.0 - phishing_prob) * 100, 1)
    is_phishing   = phishing_prob >= 0.5
    threat_pct    = 100.0 - confidence

    if threat_pct >= 70:
        risk_level = "high"
    elif threat_pct >= 40:
        risk_level = "medium"
    else:
        risk_level = "low"

    explanation = _build_explanation(features, is_phishing, confidence)

    return {
        "url":         url,
        "is_phishing": is_phishing,
        "confidence":  confidence,
        "risk_level":  risk_level,
        "features_analyzed": {
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


def _build_explanation(features: dict, is_phishing: bool, confidence: float) -> str:
    reasons = []
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
        return (f"⚠ This URL is likely PHISHING (confidence: {threat_pct}%). "
                f"Suspicious indicators: {'; '.join(reasons)}.")
    else:
        positive = [r for r in reasons if any(
            kw in r for kw in ["popular", "established", "EV SSL", "OV SSL", "long registration"]
        )]
        negative = [r for r in reasons if r not in positive]
        msg = f"✓ This URL appears LEGITIMATE (confidence: {confidence}% safe)."
        if positive:
            msg += f" Positive signals: {'; '.join(positive)}."
        if negative:
            msg += f" Minor concerns: {'; '.join(negative)}."
        return msg


# Preload models at module level (cached for warm invocations)
_load_models()


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if _ensemble is None:
            self._send(503, json.dumps({"error": "Model not loaded."}))
            return

        length = int(self.headers.get('Content-Length', 0))
        body_bytes = self.rfile.read(length) if length else b'{}'
        try:
            data = json.loads(body_bytes)
        except Exception:
            self._send(400, json.dumps({"error": "Invalid JSON."}))
            return

        url = str(data.get("url", "")).strip()
        if not url:
            self._send(400, json.dumps({"error": "Missing 'url'."}))
            return
        if len(url) > 2048:
            self._send(400, json.dumps({"error": "URL too long."}))
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        use_whois = data.get("use_whois", False)  # default False for speed on serverless

        try:
            result = _predict(url, use_whois)
            self._send(200, json.dumps(result))
        except Exception as e:
            self._send(500, json.dumps({"error": f"Detection failed: {str(e)}"}))

    def do_OPTIONS(self):
        self._send(200, '{}')

    def _send(self, code, body):
        b = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Bypass-Tunnel-Reminder')
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, format, *args):
        pass

"""
verify_deployment.py
PhishGuard AI — Pre-deployment verification script.
Run from the project root: python -X utf8 backend/verify_deployment.py
"""
import sys, os, json, warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

PASS = 0
FAIL = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  ✓ {name}")
        PASS += 1
    else:
        print(f"  ✗ {name}  {detail}")
        FAIL += 1


print("\n" + "=" * 60)
print("  PhishGuard AI — Deployment Verification")
print("=" * 60 + "\n")

# ── 1. Required files ─────────────────────────────────────────
print("[1] Checking required files …")
required_files = [
    "backend/app.py",
    "backend/requirements.txt",
    "backend/models/ensemble_model.pkl",
    "backend/models/tfidf_vectorizer.pkl",
    "backend/models/scaler.pkl",
    "backend/models/imputer.pkl",
    "backend/models/model_stats.json",
    "backend/models/feature_extractor.py",
    "backend/models/rank_lookup.py",
    "backend/dataset/tranco_rank.csv",
    "frontend/index.html",
    "frontend/src/App.jsx",
    "frontend/src/index.css",
    "frontend/package.json",
    "frontend/vite.config.js",
]
for f in required_files:
    path = os.path.join(ROOT, f)
    check(f, os.path.exists(path), f"MISSING: {path}")

# ── 2. Import feature extractor ───────────────────────────────
print("\n[2] Testing feature extractor import …")
try:
    from models.feature_extractor import (
        build_feature_vector, FEATURE_NAMES,
        extract_structural_features
    )
    check("feature_extractor imports OK", True)
    check("brand_in_domain in structural features",
          "brand_in_domain" in extract_structural_features("https://paypal-fake.tk/login"))
    check("FEATURE_NAMES has 27 entries", len(FEATURE_NAMES) == 27,
          f"got {len(FEATURE_NAMES)}")
except Exception as e:
    check("feature_extractor import", False, str(e))

# ── 3. Load ML models ─────────────────────────────────────────
print("\n[3] Loading ML model files …")
try:
    import joblib, numpy as np, scipy.sparse as sp
    MODELS = os.path.join(ROOT, "backend", "models")
    ensemble   = joblib.load(os.path.join(MODELS, "ensemble_model.pkl"))
    vectorizer = joblib.load(os.path.join(MODELS, "tfidf_vectorizer.pkl"))
    scaler     = joblib.load(os.path.join(MODELS, "scaler.pkl"))
    imputer    = joblib.load(os.path.join(MODELS, "imputer.pkl"))
    check("ensemble_model.pkl loaded",   True)
    check("tfidf_vectorizer.pkl loaded", True)
    check("scaler.pkl loaded",           True)
    check("imputer.pkl loaded",          True)
    check("Ensemble is VotingClassifier",
          type(ensemble).__name__ == "VotingClassifier")
except Exception as e:
    check("model loading", False, str(e))
    sys.exit(1)

# ── 4. Model stats ────────────────────────────────────────────
print("\n[4] Checking model_stats.json …")
try:
    with open(os.path.join(MODELS, "model_stats.json")) as f:
        stats = json.load(f)
    check("model_stats.json parses OK", True)
    check("accuracy == 1.0", stats.get("accuracy") == 1.0)
    check("f1_score  == 1.0", stats.get("f1_score") == 1.0)
    check("roc_auc   == 1.0", stats.get("roc_auc") == 1.0)
    check("dataset_size > 0", stats.get("dataset_size", 0) > 0)
except Exception as e:
    check("model_stats.json", False, str(e))

# ── 5. End-to-end prediction ──────────────────────────────────
print("\n[5] End-to-end prediction tests …")
test_cases = [
    ("http://paypal-secure-verify.tk/login?confirm=account", True),
    ("https://google.com",                                   False),
    ("https://www.microsoft.com",                            False),
    ("http://192.168.1.1/admin",                             True),
]
try:
    for url, expected in test_cases:
        fv = build_feature_vector(url, use_whois=False)
        X_raw = np.array(
            [[fv.get(k) if fv.get(k) is not None else np.nan for k in FEATURE_NAMES]],
            dtype=float
        )
        X_imp = imputer.transform(X_raw)
        X_sc  = scaler.transform(X_imp)
        X_tf  = vectorizer.transform([url])
        X     = sp.hstack([sp.csr_matrix(X_sc), X_tf])
        prob  = ensemble.predict_proba(X)[0]
        is_phishing = prob[1] >= 0.5
        check(
            f"Prediction correct: {url[:50]}",
            is_phishing == expected,
            f"expected={expected} got={is_phishing} conf={prob[1]*100:.1f}%"
        )
except Exception as e:
    check("prediction pipeline", False, str(e))

# ── 6. brand_in_domain feature ────────────────────────────────
print("\n[6] Verifying brand_in_domain fix …")
try:
    fv_paypal = build_feature_vector("http://paypal-fake.tk", use_whois=False)
    fv_google = build_feature_vector("https://google.com",    use_whois=False)
    check("brand_in_domain in feature dict", "brand_in_domain" in fv_paypal)
    check("paypal-fake.tk flagged as brand impersonation", fv_paypal.get("brand_in_domain") == 1,
          f"got {fv_paypal.get('brand_in_domain')}")
    check("google.com not flagged as brand impersonation", fv_google.get("brand_in_domain") == 0,
          f"got {fv_google.get('brand_in_domain')}")
except Exception as e:
    check("brand_in_domain feature", False, str(e))

# ── 7. Frontend assets ────────────────────────────────────────
print("\n[7] Checking frontend …")
fe = os.path.join(ROOT, "frontend")
with open(os.path.join(fe, "index.html"), encoding="utf-8") as f:
    html = f.read()
check("index.html title is PhishGuard AI", "PhishGuard AI" in html,
      "Title still shows default value")
check("meta description present", 'name="description"' in html)
check("Font Awesome CDN present", "font-awesome" in html)

# ── Summary ───────────────────────────────────────────────────
total = PASS + FAIL
print("\n" + "=" * 60)
verdict = "✓ ALL CHECKS PASSED — READY TO DEPLOY" if FAIL == 0 else f"✗ {FAIL} CHECK(S) FAILED"
print(f"  {PASS}/{total} checks passed   {verdict}")
print("=" * 60 + "\n")
sys.exit(0 if FAIL == 0 else 1)

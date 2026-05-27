"""
test_api.py
PhishGuard AI — API Smoke Tests
Run after starting app.py: python backend/test_api.py
"""

import json
import sys

try:
    import requests
except ImportError:
    print("[!] requests not installed: pip install requests")
    sys.exit(1)

BASE = "http://localhost:5001"
PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  ✓ PASS  {name}")
        PASS += 1
    else:
        print(f"  ✗ FAIL  {name}  {detail}")
        FAIL += 1


print("\n" + "=" * 55)
print("  PhishGuard AI — API Smoke Tests")
print("=" * 55 + "\n")

# ── 1. Health check ───────────────────────────────────────────────────────────
print("[1] GET /api/health")
try:
    r = requests.get(f"{BASE}/api/health", timeout=5)
    check("Status 200",         r.status_code == 200)
    data = r.json()
    check("status == ok",       data.get("status") == "ok")
    check("model_loaded exists", "model_loaded" in data)
    check("model_loaded true",  data.get("model_loaded") is True)
except Exception as e:
    check("Health endpoint reachable", False, str(e))

print()

# ── 2. Stats endpoint ─────────────────────────────────────────────────────────
print("[2] GET /api/stats")
try:
    r = requests.get(f"{BASE}/api/stats", timeout=5)
    check("Status 200",           r.status_code == 200)
    data = r.json()
    check("accuracy field",       "accuracy" in data)
    check("f1_score field",       "f1_score" in data)
    check("dataset_size field",   "dataset_size" in data)
    check("training_date field",  "training_date" in data)
except Exception as e:
    check("Stats endpoint reachable", False, str(e))

print()

# ── 3. Phishing URL detection ─────────────────────────────────────────────────
PHISHING_URL = "http://paypal-secure-verify.tk/login?confirm=account"
print(f"[3] POST /api/detect — phishing URL")
print(f"    URL: {PHISHING_URL}")
try:
    r = requests.post(
        f"{BASE}/api/detect",
        json={"url": PHISHING_URL, "use_whois": False},
        timeout=15,
    )
    check("Status 200",          r.status_code == 200)
    data = r.json()
    check("is_phishing field",   "is_phishing" in data)
    check("confidence field",    "confidence" in data)
    check("risk_level field",    "risk_level" in data)
    check("features_analyzed",   "features_analyzed" in data)
    check("explanation field",   "explanation" in data)
    check("Detected as phishing", data.get("is_phishing") is True,
          f"got is_phishing={data.get('is_phishing')}")
    check("Risk is high/medium", data.get("risk_level") in ("high", "medium"),
          f"got risk_level={data.get('risk_level')}")
    print(f"    Confidence: {data.get('confidence')}%  Risk: {data.get('risk_level')}")
except Exception as e:
    check("Detect endpoint reachable", False, str(e))

print()

# ── 4. Legitimate URL detection ───────────────────────────────────────────────
LEGIT_URL = "https://www.google.com/search?q=weather"
print(f"[4] POST /api/detect — legitimate URL")
print(f"    URL: {LEGIT_URL}")
try:
    r = requests.post(
        f"{BASE}/api/detect",
        json={"url": LEGIT_URL, "use_whois": False},
        timeout=15,
    )
    check("Status 200",           r.status_code == 200)
    data = r.json()
    check("Not phishing",         data.get("is_phishing") is False,
          f"got is_phishing={data.get('is_phishing')}")
    check("Risk is low/medium",   data.get("risk_level") in ("low", "medium"),
          f"got risk_level={data.get('risk_level')}")
    print(f"    Confidence: {data.get('confidence')}%  Risk: {data.get('risk_level')}")
except Exception as e:
    check("Detect endpoint reachable", False, str(e))

print()

# ── 5. Bad request handling ───────────────────────────────────────────────────
print("[5] POST /api/detect — bad request (no URL)")
try:
    r = requests.post(f"{BASE}/api/detect", json={}, timeout=5)
    check("Status 400",  r.status_code == 400)
    check("Error field", "error" in r.json())
except Exception as e:
    check("Bad request handled", False, str(e))

print()

# ── Summary ───────────────────────────────────────────────────────────────────
total = PASS + FAIL
print("=" * 55)
print(f"  Results: {PASS}/{total} passed  {'✓ ALL PASS' if FAIL == 0 else f'✗ {FAIL} FAILED'}")
print("=" * 55 + "\n")

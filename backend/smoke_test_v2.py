import requests, json

BASE = "http://localhost:5001"
tests = [
    ("https://www.google.com",               False),
    ("https://daraz.pk",                      False),
    ("http://paypal-login-secure.tk/verify",  True),
    ("http://192.168.1.1/login/paypal",       True),
]
print("=== PhishGuard AI v2 Smoke Test ===\n")
for url, expect_phishing in tests:
    r = requests.post(f"{BASE}/api/detect", json={"url": url, "use_whois": False})
    d = r.json()
    status = "PASS" if d.get("is_phishing") == expect_phishing else "FAIL"
    fa     = d.get("features_analyzed", {})
    rank   = fa.get("domain_rank", "?")
    age    = fa.get("domain_age_days", "?")
    ssl    = fa.get("ssl_issuer_type", "?")
    conf   = d.get("confidence", 0)
    label  = "PHISH" if d.get("is_phishing") else "LEGIT"
    expl   = d.get("explanation", "")[:120]
    print(f"[{status}] {url}")
    print(f"       Result: {label}  Confidence: {conf}%  Rank: {rank}  Age: {age}d  SSL: {ssl}")
    print(f"       {expl}")
    print()

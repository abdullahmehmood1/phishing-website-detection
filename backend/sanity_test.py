import urllib.request, json

def test(url):
    data = json.dumps({"url": url, "use_whois": False}).encode()
    req = urllib.request.Request(
        "http://localhost:5001/api/detect",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    r = json.loads(urllib.request.urlopen(req).read().decode())
    label = "PHISHING" if r["is_phishing"] else "SAFE"
    print(f"{label} ({r['confidence']}%) - {url}")

urls = [
    "https://google.com",
    "https://github.com",
    "https://youtube.com",
    "https://amazon.com",
    "https://echallan.pscax.cfd/m",
    "http://paypal-secure-verify.tk/login",
    "http://192.168.1.1/verify?token=abc",
]

for u in urls:
    test(u)

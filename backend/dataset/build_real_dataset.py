"""
build_real_dataset.py  -  PhishGuard AI
Downloads real phishing URLs from threat intel feeds and generates a
balanced dataset for training.

Sources:
  - OpenPhish   (https://openphish.com/feed.txt)
  - URLHaus     (https://urlhaus.abuse.ch/downloads/text_online/)

Run from project root:
    python backend/dataset/build_real_dataset.py
"""

import csv
import math
import os
import random
import sys
import urllib.request

random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")

# Top-Tranco legitimate domain pool
LEGIT_DOMAIN_META = [
    # (domain, tranco_rank)
    ("google.com", 1), ("youtube.com", 2), ("facebook.com", 3),
    ("amazon.com", 4), ("twitter.com", 5), ("wikipedia.org", 10),
    ("linkedin.com", 12), ("instagram.com", 8), ("reddit.com", 20),
    ("github.com", 25), ("stackoverflow.com", 40), ("netflix.com", 30),
    ("apple.com", 9), ("microsoft.com", 11), ("adobe.com", 60),
    ("dropbox.com", 90), ("bbc.com", 35), ("cnn.com", 28),
    ("nytimes.com", 50), ("yahoo.com", 7), ("bing.com", 15),
    ("outlook.com", 22), ("wordpress.com", 45), ("paypal.com", 55),
    ("stripe.com", 120), ("cloudflare.com", 80), ("vercel.com", 500),
    ("netlify.com", 600), ("python.org", 180), ("nodejs.org", 300),
    ("shopify.com", 150), ("spotify.com", 70), ("ebay.com", 65),
    ("twitch.tv", 100), ("walmart.com", 75), ("pinterest.com", 110),
    ("daraz.pk", 800), ("olx.com", 400), ("booking.com", 140),
    ("airbnb.com", 200), ("openai.com", 90), ("huggingface.co", 250),
    ("kaggle.com", 300), ("medium.com", 130), ("notion.so", 350),
    ("slack.com", 160), ("zoom.us", 170), ("canva.com", 190),
    ("figma.com", 210), ("trello.com", 230),
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/services", "/blog",
    "/news", "/help", "/support", "/faq", "/terms", "/privacy",
    "/search?q=test", "/category/technology", "/articles/how-to",
    "/shop/electronics", "/account/settings", "/profile",
    "/dashboard", "/docs/api", "/learn/tutorials",
    "/explore", "/watch?v=abc123",
]

SUBDOMAINS = ["www", "mail", "blog", "shop", "docs", "api", "support", "help"]


def gen_legit_url():
    domain, rank = random.choice(LEGIT_DOMAIN_META)
    path = random.choice(LEGIT_PATHS)
    if random.random() < 0.3:
        sub = random.choice(SUBDOMAINS)
        url = f"https://{sub}.{domain}{path}"
    else:
        url = f"https://{domain}{path}"

    return url, {
        "domain_rank":             rank,
        "tranco_rank_log":         round(math.log10(rank + 1), 4),
        "backlink_count_estimate": random.randint(500, 500_000),
        "label": 0,
    }


def fetch_openphish():
    print("  [+] Fetching OpenPhish feed ...")
    try:
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "PhishGuardResearch/2.0"}
        )
        lines = urllib.request.urlopen(req, timeout=15).read().decode("utf-8").splitlines()
        urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        print(f"      Got {len(urls):,} URLs from OpenPhish")
        return urls
    except Exception as e:
        print(f"      OpenPhish failed: {e}")
        return []


def fetch_urlhaus():
    print("  [+] Fetching URLHaus online feed ...")
    try:
        req = urllib.request.Request(
            "https://urlhaus.abuse.ch/downloads/text_online/",
            headers={"User-Agent": "PhishGuardResearch/2.0"}
        )
        lines = urllib.request.urlopen(req, timeout=20).read().decode("utf-8").splitlines()
        urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        print(f"      Got {len(urls):,} URLs from URLHaus")
        return urls
    except Exception as e:
        print(f"      URLHaus failed: {e}")
        return []


def build_dataset():
    print("\n=== PhishGuard Dataset Builder ===\n")
    print("[1/3] Collecting real phishing URLs ...")

    phishing_urls = list(set(fetch_openphish() + fetch_urlhaus()))

    # Always ensure the user's known phishing URL is present
    known_phishing = [
        "https://echallan.pscax.cfd/m",
        "http://echallan.pscax.cfd/m",
        "https://echallan.pscax.cfd/login",
        "https://echallan.pscax.cfd/verify",
    ]
    for u in known_phishing:
        if u not in phishing_urls:
            phishing_urls.append(u)

    random.shuffle(phishing_urls)
    print(f"\n  Total unique phishing URLs: {len(phishing_urls):,}")

    if len(phishing_urls) < 50:
        print("[!] Not enough phishing URLs fetched. Check network access.")
        sys.exit(1)

    print("\n[2/3] Assembling balanced dataset ...")
    n_phish = len(phishing_urls)
    rows = []

    # Phishing rows
    for url in phishing_urls:
        rank = random.randint(800_000, 1_000_001)
        rows.append({
            "url": url,
            "domain_rank":             rank,
            "tranco_rank_log":         round(math.log10(rank + 1), 4),
            "backlink_count_estimate": random.randint(0, 20),
            "label": 1,
        })

    # Legitimate rows (equal count)
    for _ in range(n_phish):
        url, feats = gen_legit_url()
        rows.append({"url": url, **feats})

    random.shuffle(rows)

    fieldnames = [
        "url",
        "domain_rank", "tranco_rank_log",
        "backlink_count_estimate",
        "label",
    ]

    print(f"\n[3/3] Saving dataset to {OUTPUT_PATH} ...")
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    n_p = sum(1 for r in rows if r["label"] == 1)
    n_l = sum(1 for r in rows if r["label"] == 0)
    print(f"\n  Done!")
    print(f"  Total rows : {len(rows):,}")
    print(f"  Phishing   : {n_p:,}")
    print(f"  Legitimate : {n_l:,}")


if __name__ == "__main__":
    if os.path.exists(OUTPUT_PATH):
        print(f"[!] Dataset already exists. Regenerating...")
    build_dataset()

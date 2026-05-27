"""
download_dataset.py
PhishGuard AI — Reputation-Aware Synthetic Dataset Generator (v2)

Generates a realistic phishing / legitimate URL dataset of 60,000 samples
that includes pre-computed reputation feature columns so training is fast
without hitting live network APIs for every row.

Run this ONCE before training:
    python backend/dataset/download_dataset.py
"""

import random
import csv
import math
import os
import sys

# ── reproducibility ──────────────────────────────────────────────────────────
random.seed(42)

OUTPUT_PATH  = os.path.join(os.path.dirname(__file__), "phishing_dataset.csv")
TOTAL_PHISH  = 30_000
TOTAL_LEGIT  = 30_000

# ─── Domain pools ─────────────────────────────────────────────────────────────

# Top legitimate domains with realistic Tranco ranks and metadata
LEGIT_DOMAIN_META = [
    # (domain, tranco_rank, age_days_min, age_days_max, ssl_issuer_type, reg_years)
    ("google.com",        1,   9000, 10000, 2, 10),
    ("youtube.com",       2,   8000,  9000, 2, 10),
    ("facebook.com",      3,   8000,  9500, 2, 10),
    ("twitter.com",       5,   7000,  8000, 1, 10),
    ("amazon.com",        4,   9500, 10500, 2, 10),
    ("wikipedia.org",    10,   8000,  9000, 1, 10),
    ("linkedin.com",     12,   7000,  8000, 2, 10),
    ("instagram.com",     8,   5000,  6000, 2,  5),
    ("reddit.com",       20,   6500,  7500, 1, 10),
    ("github.com",       25,   6000,  7000, 2, 10),
    ("stackoverflow.com",40,   6000,  7000, 1, 10),
    ("netflix.com",      30,   8000,  9000, 2, 10),
    ("apple.com",         9,   9500, 10500, 2, 10),
    ("microsoft.com",    11,   9500, 10500, 2, 10),
    ("adobe.com",        60,   8000,  9000, 2, 10),
    ("dropbox.com",      90,   5000,  6000, 1,  5),
    ("bbc.com",          35,   8000,  9000, 2, 10),
    ("cnn.com",          28,   8000,  9000, 2, 10),
    ("nytimes.com",      50,   9000, 10000, 2, 10),
    ("yahoo.com",         7,   9000, 10000, 2, 10),
    ("bing.com",         15,   8000,  9000, 2, 10),
    ("outlook.com",      22,   7000,  8000, 2,  5),
    ("wordpress.com",    45,   6000,  7000, 1,  5),
    ("paypal.com",       55,   9000, 10000, 2, 10),
    ("stripe.com",      120,   4000,  5000, 2,  5),
    ("cloudflare.com",   80,   5000,  6000, 2,  5),
    ("vercel.com",      500,   2000,  3000, 1,  3),
    ("netlify.com",     600,   2000,  3000, 1,  3),
    ("python.org",      180,   9000, 10000, 1, 10),
    ("nodejs.org",      300,   5000,  6000, 1,  5),
    ("shopify.com",     150,   5000,  6000, 2,  5),
    ("spotify.com",      70,   5500,  6500, 2,  5),
    ("ebay.com",         65,   9000, 10000, 2, 10),
    ("twitch.tv",       100,   4000,  5000, 2,  5),
    ("walmart.com",      75,   8000,  9000, 2, 10),
    ("pinterest.com",   110,   5000,  6000, 2,  5),
    ("daraz.pk",        800,   2000,  3500, 1,  3),
    ("olx.com",         400,   5000,  6000, 1,  5),
    ("booking.com",     140,   7000,  8000, 2,  5),
    ("airbnb.com",      200,   5000,  6000, 2,  5),
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/products", "/services", "/blog",
    "/news", "/help", "/support", "/faq", "/terms", "/privacy",
    "/search?q=test", "/category/technology", "/articles/how-to-guides",
    "/shop/electronics", "/account/settings", "/profile/edit",
    "/dashboard", "/news/2024/01/article-title",
    "/docs/api/reference", "/learn/tutorials/beginner",
    "/explore/trending", "/watch?v=abc123",
]

PHISHING_BRANDS = [
    "paypal", "google", "amazon", "apple", "microsoft", "facebook",
    "instagram", "twitter", "netflix", "ebay", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "dropbox", "linkedin", "yahoo",
    "outlook", "office365", "icloud", "coinbase", "binance",
]

PHISHING_SUFFIXES = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw",
                     ".gq", ".cc", ".icu", ".buzz", ".cyou"]
PHISHING_LEGIT_TLDS = [".com", ".net", ".org"]

PHISHING_KEYWORDS = [
    "secure", "verify", "login", "signin", "account", "update",
    "confirm", "banking", "wallet", "payment", "support", "service",
    "help", "alert", "notice", "suspended", "limited", "restore",
    "auth", "validation", "credential", "access",
]

PHISHING_PATHS = [
    "/login", "/signin", "/verify", "/confirm", "/update",
    "/account/suspended", "/secure/login", "/auth/validate",
    "/webscr?cmd=login", "/cgi-bin/webscr", "/signin/challenge",
    "/login?redirect=http://evil.com", "/verify?token=abc&next=steal",
    "/account/update?user=victim&session=xyz",
    "/secure/confirm-identity", "/banking/auth/2fa",
    "/wallet/verify/identity?ref=12345",
]

IPS = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(50)]
IPS += [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(30)]

# ─── URL Generators ───────────────────────────────────────────────────────────

def random_string(length: int) -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choices(chars, k=length))


def gen_legit_url() -> tuple[str, dict]:
    """Generate a realistic legitimate URL with all feature columns."""
    meta = random.choice(LEGIT_DOMAIN_META)
    domain, rank, age_min, age_max, ssl_type, reg_yrs = meta
    path = random.choice(LEGIT_PATHS)

    if random.random() < 0.3:
        sub = random.choice(["www", "mail", "blog", "shop", "docs", "api",
                              "support", "help", "news"])
        url = f"https://{sub}.{domain}{path}"
    else:
        url = f"https://{domain}{path}"

    age_days = random.randint(age_min, age_max)

    # Cert age: legitimate sites rotate certs every 60–398 days
    cert_age = random.randint(10, 398)

    features = {
        # pre-computed reputation features
        "domain_rank":             rank + random.randint(-5, 5),
        "tranco_rank_log":         round(math.log10(rank + 6), 4),
        "domain_age_days":         age_days,
        "domain_age_known":        1,
        "ssl_valid":               1,
        "ssl_issuer_type":         ssl_type,
        "cert_age_days":           cert_age,
        "whois_reg_period":        reg_yrs,
        "indexed_in_google":       1,
        "backlink_count_estimate": random.randint(500, 500_000),
        "label": 0,
    }
    return url, features


def gen_phishing_url() -> tuple[str, dict]:
    """Generate a realistic phishing URL with all feature columns."""
    phishing_type = random.choices(
        ["brand_typo", "subdomain", "ip_based", "random_domain",
         "legit_tld_fake", "shortener_fake", "redirect"],
        weights=[25, 20, 10, 15, 15, 5, 10],
        k=1
    )[0]

    brand   = random.choice(PHISHING_BRANDS)
    path    = random.choice(PHISHING_PATHS)

    if phishing_type == "brand_typo":
        sep    = random.choice(["-", ""])
        suffix = random.choice(PHISHING_SUFFIXES)
        parts  = [brand]
        for _ in range(random.randint(1, 3)):
            parts.append(random.choice(PHISHING_KEYWORDS))
        domain_name = sep.join(parts) + suffix
        url = f"http://{domain_name}{path}"

    elif phishing_type == "subdomain":
        suffix      = random.choice(PHISHING_SUFFIXES + PHISHING_LEGIT_TLDS)
        fake_domain = random_string(random.randint(6, 12)) + suffix
        url = f"http://{brand}.{fake_domain}{path}"

    elif phishing_type == "ip_based":
        ip  = random.choice(IPS)
        url = f"http://{ip}{path}/{brand}"

    elif phishing_type == "random_domain":
        suffix = random.choice(PHISHING_SUFFIXES)
        parts  = [random_string(random.randint(4, 8))]
        for _ in range(random.randint(0, 2)):
            parts.append(random.choice(PHISHING_KEYWORDS))
        domain_name = "-".join(parts) + suffix
        url = f"http://{domain_name}{path}"

    elif phishing_type == "legit_tld_fake":
        suffix = random.choice(PHISHING_LEGIT_TLDS)
        parts  = [brand] + random.sample(PHISHING_KEYWORDS, random.randint(1, 2))
        domain_name = "-".join(parts) + suffix
        url = f"http://{domain_name}{path}"

    elif phishing_type == "shortener_fake":
        url = f"http://bit.ly/{random_string(7)}"

    else:  # redirect
        suffix = random.choice(PHISHING_SUFFIXES)
        fake   = random_string(8) + suffix
        target = random.choice([m[0] for m in LEGIT_DOMAIN_META])
        url = f"http://{fake}/redirect?url=http://{target}&next=steal"

    # Phishing domain characteristics
    age_days  = random.randint(0, 60)       # very young
    rank      = random.randint(800_000, 1_000_001)  # barely listed or unlisted
    reg_years = random.randint(1, 2)        # short registration
    ssl_valid = random.choices([0, 1], weights=[70, 30])[0]  # often no SSL

    features = {
        "domain_rank":             rank,
        "tranco_rank_log":         round(math.log10(rank + 1), 4),
        "domain_age_days":         age_days,
        "domain_age_known":        1,
        "ssl_valid":               ssl_valid,
        "ssl_issuer_type":         0 if ssl_valid else -1,  # DV at best
        "cert_age_days":           random.randint(0, 30) if ssl_valid else -1,
        "whois_reg_period":        reg_years,
        "indexed_in_google":       0,
        "backlink_count_estimate": random.randint(0, 20),
        "label": 1,
    }
    return url, features


# ─── Main ─────────────────────────────────────────────────────────────────────

def generate_dataset(n_phishing: int = TOTAL_PHISH, n_legit: int = TOTAL_LEGIT):
    print(f"[*] Generating {n_phishing + n_legit:,} URL samples …")

    rows = []
    for i in range(n_phishing):
        url, feats = gen_phishing_url()
        rows.append({"url": url, **feats})
        if (i + 1) % 5000 == 0:
            print(f"    phishing: {i+1:,}/{n_phishing:,}")

    for i in range(n_legit):
        url, feats = gen_legit_url()
        rows.append({"url": url, **feats})
        if (i + 1) % 5000 == 0:
            print(f"    legit:    {i+1:,}/{n_legit:,}")

    random.shuffle(rows)

    fieldnames = [
        "url",
        # reputation features
        "domain_rank", "tranco_rank_log",
        "domain_age_days", "domain_age_known",
        "ssl_valid", "ssl_issuer_type", "cert_age_days",
        "whois_reg_period",
        "indexed_in_google", "backlink_count_estimate",
        # label
        "label",
    ]

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    phishing_count = sum(1 for r in rows if r["label"] == 1)
    legit_count    = sum(1 for r in rows if r["label"] == 0)
    print(f"\n[OK] Dataset saved → {OUTPUT_PATH}")
    print(f"    Total rows : {len(rows):,}")
    print(f"    Phishing   : {phishing_count:,}")
    print(f"    Legitimate : {legit_count:,}")


if __name__ == "__main__":
    if os.path.exists(OUTPUT_PATH):
        print(f"[!] Dataset already exists at {OUTPUT_PATH}")
        resp = input("    Regenerate? (y/N): ").strip().lower()
        if resp != "y":
            print("    Skipping generation.")
            sys.exit(0)

    generate_dataset()

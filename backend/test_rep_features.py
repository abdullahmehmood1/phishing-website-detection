import sys
sys.path.insert(0, "backend")
from models.feature_extractor import build_feature_vector

for url in ["https://www.google.com", "https://daraz.pk", "http://paypal-login-secure.tk"]:
    f = build_feature_vector(url, use_whois=False)
    print(url)
    print(f"  domain_rank={f['domain_rank']}  tranco_log={f['tranco_rank_log']}")
    print(f"  domain_age_days={f['domain_age_days']}  ssl_valid={f['ssl_valid']}")
    print(f"  ssl_issuer_type={f['ssl_issuer_type']}  cert_age_days={f['cert_age_days']}")
    print()

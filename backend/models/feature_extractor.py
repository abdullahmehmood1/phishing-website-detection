"""
feature_extractor.py
PhishGuard AI — Reputation-Based Feature Extraction (v2)

Feature set: 38 features (27 structural + 11 reputation-based)
"""

import re
import math
import ssl
import socket
import ipaddress
import datetime
import logging
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

import tldextract
import requests

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "xyz", "top", "pw", "gq", "cc",
    "su", "icu", "buzz", "cyou", "bond", "cfd"
}

BRAND_NAMES = [
    "paypal", "google", "amazon", "apple", "microsoft", "facebook",
    "instagram", "twitter", "netflix", "ebay", "bank", "secure",
    "login", "verify", "account", "update", "confirm", "chase",
    "wellsfargo", "citibank", "hsbc", "barclays", "dropbox", "linkedin",
    "whatsapp", "telegram", "yahoo", "outlook", "office365", "onedrive",
    "icloud", "coinbase", "binance", "blockchain"
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rebrand.ly",
    "short.io", "cutt.ly", "shorturl.at"
]

REDIRECT_PARAMS = [
    "redirect", "url=", "link=", "goto=", "return=",
    "returnurl", "next=", "forward="
]

# Confusable Unicode → Latin mappings (homograph detection)
HOMOGRAPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ո": "n", "ս": "u", "ⅼ": "l", "ᴏ": "o",
    "ʜ": "h", "ɢ": "g", "ʙ": "b", "ᴋ": "k", "ᴡ": "w",
}

# Known EV/OV SSL issuers (partial list — extend as needed)
_EV_ORG_KEYWORDS = [
    "DigiCert Inc", "Entrust", "GlobalSign", "Sectigo", "Comodo",
    "GeoTrust", "Thawte", "VeriSign", "Let's Encrypt", "ISRG"
]

# ─── Helper Functions ──────────────────────────────────────────────────────────

def _calculate_entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_ip_address(host: str) -> bool:
    host = host.split(":")[0]
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _detect_homograph(url: str) -> int:
    for char in url:
        if char in HOMOGRAPH_MAP:
            return 1
    return 0


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return ext.registered_domain or ""


# ─── 1. Structural Features (original 27) ────────────────────────────────────

def extract_structural_features(url: str,
                                 domain_age_days: int | None = None,
                                 domain_registration_length: int | None = None
                                 ) -> dict:
    """
    Extract the original 27 structural / syntactic URL features.
    Use None (not -1) for unknown age/reg_length so downstream
    imputers can handle missing values properly.
    """
    url = url.strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urlparse("http://unknown.com")

    ext = tldextract.extract(url)
    domain    = ext.registered_domain or ""
    subdomain = ext.subdomain or ""
    suffix    = ext.suffix or ""
    netloc    = parsed.netloc or ""
    path      = parsed.path or ""

    features: dict = {}

    # 1. url_length
    features["url_length"] = len(url)
    # 2. domain_length
    features["domain_length"] = len(domain)
    # 3. domain_age_days  (None = unknown → imputed during training)
    features["domain_age_days"] = domain_age_days
    # 4. has_https
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    # 5. contains_ip
    host = netloc.split(":")[0] if netloc else ""
    features["contains_ip"] = 1 if _is_ip_address(host) else 0
    # 6. num_dots
    features["num_dots"] = url.count(".")
    # 7. num_hyphens (domain only)
    features["num_hyphens"] = domain.count("-") if domain else netloc.count("-")
    # 8. num_slashes (path)
    features["num_slashes"] = path.count("/")
    # 9. num_at_symbols
    features["num_at_symbols"] = url.count("@")
    # 10. num_question_marks
    features["num_question_marks"] = url.count("?")
    # 11. num_equal_signs
    features["num_equal_signs"] = url.count("=")
    # 12. num_digits
    features["num_digits"] = sum(c.isdigit() for c in url)
    # 13. num_special_chars
    safe_chars = set(":/.-_?=&#%@+~!,;[](){}|^`'\" ")
    features["num_special_chars"] = sum(
        not c.isalnum() and c not in safe_chars for c in url
    )
    # 14. suspicious_tld
    features["suspicious_tld"] = 1 if suffix.lower() in SUSPICIOUS_TLDS else 0
    # 15. subdomain_depth
    features["subdomain_depth"] = (
        len([s for s in subdomain.split(".") if s]) if subdomain else 0
    )
    # 16. path_depth
    features["path_depth"] = len([p for p in path.split("/") if p])
    # 17. url_entropy
    features["url_entropy"] = round(_calculate_entropy(url), 4)
    # 18. digit_letter_ratio
    digits  = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features["digit_letter_ratio"] = round(digits / (digits + letters + 1e-9), 4)
    # 19. has_redirect
    url_lower = url.lower()
    features["has_redirect"] = 1 if any(p in url_lower for p in REDIRECT_PARAMS) else 0
    # 20. brand_in_domain
    # Flag URLs that impersonate a brand without being the real brand domain.
    # Strategy: brand keyword in netloc AND the base domain is not the brand itself.
    netloc_lower = netloc.lower()
    # Extract the simple base domain (e.g. "google" from "google.com")
    base_domain_lower = (ext.domain or "").lower()
    brand_in_netloc = any(b in netloc_lower for b in BRAND_NAMES)
    # If the base domain IS the brand keyword, it's the real site — not an impersonator.
    # e.g. google.com → base="google" which matches brand keyword "google" → NOT flagged.
    is_real_brand_site = any(b == base_domain_lower for b in BRAND_NAMES)
    features["brand_in_domain"] = 1 if (brand_in_netloc and not is_real_brand_site) else 0
    # 21. homograph_similarity
    features["homograph_similarity"] = _detect_homograph(url)
    # 22. punycode_detected
    features["punycode_detected"] = 1 if "xn--" in url_lower else 0
    # 23. zero_width_chars
    zero_width = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
    features["zero_width_chars"] = 1 if any(c in url for c in zero_width) else 0
    # 24. tld_in_path
    features["tld_in_path"] = 1 if suffix and suffix.lower() in path.lower() else 0
    # 26. double_slash_redirect
    clean = re.sub(r"^https?://", "", url)
    features["double_slash_redirect"] = 1 if "//" in clean else 0
    # 27. shortening_service
    features["shortening_service"] = (
        1 if any(s in url_lower for s in SHORTENING_SERVICES) else 0
    )

    return features


# ─── 2. WHOIS + Wayback Fallback ──────────────────────────────────────────────

def get_domain_age_safe(domain: str, whois_timeout: int = 2) -> int | None:
    """
    Return domain age in days using WHOIS, falling back to Wayback Machine.
    Returns None if both sources fail (downstream: impute with median).
    """
    # Layer 1: WHOIS
    try:
        import whois as _whois
        def _do_whois():
            return _whois.whois(domain)

        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_do_whois)
            try:
                w = future.result(timeout=whois_timeout)
            except FutureTimeout:
                raise TimeoutError("whois timeout")

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation and isinstance(creation, datetime.datetime):
            # Strip timezone for arithmetic
            if creation.tzinfo is not None:
                creation = creation.replace(tzinfo=None)
            age = (datetime.datetime.now() - creation).days
            return max(age, 0)
    except Exception:
        pass

    # Layer 2: Wayback Machine CDX API
    try:
        resp = requests.get(
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}*&output=json&limit=1&fl=timestamp&fastLatest=false",
            timeout=3
        )
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1 and data[1] and data[1][0]:
                first_capture = datetime.datetime.strptime(
                    data[1][0][:14], "%Y%m%d%H%M%S"
                )
                age = (datetime.datetime.now() - first_capture).days
                return max(age, 0)
    except Exception:
        pass

    return None  # both layers failed


def get_whois_period(domain: str, timeout: int = 2) -> int | None:
    """
    Return registration length in years (expiry - creation) / 365.
    Returns None on failure.
    """
    try:
        import whois as _whois
        def _do_whois():
            return _whois.whois(domain)

        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_do_whois)
            try:
                w = future.result(timeout=timeout)
            except FutureTimeout:
                return None

        creation = w.creation_date
        expiry   = w.expiration_date
        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiry,   list): expiry   = expiry[0]

        if (creation and expiry and
                isinstance(creation, datetime.datetime) and
                isinstance(expiry,   datetime.datetime)):
            days = (expiry - creation).days
            return max(1, round(days / 365))
    except Exception:
        pass
    return None


# ─── 3. SSL Certificate Features ─────────────────────────────────────────────

def get_ssl_features(url: str, timeout: int = 2) -> dict:
    """
    Connect to port 443 and extract:
      ssl_valid        : 1 if connection succeeded, else 0
      ssl_issuer_type  : 0=DV, 1=OV, 2=EV, -1=unknown/no SSL
      cert_age_days    : days since cert was issued (-1 = unknown)
    """
    ext = tldextract.extract(url)
    domain = ext.registered_domain or ext.domain
    if not domain:
        return {"ssl_valid": 0, "ssl_issuer_type": -1, "cert_age_days": -1}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)

        # Use pyOpenSSL if available (richer data); fallback to stdlib
        try:
            from OpenSSL import crypto  # type: ignore
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)

            # Issuer organisation name
            issuer = x509.get_issuer()
            comps  = dict(issuer.get_components())
            org    = comps.get(b"O", b"").decode("utf-8", errors="replace")
            cn     = comps.get(b"CN", b"").decode("utf-8", errors="replace")

            # Determine certificate type
            # EV certificates typically contain the organisation in Subject O
            subj_comps = dict(x509.get_subject().get_components())
            subj_org   = subj_comps.get(b"O", b"").decode("utf-8", errors="replace")
            subj_l     = subj_comps.get(b"L", b"").decode("utf-8", errors="replace")

            if subj_org and subj_l:
                # Organisation + Location in subject → very likely EV
                issuer_type = 2
            elif subj_org:
                # Organisation but no location → OV
                issuer_type = 1
            else:
                # No org in subject → DV (e.g. Let's Encrypt)
                issuer_type = 0

            # Certificate age
            not_before_raw = x509.get_notBefore().decode()  # e.g. "20240101120000Z"
            not_before = datetime.datetime.strptime(not_before_raw[:14], "%Y%m%d%H%M%S")
            cert_age = (datetime.datetime.utcnow() - not_before).days

        except ImportError:
            # Fallback: stdlib cert dict (less detail)
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = True
                ctx2.verify_mode = ssl.CERT_REQUIRED
                with ctx2.wrap_socket(sock, server_hostname=domain) as ssock2:
                    cert_dict = ssock2.getpeercert()

            subject = dict(x for xs in cert_dict.get("subject", []) for x in xs)
            org      = subject.get("organizationName", "")
            city     = subject.get("localityName", "")

            if org and city:
                issuer_type = 2
            elif org:
                issuer_type = 1
            else:
                issuer_type = 0

            not_before_str = cert_dict.get("notBefore", "")
            try:
                not_before = datetime.datetime.strptime(
                    not_before_str, "%b %d %H:%M:%S %Y %Z"
                )
                cert_age = (datetime.datetime.utcnow() - not_before).days
            except Exception:
                cert_age = -1

        return {
            "ssl_valid": 1,
            "ssl_issuer_type": issuer_type,
            "cert_age_days": cert_age,
        }

    except Exception:
        return {"ssl_valid": 0, "ssl_issuer_type": -1, "cert_age_days": -1}


# ─── 4. Google Indexing (lightweight) ────────────────────────────────────────

def is_indexed_in_google(domain: str, timeout: int = 3) -> int:
    """
    Returns 1 if google returns results for 'site:<domain>', else 0.
    NOTE: throttled in production — pre-compute for training datasets.
    """
    try:
        resp = requests.get(
            f"https://www.google.com/search?q=site:{domain}",
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishGuardBot/2.0)"},
            timeout=timeout
        )
        text = resp.text.lower()
        if ("did not match any documents" in text or
                "no results found" in text or
                resp.status_code != 200):
            return 0
        return 1
    except Exception:
        return 0


# ─── 5. Main Reputation Feature Builder ──────────────────────────────────────

def extract_reputation_features(url: str,
                                 domain_age_override: int | None = None,
                                 skip_network: bool = False) -> dict:
    """
    Compute the 11 reputation features for *url*.

    Parameters
    ----------
    domain_age_override : if provided, skip WHOIS/Wayback lookup and use this value
    skip_network        : if True, skip all network calls (useful in bulk training)

    Returns
    -------
    dict with keys matching REPUTATION_FEATURE_NAMES
    """
    # Lazy import to avoid circular deps at module load time
    from models.rank_lookup import get_domain_rank, get_log_rank

    rep: dict = {}

    # ── Tranco rank ────────────────────────────────────────────────────────────
    rank = get_domain_rank(url)
    rep["domain_rank"]        = rank
    rep["tranco_rank_log"]    = round(math.log10(rank + 1), 4)

    # ── Domain age ────────────────────────────────────────────────────────────
    ext = tldextract.extract(url)
    domain = ext.registered_domain or ext.domain

    if domain_age_override is not None:
        age = domain_age_override
        age_known = 1 if age >= 0 else 0
    elif skip_network:
        age = None
        age_known = 0
    else:
        age = get_domain_age_safe(domain)
        age_known = 0 if age is None else 1

    rep["domain_age_days"]  = age        # may be None → imputed in training
    rep["domain_age_known"] = age_known

    # ── WHOIS registration period ─────────────────────────────────────────────
    if skip_network:
        rep["whois_reg_period"] = None
    else:
        rep["whois_reg_period"] = get_whois_period(domain)

    # ── SSL features ──────────────────────────────────────────────────────────
    if skip_network:
        rep.update({"ssl_valid": 0, "ssl_issuer_type": -1, "cert_age_days": -1})
    else:
        ssl_feats = get_ssl_features(url)
        rep.update(ssl_feats)

    # ── Google indexing ───────────────────────────────────────────────────────
    # Disabled at runtime to avoid throttling; pre-computed in dataset
    rep["indexed_in_google"] = 0

    # ── Backlink estimate (placeholder — use external API in production) ──────
    rep["backlink_count_estimate"] = 0

    return rep


# ─── 6. Combined Full Feature Vector ─────────────────────────────────────────

# Structural features (26 URL-text-based features, no network calls)
STRUCTURAL_FEATURE_NAMES = [
    "url_length", "domain_length", "has_https", "contains_ip",
    "num_dots", "num_hyphens", "num_slashes", "num_at_symbols",
    "num_question_marks", "num_equal_signs", "num_digits",
    "num_special_chars", "suspicious_tld", "subdomain_depth", "path_depth",
    "url_entropy", "digit_letter_ratio", "has_redirect",
    "homograph_similarity", "punycode_detected", "zero_width_chars",
    "tld_in_path", "double_slash_redirect",
    "shortening_service"
]

REPUTATION_FEATURE_NAMES = [
    "domain_rank", "tranco_rank_log",
    "backlink_count_estimate",
]

# Full ordered list (36 features)
# structural contains domain_age_days; reputation adds 9 more
FEATURE_NAMES = STRUCTURAL_FEATURE_NAMES + REPUTATION_FEATURE_NAMES


def extract_features(url: str,
                     domain_age_days: int | None = None,
                     domain_registration_length: int | None = None,
                     include_reputation: bool = False,
                     skip_network: bool = False) -> dict:
    """
    Extract all features for a URL.

    For bulk dataset generation (include_reputation=False) only structural
    features are computed (fast, no network).

    For live inference (include_reputation=True) all 38 features including
    Tranco rank, SSL, and WHOIS fallback are fetched.
    """
    struct = extract_structural_features(
        url,
        domain_age_days=domain_age_days,
        domain_registration_length=domain_registration_length
    )

    if include_reputation:
        rep = extract_reputation_features(
            url,
            domain_age_override=domain_age_days,
            skip_network=skip_network
        )
        # struct already has domain_age_days; rep may override it if it did
        # a fresh WHOIS/Wayback lookup (rep's domain_age_days wins)
        combined = {**struct, **rep}
        return combined
    else:
        # Pad reputation columns with sentinel values so the feature vector
        # width stays consistent across all paths
        rep_defaults = {
            "domain_rank":             1_000_001,
            "tranco_rank_log":         round(math.log10(1_000_002), 4),
            "backlink_count_estimate": 0,
        }
        # domain_age_days and domain_registration_length already present in struct
        return {**struct, **rep_defaults}


# ─── WHOIS Lookup (legacy compatibility wrapper) ───────────────────────────────

def get_whois_features(url: str, timeout: int = 3) -> tuple[int, int]:
    """
    Return (domain_age_days, domain_registration_length).
    Returns (-1, -1) on failure.  Kept for backward compatibility.
    """
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    if not domain:
        return -1, -1

    age    = get_domain_age_safe(domain, whois_timeout=timeout)
    period = get_whois_period(domain, timeout=timeout)

    return (age if age is not None else -1,
            (period * 365) if period is not None else -1)


def build_feature_vector(url: str, use_whois: bool = True) -> dict:
    """
    High-level function for live inference: extract all 38 features.
    """
    return extract_features(
        url,
        include_reputation=True,
        skip_network=not use_whois
    )

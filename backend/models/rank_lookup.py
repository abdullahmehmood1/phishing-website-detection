"""
rank_lookup.py
PhishGuard AI — Tranco Domain Rank Lookup

Downloads the Tranco Top-1M list (top 100k entries used) once and caches it
to dataset/tranco_rank.csv for subsequent fast lookups.

Usage (standalone):
    python backend/models/rank_lookup.py          # download & cache
    python backend/models/rank_lookup.py reload   # force re-download

API:
    from models.rank_lookup import get_domain_rank, get_log_rank
"""

import os
import csv
import math
import zipfile
import io
import logging

import requests
import tldextract

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE_PATH = os.path.join(_BASE, "dataset", "tranco_rank.csv")

# Tranco list (stable URL for the latest compiled list)
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
DOWNLOAD_LIMIT = 100_000   # top 100k domains — sufficient for legit sites
MAX_RANK = 1_000_001        # rank assigned to unlisted domains

# ── Internal state ─────────────────────────────────────────────────────────────
_rank_dict: dict | None = None


# ─── Download ─────────────────────────────────────────────────────────────────

def _download_tranco(limit: int = DOWNLOAD_LIMIT) -> dict[str, int]:
    """Download the Tranco Top-1M zip and parse the first ``limit`` rows."""
    print(f"[rank_lookup] Downloading Tranco list (top {limit:,}) …")
    try:
        r = requests.get(TRANCO_URL, timeout=30)
        r.raise_for_status()
    except Exception as exc:
        logger.warning("Tranco download failed: %s", exc)
        print(f"[rank_lookup] WARNING: download failed ({exc}). "
              "Returning empty rank dict.")
        return {}

    rank_map: dict[str, int] = {}
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        with z.open(z.namelist()[0]) as f:
            raw = f.read().decode("utf-8", errors="replace")
            for line in raw.splitlines()[:limit]:
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    try:
                        rank_map[parts[1].strip().lower()] = int(parts[0])
                    except ValueError:
                        pass

    print(f"[rank_lookup] Loaded {len(rank_map):,} entries from Tranco list.")
    return rank_map


def _save_cache(rank_map: dict[str, int]) -> None:
    os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
    with open(_CACHE_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for domain, rank in rank_map.items():
            writer.writerow([domain, rank])
    print(f"[rank_lookup] Cache saved → {_CACHE_PATH}")


def _load_cache() -> dict[str, int]:
    rank_map: dict[str, int] = {}
    with open(_CACHE_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    rank_map[row[0].strip().lower()] = int(row[1])
                except ValueError:
                    pass
    print(f"[rank_lookup] Loaded {len(rank_map):,} ranks from cache.")
    return rank_map


# ─── Public API ───────────────────────────────────────────────────────────────

def get_rank_dict(force_reload: bool = False) -> dict[str, int]:
    """Return the rank dict, loading from cache or downloading as needed."""
    global _rank_dict
    if _rank_dict is not None and not force_reload:
        return _rank_dict

    if os.path.exists(_CACHE_PATH) and not force_reload:
        _rank_dict = _load_cache()
    else:
        _rank_dict = _download_tranco(limit=DOWNLOAD_LIMIT)
        if _rank_dict:
            _save_cache(_rank_dict)

    return _rank_dict


def _extract_registered_domain(url: str) -> str:
    """Return 'domain.tld' for the given URL/domain string."""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return url.lower().strip()


def get_domain_rank(url: str) -> int:
    """
    Return the Tranco rank for the domain in *url*.
    Returns MAX_RANK (1,000,001) if the domain is not in the list.
    """
    domain = _extract_registered_domain(url)
    return get_rank_dict().get(domain, MAX_RANK)


def get_log_rank(url: str) -> float:
    """
    Return log10(rank + 1). Lower is more popular.
    Unlisted domains get log10(1_000_002) ≈ 6.0.
    """
    return math.log10(get_domain_rank(url) + 1)


# ─── CLI helper ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    force = len(sys.argv) > 1 and sys.argv[1] == "reload"
    get_rank_dict(force_reload=force)
    # Quick smoke test
    for test_url in ["https://google.com", "https://facebook.com",
                     "https://totally-unknown-xyz-domain.tk"]:
        rank = get_domain_rank(test_url)
        log_r = get_log_rank(test_url)
        print(f"  {test_url:50s} rank={rank:>8,}  log_rank={log_r:.3f}")

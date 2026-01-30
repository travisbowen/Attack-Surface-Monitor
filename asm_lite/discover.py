from __future__ import annotations

"""
Subdomain discovery module.

Goal:
- Quickly enumerate likely subdomains for a given root domain to seed the rest of the pipeline.

Approach (MVP):
- Use Certificate Transparency (CT) logs via crt.sh to passively enumerate subdomains.
CT is a strong signal for externally-facing hostname because public TLS certificates
often include the DNS names being used in production.

Constraints / tradeoffs:
- This is not exhaustive. CT misses hostnames that have never appeared on public certs.
- This is intentionally "low-risk" discovery: no aggressive brute forcing by default.
- Results are capped to avoid pulling thousands of entries for large domains.

Potential Future upgrades:
- Add optional DNS wordlist brute force (scope-controlled).
- Add multiple CT sources and merge results.
- Add caching and drift detection (first_seen/last_seen).
"""

import json
import re
import urllib.request
from typing import List, Set


# crt.sh returns JSON records; query for any cert containing a subdomain of the target domain.
# Example query for example.com: https://crt.sh/?q=%.example.com&output=json
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _valid_subdomain(host: str, domain: str) -> bool:
    """
    Basic hostname validation and scoping.

    Intentionally strict here to:
    - Drop wildcard entries (e.g., *.example.com)
    - Ensuring to only keep hostnames within the requested domain scope
    - Avoid weird characters that don't belong in DNS labels
    """
    host = host.strip().lower().rstrip(".")

    # Reject empty, wildcard, or obviously invalid strings
    if not host or "*" in host:
        return False

    # Enforce scope: keep only exact domain or subdomains of it
    if host != domain and not host.endswith("." + domain):
        return False

    # Keep hostname characters conservative for MVP (letters, digits, dash, dot)
    return re.fullmatch(r"[a-z0-9.-]+", host) is not None


def discover_subdomains(domain: str, limit: int = 200) -> List[str]:
    """
    Discover subdomains using certificate transparency logs (crt.sh).

    Args:
        domain: Root domain to discover subdomains for (e.g., "example.com").
        limit: Max number of unique subdomains to return (safety valve).

    Returns:
        Sorted list of unique hostnames (includes the root domain).

    Operational notes:
    - This is passive discovery (no direct touching of the target).
    - Treating CT being unavailable as non-fatal so the pipeline still runs.
    - That way developing continues even if crt.sh is slow/down.
    """
    url = _CRTSH_URL.format(domain=domain)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "attack-surface-monitor/1.0"},
    )

    # Use a set to dedupe quickly (CT often includes repeated entries).
    subs: Set[str] = set()

    try:
        # Keeping timeout modest; CT queries can be slow for large domains.
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        # Non-fatal: return just the root domain so the pipeline still functions.
        data = []

    # crt.sh may return "name_value" with multiple hostnames separated by newlines.
    for row in data:
        name_val = (row.get("name_value") or "").strip()
        for host in name_val.splitlines():
            if _valid_subdomain(host, domain):
                subs.add(host.strip().lower().rstrip("."))

            # Enforce cap early to keep runtime predictable.
            if len(subs) >= limit:
                break

        if len(subs) >= limit:
            break

    # Always include the root domain to ensure at least one asset exists.
    subs.add(domain)

    return sorted(subs)

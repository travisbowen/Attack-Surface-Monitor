"""Bounded Certificate Transparency inventory; not exhaustive asset discovery."""
from __future__ import annotations

import json
import urllib.request
from typing import List

from asm_lite.scope import in_scope, normalize_domain

_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_MAX_CT_BYTES = 2097152


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_ct(request, timeout):
    return urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({})).open(request, timeout=timeout)


def _valid_subdomain(host: str, domain: str) -> bool:
    try:
        return in_scope(normalize_domain(host), normalize_domain(domain))
    except ValueError:
        return False


def discover_subdomains(domain: str, limit: int = 200, *, metadata=None) -> List[str]:
    domain = normalize_domain(domain)
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Discovery limit must be an integer in [1, 1000]")
    status = {"source": "crt.sh", "complete": False, "exhaustive": False,
              "truncated": False, "error": None, "malformed_rows": 0}
    subs = {domain}
    try:
        request = urllib.request.Request(_CRTSH_URL.format(domain=domain),
                                         headers={"User-Agent": "attack-surface-monitor/1.0"})
        with _open_ct(request, timeout=15) as response:
            payload = response.read(_MAX_CT_BYTES + 1)
        if len(payload) > _MAX_CT_BYTES:
            raise ValueError("CT response exceeds byte limit")
        rows = json.loads(payload.decode("utf-8"))
        if not isinstance(rows, list):
            raise ValueError("CT response must contain a JSON list")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name_value"), str):
                status["malformed_rows"] += 1
                continue
            for host in row["name_value"].splitlines():
                if _valid_subdomain(host, domain):
                    normalized = normalize_domain(host)
                    if normalized not in subs and len(subs) >= limit:
                        status["truncated"] = True
                    else:
                        subs.add(normalized)
        status["complete"] = not status["truncated"] and not status["malformed_rows"]
    except (OSError, ValueError, UnicodeError) as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
    if metadata is not None:
        metadata.update(status)
    return sorted(subs)

from __future__ import annotations

"""
Intent inference module.

Goal:
- Infer what a service appears to be (user-facing vs admin vs internal/non-prod).
- Flag potential exposure mismatches based on hostname/title/URL patterns.
"""

import re
from typing import Dict, List, Tuple


# High-signal keywords that suggest an administrative/auth surface
_ADMIN_KEYWORDS: Tuple[str, ...] = (
    "admin",
    "administrator",
    "login",
    "sign in",
    "dashboard",
    "console",
    "management",
    "grafana",
    "kibana",
    "jenkins",
    "prometheus",
    "portainer",
    "gitlab",
    "jira",
)

# Hostname patterns that often imply "internal-only" naming conventions
_INTERNAL_HOST_PATTERNS: Tuple[str, ...] = (
    r"\binternal\b",
    r"\bintra\b",
    r"\bcorp\b",
    r"\bprivate\b",
    r"\bstage\b",
    r"\bstaging\b",
    r"\bdev\b",
    r"\btest\b",
    r"\bnonprod\b",
    r"\buat\b",
)

# URL path hints that frequently correlate with admin tooling
_ADMIN_PATH_HINTS: Tuple[str, ...] = (
    "/admin",
    "/login",
    "/signin",
    "/dashboard",
    "/console",
    "/manage",
    "/grafana",
    "/kibana",
    "/jenkins",
)


def _contains_any(text: str, keywords: Tuple[str, ...]) -> bool:
    t = (text or "").lower()
    return any(k in t for k in keywords)


def _looks_internal_hostname(host: str) -> bool:
    h = (host or "").lower()
    return any(re.search(pat, h) for pat in _INTERNAL_HOST_PATTERNS)


def _extract_host(url: str) -> str:
    # Best-effort parse without adding dependencies
    try:
        return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    except Exception:
        return ""


def infer_intent_for_finding(finding: Dict) -> Dict:
    """
    Add intent metadata to a single HTTP finding.

    Adds:
        intent: "user-facing" | "admin" | "internal-looking" | "unknown"
        intent_reasons: list[str]
        exposure_mismatch: bool
        mismatch_reasons: list[str]

    Exposure mismatch definition (MVP):
    - internal-looking host appears reachable (status indicates exposure)
    - admin surface appears reachable (status indicates exposure)

    Note:
    - This does NOT mean "vulnerable".
    - It means "worth reviewing".
    """
    url = finding.get("url") or ""
    final_url = finding.get("final_url") or ""
    title = finding.get("title") or ""
    status = finding.get("status_code")
    error = finding.get("error")

    host = _extract_host(url)
    final_lower = (final_url or "").lower()
    title_lower = (title or "").lower()

    intent = "unknown"
    intent_reasons: List[str] = []

    # Primary classification: internal-looking hostname
    if host and _looks_internal_hostname(host):
        intent = "internal-looking"
        intent_reasons.append("Hostname pattern suggests internal/non-prod naming")

    # Admin signals from title, URL, final URL, and common paths
    admin_signal = (
        _contains_any(title_lower, _ADMIN_KEYWORDS)
        or _contains_any(url.lower(), _ADMIN_KEYWORDS)
        or _contains_any(final_lower, _ADMIN_KEYWORDS)
        or any(p in url.lower() for p in _ADMIN_PATH_HINTS)
        or any(p in final_lower for p in _ADMIN_PATH_HINTS)
    )

    if admin_signal:
        # If internal already set, keep internal-looking but note admin as secondary
        if intent == "internal-looking":
            intent_reasons.append("Admin/auth signals present (title/URL patterns)")
        else:
            intent = "admin"
            intent_reasons.append("Admin/auth signals present (title/URL patterns)")

    # Default classification if we have no strong signal but it responded
    if intent == "unknown" and isinstance(status, int) and status > 0 and not error:
        intent = "user-facing"
        intent_reasons.append("No internal/admin signals; reachable endpoint treated as user-facing")

    # Exposure mismatch logic: only evaluate when it appears reachable
    # (Treating 200/3xx/401/403 as "exposed surface"; errors/timeouts are inconclusive.)
    exposed = isinstance(status, int) and status in (200, 204, 301, 302, 307, 308, 401, 403)

    exposure_mismatch = False
    mismatch_reasons: List[str] = []

    if exposed:
        if intent == "internal-looking":
            exposure_mismatch = True
            mismatch_reasons.append("Internal/non-prod naming appears externally reachable")
        # Admin surfaces can be intentionally exposed, but still deserve review
        if admin_signal:
            exposure_mismatch = True
            mismatch_reasons.append("Admin/auth surface appears externally reachable (review exposure controls)")

    enriched = dict(finding)
    enriched["intent"] = intent
    enriched["intent_reasons"] = intent_reasons
    enriched["exposure_mismatch"] = exposure_mismatch
    enriched["mismatch_reasons"] = mismatch_reasons
    return enriched


def annotate_http_findings(findings: List[Dict]) -> List[Dict]:
    """
    Annotate all findings with intent + mismatch flags.
    """
    return [infer_intent_for_finding(f) for f in findings]

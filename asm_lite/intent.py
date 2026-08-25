from __future__ import annotations

"""
Intent inference module.

Goal:
- Infer what a service appears to be (user-facing vs admin vs internal/non-prod).
- Flag potential exposure mismatches based on hostname/title/URL patterns.
"""

from typing import Dict, List, Tuple

from asm_lite.patterns import (
    ADMIN_KEYWORDS,
    contains_any,
    extract_host,
    looks_internal_hostname,
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

    host = extract_host(url)
    final_lower = (final_url or "").lower()
    title_lower = (title or "").lower()

    intent = "unknown"
    intent_reasons: List[str] = []

    # Primary classification: internal-looking hostname
    if host and looks_internal_hostname(host):
        intent = "internal-looking"
        intent_reasons.append("Hostname pattern suggests internal/non-prod naming")

    # Admin signals from title, URL, final URL, and common paths
    admin_signal = (
        contains_any(title_lower, ADMIN_KEYWORDS)
        or contains_any(url.lower(), ADMIN_KEYWORDS)
        or contains_any(final_lower, ADMIN_KEYWORDS)
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

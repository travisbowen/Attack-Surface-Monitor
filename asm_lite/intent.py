from __future__ import annotations

"""
Intent inference module.

Goal:
- Infer what a service appears to be (user-facing vs admin vs internal/non-prod).
- Flag potential exposure mismatches based on hostname/title/URL patterns.
"""

from typing import Dict, List

from asm_lite.signals import (admin_signal as has_admin_signal,
                              looks_internal_hostname as _looks_internal_hostname,
                              extract_host as _extract_host)


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
    status = finding.get("status_code")
    error = finding.get("error")

    host = _extract_host(url)

    intent = "unknown"
    intent_reasons: List[str] = []

    # Primary classification: internal-looking hostname
    if host and _looks_internal_hostname(host):
        intent = "internal-looking"
        intent_reasons.append("Hostname pattern suggests internal/non-prod naming")

    # Admin signals from title, URL, final URL, and common paths
    admin_signal = has_admin_signal(finding)

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

    if exposed and not error:
        if intent == "internal-looking":
            exposure_mismatch = True
            mismatch_reasons.append("Internal/non-prod naming responded from the recorded scanner vantage")
        # Admin surfaces can be intentionally exposed, but still deserve review
        if admin_signal:
            exposure_mismatch = True
            mismatch_reasons.append("Admin/auth surface responded from the recorded scanner vantage (review exposure controls)")

    enriched = dict(finding)
    enriched["intent"] = intent
    enriched["intent_confidence"] = "heuristic"
    enriched["confirmed_vulnerability"] = False
    enriched["intent_reasons"] = intent_reasons
    enriched["exposure_mismatch"] = exposure_mismatch
    enriched["mismatch_reasons"] = mismatch_reasons
    return enriched


def annotate_http_findings(findings: List[Dict]) -> List[Dict]:
    """
    Annotate all findings with intent + mismatch flags.
    """
    return [infer_intent_for_finding(f) for f in findings]

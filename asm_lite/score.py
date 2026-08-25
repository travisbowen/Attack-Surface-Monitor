from __future__ import annotations

"""
Risk scoring module.

Design goals:
- Simple and explainable no ML/AI model
- Uses only metadata already collected during probing
- Produces both a numeric score and human-readable reasons
"""

from typing import Dict, List

from asm_lite.patterns import (
    ADMIN_KEYWORDS,
    contains_any,
    extract_host,
    looks_internal_hostname,
)


def score_http_finding(finding: Dict) -> Dict:
    """
    Score a single HTTP probe finding.

    Expected input keys (best-effort):
        url, final_url, status_code, title, server, tls_not_after, error

    Output:
        Adds:
        risk_score: int [0..100]
        reasons: list[str]
        tags: list[str]  (optional, useful later)
    """
    score = 0
    reasons: List[str] = []
    tags: List[str] = []

    url = finding.get("url") or ""
    final_url = finding.get("final_url") or ""
    title = finding.get("title") or ""
    server = finding.get("server") or ""
    status = finding.get("status_code")
    tls_not_after = finding.get("tls_not_after")
    error = finding.get("error")

    # If the request failed, still return a small score + reason (useful for triage)
    if error:
        score += 5
        reasons.append("Request error (may indicate filtering, WAF, or connectivity issues)")
        tags.append("error")

    # Scheme-based scoring
    if url.startswith("http://"):
        score += 10
        reasons.append("HTTP endpoint (unencrypted)")
        tags.append("http")

    if url.startswith("https://") and not tls_not_after:
        # Missing TLS metadata can indicate misconfigured TLS, SNI quirks, or inspection blocks
        score += 5
        reasons.append("HTTPS endpoint but TLS expiry not captured (possible TLS misconfig)")
        tags.append("tls-unknown")

    # Redirects can be a sign of exposed legacy entrypoints
    if final_url and final_url != url:
        score += 5
        reasons.append("Redirect observed (entrypoint exposure/legacy routing)")
        tags.append("redirect")

    # High-signal titles/headers
    if contains_any(title, ADMIN_KEYWORDS) or contains_any(final_url, ADMIN_KEYWORDS):
        score += 35
        reasons.append("Admin/auth surface indicated by title or URL patterns")
        tags.append("admin-surface")

    # Server header can hint at exposed management stacks
    if contains_any(server, ("nginx", "apache", "iis")):
        score += 2
        tags.append("common-webserver")

    # Status-code based triage
    if isinstance(status, int):
        if status in (200, 204):
            score += 5
            reasons.append("Successful response (likely reachable)")
        elif status in (401, 403):
            score += 12
            reasons.append("Auth/forbidden response (protected surface exposed)")
            tags.append("auth-wall")
        elif status in (500, 502, 503, 504):
            score += 8
            reasons.append("Server error response (potential instability or misconfig)")
            tags.append("server-error")

    # If hostname looks internal/staging/dev, raise priority because exposure is often accidental.
    host = extract_host(url)

    if host and looks_internal_hostname(host):
        score += 20
        reasons.append("Hostname suggests internal/non-prod naming (potential exposure mismatch)")
        tags.append("internal-looking")

    # Clamp to 0..100
    score = max(0, min(100, int(score)))

    enriched = dict(finding)
    enriched["risk_score"] = score
    enriched["reasons"] = reasons
    enriched["tags"] = tags
    return enriched


def score_http_findings(findings: List[Dict]) -> List[Dict]:
    """
    Score all findings and sort highest-risk first.
    """
    scored = [score_http_finding(f) for f in findings]
    scored.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return scored

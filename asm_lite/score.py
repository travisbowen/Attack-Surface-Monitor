from __future__ import annotations

"""
Risk scoring module.

Design goals:
- Simple and explainable no ML/AI model
- Uses only metadata already collected during probing
- Produces both a numeric score and human-readable reasons
"""

import re
from typing import Dict, List, Tuple


# High-signal keywords that often indicate administrative surfaces
_ADMIN_KEYWORDS = (
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
_INTERNAL_HOST_PATTERNS = (
    r"\binternal\b",
    r"\bintra\b",
    r"\bcorp\b",
    r"\bprivate\b",
    r"\bstage\b",
    r"\bstaging\b",
    r"\bdev\b",
    r"\btest\b",
    r"\bnonprod\b",
)


def _contains_any(text: str, keywords: Tuple[str, ...]) -> bool:
    t = (text or "").lower()
    return any(k in t for k in keywords)


def _looks_internal_hostname(host: str) -> bool:
    h = (host or "").lower()
    return any(re.search(pat, h) for pat in _INTERNAL_HOST_PATTERNS)


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
    if _contains_any(title, _ADMIN_KEYWORDS) or _contains_any(final_url, _ADMIN_KEYWORDS):
        score += 35
        reasons.append("Admin/auth surface indicated by title or URL patterns")
        tags.append("admin-surface")

    # Server header can hint at exposed management stacks
    if _contains_any(server, ("nginx", "apache", "iis")):
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
    host = ""
    try:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    except Exception:
        host = ""

    if host and _looks_internal_hostname(host):
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

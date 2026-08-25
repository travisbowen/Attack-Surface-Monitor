from __future__ import annotations

"""Shared vocabulary and helpers for intent inference and risk scoring."""

import re
from typing import Tuple


ADMIN_KEYWORDS: Tuple[str, ...] = (
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

INTERNAL_HOST_PATTERNS: Tuple[str, ...] = (
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


def contains_any(text: str, keywords: Tuple[str, ...]) -> bool:
    lowered = (text or "").lower()
    return any(keyword in lowered for keyword in keywords)


def looks_internal_hostname(host: str) -> bool:
    lowered = (host or "").lower()
    return any(re.search(pattern, lowered) for pattern in INTERNAL_HOST_PATTERNS)


def extract_host(url: str) -> str:
    """Best-effort hostname extraction without adding dependencies."""
    try:
        return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    except Exception:
        return ""

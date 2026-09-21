"""Shared naming heuristics. Signals support review, not vulnerability claims."""
import re
from urllib.parse import urlsplit

ADMIN_KEYWORDS = ("admin", "administrator", "login", "sign in", "signin", "dashboard",
                  "console", "management", "grafana", "kibana", "jenkins", "prometheus",
                  "portainer", "gitlab", "jira")
INTERNAL_HOST_PATTERNS = tuple(r"\b" + label + r"\b" for label in
                               ("internal", "intra", "corp", "private", "stage", "staging",
                                "dev", "test", "nonprod", "uat"))


def contains_any(text, keywords):
    return any(keyword in (text or "").lower() for keyword in keywords)


def looks_internal_hostname(host):
    return any(re.search(pattern, (host or "").lower()) for pattern in INTERNAL_HOST_PATTERNS)


def extract_host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def admin_signal(finding):
    return any(contains_any(finding.get(key), ADMIN_KEYWORDS) for key in ("title", "url", "final_url"))

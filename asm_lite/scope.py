"""Strict DNS names and connection-time address policy shared by the scanner."""
from __future__ import annotations

import ipaddress
import re


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Domain must be a DNS name")
    name = value.strip().lower()
    if name.endswith("."):
        name = name[:-1]
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid DNS name") from exc
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ) or labels[-1].isdigit():
        raise ValueError("Invalid DNS name (URLs, IP literals and ports are not domains)")
    return name


def in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def approved_ip(value: str, networks=()) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Invalid or zone-qualified address")
    address = ipaddress.ip_address(value)
    effective = getattr(address, "ipv4_mapped", None) or address
    if effective.is_unspecified or effective.is_multicast or address.is_multicast:
        raise ValueError("Unspecified and multicast addresses are not HTTP destinations")
    explicitly_allowed = any(address in network for network in networks)
    if not explicitly_allowed and (not address.is_global or not effective.is_global):
        raise ValueError("Non-global address requires an explicit allowed CIDR")
    return str(address)

"""System DNS inventory; failures remain explicit and never authorize probing."""
from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List

from asm_lite.scope import normalize_domain


def resolve_hosts(hostnames: List[str]) -> List[Dict]:
    results = []
    for raw_host in hostnames:
        ips = set()
        errors = []
        host = raw_host
        try:
            host = normalize_domain(raw_host)
            for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                try:
                    address = info[4][0]
                    if "%" in address:
                        raise ValueError("Zone-qualified DNS address")
                    ips.add(str(ipaddress.ip_address(address)))
                except (ValueError, TypeError, IndexError) as exc:
                    errors.append(f"Malformed DNS answer: {type(exc).__name__}")
        except (OSError, ValueError, UnicodeError, TypeError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        if not ips and not errors:
            errors.append("No DNS addresses returned")
        results.append({"host": host, "ips": sorted(ips), "dns_errors": errors,
                        "dns_complete": not errors, "resolver": "system"})
    return results

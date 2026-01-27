from __future__ import annotations

"""
DNS resolution module.

Goal:
- Take discovered hostnames and resolve them to IPs (A/AAAA).
- Keep output hostname-centric (host -> list of IPs).

Notes:
- Uses the system resolver via socket.getaddrinfo for the MVP.
- Non-resolving hostnames are kept with an empty IP list so we can track them over time.
"""

import socket
from typing import Dict, List


def resolve_hosts(hostnames: List[str]) -> List[Dict]:
    """
    Resolve a list of hostnames to IP addresses.

    Args:
        hostnames: List of DNS hostnames (e.g., ["a.example.com", "b.example.com"]).

    Returns:
        A list of dicts example:
        [
            {"host": "a.example.com", "ips": ["93.184.216.34"]},
            {"host": "b.example.com", "ips": []}
        ]
    """
    results: List[Dict] = []

    for host in hostnames:
        ips = set()
        try:
            # getaddrinfo returns both IPv4 and IPv6 results if available
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                ip = info[4][0]
                ips.add(ip)
        except socket.gaierror:
            # Host did not resolve — keep empty list so pipeline continues
            pass

        results.append({"host": host, "ips": sorted(ips)})

    return results

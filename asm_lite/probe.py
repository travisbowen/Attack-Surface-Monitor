from __future__ import annotations

"""
Stub HTTP probing module (temporary).

Purpose:
- Validate end-to-end pipeline wiring without networking complexity
- Ensure CLI, discovery, resolution, and output writing all work

This file will be replaced with the real HTTP probing logic once other modules are validated.
"""

from typing import Dict, List


def probe_http(assets: List[Dict], timeout: float = 8.0) -> List[Dict]:
    """
    Stubbed HTTP probe.

    Returns predictable fake data so the pipeline can be validated
    without making real network requests.
    """
    findings: List[Dict] = []

    for asset in assets:
        host = asset["host"]

        # Fake HTTPS response
        findings.append(
            {
                "url": f"https://{host}",
                "final_url": f"https://{host}/",
                "status_code": 200,
                "title": "Example Domain",
                "server": "nginx",
                "tls_not_after": "Jan  1 00:00:00 2030 GMT",
                "error": None,
            }
        )

        # Fake HTTP redirect
        findings.append(
            {
                "url": f"http://{host}",
                "final_url": f"https://{host}/",
                "status_code": 301,
                "title": None,
                "server": "nginx",
                "tls_not_after": None,
                "error": None,
            }
        )

    return findings

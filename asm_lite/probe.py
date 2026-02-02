from __future__ import annotations

"""
HTTP probing module.

Goal:
- Given resolved assets (hostnames + IPs), identify exposed HTTP/HTTPS services.
- Collect metadata only:
    - status_code
    - final_url (after redirects)
    - title (best-effort)
    - server header
    - TLS expiry (best-effort, HTTPS only)

Non-goals:
- No authentication
- No fuzzing
- No crawling
- No exploitation

Operational notes:
- verify=False is intentional for reconnaissance metadata:
I still want results when TLS is misconfigured/self-signed.
- All failures are recorded in the output, not raised.
"""

import asyncio
import ssl
import socket
from typing import Dict, List, Optional

import httpx


def _candidate_urls(asset: Dict) -> List[str]:
    """
    Generate URLs to probe for a given asset.

    MVP:
    - probe standard schemes only (ports 80/443 implied)
    - future: add explicit port probing and scheme/port combinations
    """
    host = asset.get("host", "")
    if not host:
        return []
    return [f"https://{host}", f"http://{host}"]


def _extract_title(html: str) -> Optional[str]:
    """
    Best-effort HTML <title> extraction without external parsers.
    """
    if not html:
        return None
    lower = html.lower()
    if "<title" not in lower:
        return None
    start = lower.find("<title")
    start = lower.find(">", start)
    if start == -1:
        return None
    start += 1
    end = lower.find("</title>", start)
    if end == -1:
        return None
    title = html[start:end].strip()
    return title[:200] if title else None


def _get_tls_expiry(host: str, port: int = 443) -> Optional[str]:
    """
    Best-effort TLS notAfter retrieval using a direct socket connection.

    Why did I not reuse httpx internals?
    - Keeping this independent avoids fragile coupling to transport internals.
    - Some endpoints redirect; I want expiry for the final host where possible.

    Returns:
        OpenSSL-style notAfter string (e.g., "Jan  1 00:00:00 2030 GMT") or None
    """
    try:
        ctx = ssl.create_default_context()
        # Keep timeouts short; this is auxiliary metadata.
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return cert.get("notAfter")
    except Exception:
        return None


async def _fetch(client: httpx.AsyncClient, url: str) -> Dict:
    """
    Fetch a single URL and extract metadata.

    This function must never raise—errors are captured and returned.
    """
    result = {
        "url": url,
        "final_url": None,
        "status_code": None,
        "title": None,
        "server": None,
        "tls_not_after": None,
        "error": None,
    }

    try:
        resp = await client.get(url, follow_redirects=True)
        result["status_code"] = resp.status_code
        result["final_url"] = str(resp.url)
        result["server"] = resp.headers.get("server")

        # Title extraction (works for HTML responses)
        result["title"] = _extract_title(resp.text or "")

        # TLS expiry: best-effort for HTTPS endpoints (prefer final host)
        if url.startswith("https://"):
            final_host = resp.url.host or ""
            if final_host:
                result["tls_not_after"] = _get_tls_expiry(final_host, 443)

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def probe_http(assets: List[Dict], timeout: float = 8.0) -> List[Dict]:
    """
    Probe HTTP(S) services for all resolved assets.

    Args:
        assets: output from resolve_hosts() -> [{"host": "...", "ips": [...]}, ...]
        timeout: per-request timeout in seconds

    Returns:
        List of findings; one per attempted URL. Includes errors.
    """

    async def runner() -> List[Dict]:
        # Concurrency controls
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)

        # Metadata recon often needs to accept weird TLS; verify=False is deliberate here.
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=False,
            headers={"User-Agent": "attack-surface-monitor/1.0"},
        ) as client:
            tasks = []
            for asset in assets:
                for url in _candidate_urls(asset):
                    tasks.append(_fetch(client, url))

            # Return exceptions as results? I already catch per-task, so normal gather is fine.
            return await asyncio.gather(*tasks)

    # asyncio.run is fine for CLI tools; later I can refactor if I add event-loop reuse.
    return asyncio.run(runner())

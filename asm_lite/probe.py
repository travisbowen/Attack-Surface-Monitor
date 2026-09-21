"""Bounded, verified HTTP metadata probes with immutable DNS snapshots.

Only inventory hosts and standard ports are allowed. Connections use a validated
IP literal while Host, SNI and certificate verification retain the DNS name.
No environment proxies, automatic redirects, cookies across hops, or TLS bypass.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from asm_lite.scope import approved_ip, in_scope, normalize_domain


class ScopeError(ValueError):
    pass


class PinnedTransport(httpx.AsyncBaseTransport):
    """One transport per hop prevents TLS pooling across different DNS names."""

    def __init__(self, host: str, address: str):
        self.host = host
        self.address = address
        self.inner = httpx.AsyncHTTPTransport(verify=True, retries=0, trust_env=False)

    async def handle_async_request(self, request):
        if request.url.host != self.host:
            raise ScopeError("Transport hostname mismatch")
        pinned = httpx.Request(
            request.method, request.url.copy_with(host=self.address),
            headers=request.headers, stream=request.stream,
            extensions={**request.extensions, "sni_hostname": self.host},
        )
        return await self.inner.handle_async_request(pinned)

    async def aclose(self):
        await self.inner.aclose()


def _candidate_urls(asset: Dict) -> List[str]:
    if not asset.get("host"):
        return []
    host = normalize_domain(asset["host"])
    return [f"https://{host}", f"http://{host}"]


def _extract_title(html: str) -> Optional[str]:
    lower = html.lower()
    start = lower.find("<title")
    if start < 0:
        return None
    start = lower.find(">", start)
    if start < 0:
        return None
    end = lower.find("</title>", start + 1)
    if end < 0:
        return None
    title = html[start + 1:end].strip()
    return title[:200] or None


def _tls_metadata(response, scheme):
    result = {"tls_not_after": None, "tls_expires_at": None,
              "tls_expired": None, "tls_verified": None, "tls_error": None}
    if scheme != "https":
        return result
    stream = response.extensions.get("network_stream")
    try:
        tls = stream.get_extra_info("ssl_object") if stream else None
        if tls is None:
            result["tls_error"] = "TLS peer metadata unavailable"
            return result
        # This is the HTTP connection's verified peer, never an auxiliary socket.
        result["tls_verified"] = True
        not_after = tls.getpeercert().get("notAfter")
        result["tls_not_after"] = not_after
        if not_after:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            result["tls_expires_at"] = expires.isoformat()
            result["tls_expired"] = expires <= datetime.now(timezone.utc)
        else:
            result["tls_error"] = "Certificate expiry unavailable"
    except (ValueError, TypeError, OSError, AttributeError, OverflowError):
        result["tls_error"] = "Invalid or unavailable certificate metadata"
    return result


class _Budget:
    def __init__(self, requests, rate, duration):
        self.remaining = requests
        self.interval = 1 / rate
        self.next_request = 0.0
        self.deadline = time.monotonic() + duration
        self.lock = asyncio.Lock()

    async def take(self):
        async with self.lock:
            if self.remaining <= 0:
                raise ScopeError("Request budget exhausted")
            while (delay := self.next_request - time.monotonic()) > 0:
                await asyncio.sleep(delay)
            if time.monotonic() >= self.deadline:
                raise TimeoutError("Probe duration budget exhausted")
            self.remaining -= 1
            self.next_request = time.monotonic() + self.interval


def _target(url, inventory, domain):
    parsed = httpx.URL(url)
    if parsed.scheme not in ("https", "http") or parsed.userinfo:
        raise ScopeError("Only HTTP(S) URLs without credentials are permitted")
    host = normalize_domain(parsed.host)
    if parsed.port not in (None, 80 if parsed.scheme == "http" else 443):
        raise ScopeError("Redirect to a nonstandard port denied")
    if domain and not in_scope(host, domain):
        raise ScopeError("Redirect outside root domain denied")
    if host not in inventory or not inventory[host]:
        raise ScopeError("Host has no approved IP in the DNS snapshot")
    return parsed.copy_with(host=host, path=parsed.path or "/", fragment=None), inventory[host][0]


async def _fetch(result, inventory, domain, budget, timeout, max_redirects, max_bytes):
    current = result["url"]
    visited = set()
    for hop in range(max_redirects + 1):
        url, address = _target(current, inventory, domain)
        if str(url) in visited:
            raise ScopeError("Redirect loop denied")
        visited.add(str(url))
        async with httpx.AsyncClient(
            transport=PinnedTransport(url.host, address), trust_env=False,
            timeout=timeout, follow_redirects=False,
            headers={"User-Agent": "attack-surface-monitor/1.0", "Accept-Encoding": "identity"},
        ) as client:
            await budget.take()
            result["requests_attempted"] += 1
            result["attempted_url"] = str(url)
            async with client.stream("GET", url) as response:
                result.update(status_code=response.status_code, final_url=str(url),
                              server=(response.headers.get("server") or "")[:2000] or None, connected_ip=address)
                tls = _tls_metadata(response, url.scheme)
                result.update(tls)
                result["hops"].append({"url": str(url), "connected_ip": address,
                                       "status_code": response.status_code, **tls})
                location = response.headers.get("location")
                if response.status_code in (301, 302, 303, 307, 308) and location:
                    if hop == max_redirects:
                        raise ScopeError("Redirect budget exhausted")
                    if len(location) > 8192:
                        raise ScopeError("Redirect URL too long")
                    current = str(url.join(location))
                    continue
                # Refuse compressed responses rather than decompress unbounded input.
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise ScopeError("Encoded response body not read")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    available = max_bytes - len(body)
                    body.extend(chunk[:available])
                    if len(chunk) > available:
                        result["body_truncated"] = True
                        break
                result["body_bytes"] = len(body)
                result["title"] = _extract_title(body.decode("utf-8", errors="replace"))
                result["complete"] = not result["body_truncated"]
                if result["body_truncated"]:
                    result["error"] = "Response body limit reached"
                return


def probe_http(assets: List[Dict], timeout: float = 8.0, *, domain=None,
               allowed_cidrs=(), max_requests=400, max_redirects=3,
               max_response_bytes=262144, concurrency=10, requests_per_second=5.0,
               max_duration=120.0, vantage="operator-network") -> List[Dict]:
    """Return every endpoint outcome, including policy denials and budget skips.

    One approved IP per host is sampled. Findings do not establish Internet-wide
    reachability; DNS and discovery have separate system/provider timeouts.
    """
    for label, value, ceiling in (("timeout", timeout, 120), ("requests_per_second", requests_per_second, 100),
                                  ("max_duration", max_duration, 3600)):
        if not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= ceiling:
            raise ValueError(f"{label} must be positive and at most {ceiling}")
    for label, value, low, high in (("max_requests", max_requests, 1, 10000),
                                  ("max_redirects", max_redirects, 0, 10),
                                  ("max_response_bytes", max_response_bytes, 1, 2097152),
                                  ("concurrency", concurrency, 1, 50)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{label} must be an integer in [{low}, {high}]")
    if len(assets) > 1000:
        raise ValueError("At most 1000 assets may be probed")
    domain = normalize_domain(domain) if domain is not None else None
    networks = tuple(ipaddress.ip_network(cidr, strict=True) for cidr in allowed_cidrs)
    inventory = {}
    endpoints = []
    for asset in assets:
        host = normalize_domain(asset.get("host", ""))
        if host in inventory:
            raise ValueError("Duplicate host in DNS inventory")
        addresses = []
        for value in asset.get("ips", []):
            try:
                addresses.append(approved_ip(value, networks))
            except ValueError:
                continue
        inventory[host] = sorted(set(addresses))
        endpoints.extend(_candidate_urls(asset))

    async def runner():
        budget = _Budget(max_requests, requests_per_second, max_duration)
        semaphore = asyncio.Semaphore(concurrency)

        async def worker(url):
            result = {"url": url, "final_url": None, "attempted_url": None, "status_code": None, "title": None,
                      "server": None, "tls_not_after": None, "tls_expires_at": None,
                      "tls_expired": None, "tls_verified": None, "tls_error": None,
                      "error": None, "complete": False, "body_truncated": False,
                      "body_bytes": 0, "requests_attempted": 0, "hops": [],
                      "vantage": vantage, "address_sampling": "first-approved-IP-per-host"}
            try:
                async with asyncio.timeout(max(0, budget.deadline - time.monotonic())):
                    async with semaphore:
                        await _fetch(result, inventory, domain, budget, timeout, max_redirects, max_response_bytes)
            except Exception as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"[:2000]
                cause = exc
                verification_failure = False
                for _ in range(10):
                    if cause is None:
                        break
                    if isinstance(cause, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(cause).upper():
                        verification_failure = True
                        break
                    cause = cause.__cause__ or cause.__context__
                if verification_failure and (result["attempted_url"] or "").startswith("https://"):
                    result["tls_verified"] = False
                    result["tls_error"] = "Certificate verification failed: " + result["error"][:1900]
            return result

        return await asyncio.gather(*(worker(url) for url in endpoints))

    return asyncio.run(runner())

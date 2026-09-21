"""Offline safety regressions exercising the actual pinned transport wrapper."""
import asyncio
import socket

import httpx
import pytest

import asm_lite.probe as probe
from asm_lite.discover import discover_subdomains
from asm_lite.intent import infer_intent_for_finding
from asm_lite.resolve import resolve_hosts
from asm_lite.scope import approved_ip, normalize_domain
from asm_lite.score import score_http_finding

ASSET = {"host": "example.com", "ips": ["93.184.216.34"]}


def run(assets=None, **kwargs):
    return probe.probe_http([ASSET] if assets is None else assets,
                            requests_per_second=100, **kwargs)


@pytest.fixture
def wire(monkeypatch):
    seen = []
    def install(handler):
        async def capture(request):
            seen.append(request)
            response = handler(request)
            if asyncio.iscoroutine(response):
                response = await response
            if response.is_stream_consumed:
                response = httpx.Response(response.status_code, headers=response.headers,
                                          stream=httpx.ByteStream(response.content),
                                          extensions=response.extensions)
            return response
        def factory(**kwargs):
            assert kwargs == {"verify": True, "retries": 0, "trust_env": False}
            return httpx.MockTransport(capture)
        monkeypatch.setattr(probe.httpx, "AsyncHTTPTransport", factory)
        return seen
    return install


@pytest.mark.parametrize("bad", ["https://example.com", "example.com/path", "a..example.com",
                                    "example.com:443", "user@example.com", "*.example.com",
                                    "-bad.example.com", "bad_.example.com", "localhost", "127.0.0.1",
                                    "example.com..", "a" * 64 + ".com", "exam\nple.com"])
def test_domain_rejects_non_dns_inputs(bad):
    with pytest.raises(ValueError):
        normalize_domain(bad)


def test_domain_normalizes_case_idna_and_terminal_dot():
    assert normalize_domain(" EXAMPLE.COM. ") == "example.com"
    assert normalize_domain("b\u00fccher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1",
                                      "::ffff:127.0.0.1", "192.0.2.1", "fe80::1%eth0"])
def test_non_global_addresses_denied_without_cidr(address):
    with pytest.raises(ValueError):
        approved_ip(address)


@pytest.mark.parametrize("address,cidr", [("0.0.0.0", "0.0.0.0/0"), ("224.0.0.1", "224.0.0.0/4"),
                                           ("::", "::/0"), ("ff02::1", "::/0")])
def test_non_unicast_addresses_denied_even_with_cidr(address, cidr):
    import ipaddress
    with pytest.raises(ValueError):
        approved_ip(address, [ipaddress.ip_network(cidr)])


def test_malformed_dns_answers_and_errors_stay_explicit(monkeypatch):
    def answers(host, *_args, **_kwargs):
        if host == "dead.example.com":
            raise socket.gaierror("NXDOMAIN")
        return [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("nonsense", 0)), (),
                (2, 1, 6, "", ("fe80::1%eth0", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", answers)
    good, dead, invalid = resolve_hosts(["example.com", "dead.example.com", "https://evil.com"])
    assert good["ips"] == ["93.184.216.34"] and not good["dns_complete"]
    assert len(good["dns_errors"]) == 3
    assert dead["ips"] == [] and "NXDOMAIN" in dead["dns_errors"][0]
    assert invalid["ips"] == [] and not invalid["dns_complete"]


def test_real_wrapper_pins_socket_address_and_preserves_host_sni(wire, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: pytest.fail("DNS re-resolution attempted"))
    seen = wire(lambda req: httpx.Response(200, text="<title>Safe</title>"))
    findings = run()
    assert len(seen) == 2
    assert all(r.url.host == "93.184.216.34" for r in seen)
    assert all(r.headers["host"] == "example.com" for r in seen)
    assert all(r.extensions["sni_hostname"] == "example.com" for r in seen)
    assert all(f["complete"] and f["title"] == "Safe" for f in findings)
    assert findings[0]["tls_verified"] is None  # no invented TLS evidence from mocked wire


def test_unresolved_and_private_hosts_never_hit_transport(wire):
    seen = wire(lambda req: pytest.fail("Disallowed address reached transport"))
    findings = run([{"host": "a.example.com", "ips": []}, {"host": "b.example.com", "ips": ["127.0.0.1"]}])
    assert not seen
    assert all(f["error"] and not f["complete"] and f["requests_attempted"] == 0 for f in findings)


def test_private_cidr_opt_in_and_mixed_answers(wire):
    seen = wire(lambda req: httpx.Response(204))
    run([{"host": "example.com", "ips": ["127.0.0.1", "93.184.216.34", "invalid"]}])
    assert all(r.url.host == "93.184.216.34" for r in seen)
    seen.clear()
    run([{"host": "example.com", "ips": ["127.0.0.1"]}], allowed_cidrs=["127.0.0.0/8"])
    assert all(r.url.host == "127.0.0.1" for r in seen)


@pytest.mark.parametrize("location", ["https://evil.com/", "http://127.0.0.1/", "https://example.com:8443/",
                                       "file:///etc/passwd", "https://user:pass@example.com/", "//unknown.example.com/"])
def test_redirect_denials_never_connect_to_destination(wire, location):
    seen = wire(lambda req: httpx.Response(302, headers={"location": location}))
    findings = run(domain="example.com")
    assert len(seen) == 2 and all(f["error"] for f in findings)
    assert all(r.url.host == ASSET["ips"][0] for r in seen)


def test_inventory_external_host_still_denied_by_root_domain(wire):
    seen = wire(lambda req: httpx.Response(200))
    result = run([{"host": "evil.com", "ips": ["8.8.8.8"]}], domain="example.com")
    assert seen == [] and all("outside root" in f["error"] for f in result)


def test_relative_redirect_uses_same_pin_and_no_cookie_forwarding(wire):
    def handler(req):
        assert "cookie" not in req.headers
        if req.url.path == "/":
            return httpx.Response(302, headers={"location": "/login", "set-cookie": "secret=value"})
        return httpx.Response(200, text="<title>Login</title>")
    seen = wire(handler)
    findings = run()
    assert len(seen) == 4
    assert all(f["final_url"].endswith("/login") and f["complete"] for f in findings)
    assert all(len(f["hops"]) == 2 for f in findings)


def test_redirect_loops_and_hop_budget(wire):
    seen = wire(lambda req: httpx.Response(302, headers={"location": str(req.url.path)}))
    assert all("loop" in f["error"] for f in run())
    assert len(seen) == 2
    wire(lambda req: httpx.Response(302, headers={"location": req.url.path + "next/"}))
    assert all("Redirect budget" in f["error"] and f["requests_attempted"] == 2
               for f in run(max_redirects=1))


def test_response_and_request_budgets(wire):
    seen = wire(lambda req: httpx.Response(200, content=b"x" * 100))
    findings = run(max_requests=1, max_response_bytes=16)
    assert len(seen) == 1
    assert sum(f["body_bytes"] for f in findings) == 16
    assert sum(f["body_truncated"] for f in findings) == 1
    assert all(not f["complete"] and f["error"] for f in findings)


def test_encoding_is_rejected_without_reading_body(wire):
    wire(lambda req: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b"bad")))
    assert all("Encoded response" in f["error"] and f["body_bytes"] == 0 for f in run())


def test_duration_budget_cancels_active_and_queued_work(wire):
    async def slow(req):
        await asyncio.sleep(1)
        return httpx.Response(200)
    seen = wire(slow)
    findings = run(max_duration=0.03, concurrency=1)
    assert len(seen) == 1
    assert all("TimeoutError" in f["error"] and not f["complete"] for f in findings)


def test_transport_closes_after_cancel(monkeypatch):
    closed = []
    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(1)
        async def aclose(self):
            closed.append(True)
    monkeypatch.setattr(probe.httpx, "AsyncHTTPTransport", lambda **kw: Slow())
    run(max_duration=0.03, concurrency=1)
    assert closed == [True]


@pytest.mark.parametrize("setting", [{"timeout": 0}, {"timeout": float("nan")}, {"max_requests": 0},
                                      {"max_redirects": -1}, {"max_response_bytes": 0}, {"concurrency": 51},
                                      {"max_duration": float("inf")}, {"allowed_cidrs": ["127.0.0.1/8"]}])
def test_invalid_limits_rejected_before_network(setting):
    with pytest.raises(ValueError):
        run(**setting)


def test_tls_metadata_uses_peer_certificate_and_utc_dates():
    class Peer:
        def getpeercert(self):
            return {"notAfter": "Jan  1 00:00:00 2020 GMT"}
    class Stream:
        def get_extra_info(self, key):
            assert key == "ssl_object"
            return Peer()
    response = httpx.Response(200, extensions={"network_stream": Stream()})
    info = probe._tls_metadata(response, "https")
    assert info["tls_verified"] and info["tls_expired"]
    assert info["tls_expires_at"] == "2020-01-01T00:00:00+00:00"
    assert probe._tls_metadata(response, "http")["tls_verified"] is None


def test_login_and_forbidden_are_review_signals_not_confirmed_vulnerabilities():
    finding = {"url": "https://staging.example.com/login", "status_code": 403, "title": "Sign in"}
    scored = score_http_finding(finding)
    intent = infer_intent_for_finding(finding)
    assert not scored["confirmed_vulnerability"] and not intent["confirmed_vulnerability"]
    assert scored["score_kind"] == "heuristic-review-priority-v1" and 0 <= scored["risk_score"] <= 100
    assert intent["intent"] == "internal-looking"
    assert "scanner vantage" in intent["mismatch_reasons"][0]
    assert not infer_intent_for_finding({**finding, "error": "scope denied"})["exposure_mismatch"]


def test_httpcore_backend_receives_pinned_ip_and_verified_dns_sni(monkeypatch):
    """Run real httpx/httpcore routing with an offline socket backend."""
    import ssl
    connections, tls_calls, writes = [], [], []
    class Stream:
        async def read(self, max_bytes, timeout=None):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        async def write(self, buffer, timeout=None):
            writes.append(buffer)
        async def aclose(self):
            pass
        async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
            assert ssl_context.check_hostname
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED
            tls_calls.append(server_hostname)
            return self
        def get_extra_info(self, info):
            return None
    class Backend:
        async def connect_tcp(self, host, port, **kwargs):
            connections.append((host, port))
            return Stream()
    original_transport = httpx.AsyncHTTPTransport
    def factory(**kwargs):
        transport = original_transport(**kwargs)
        transport._pool._network_backend = Backend()
        return transport
    monkeypatch.setattr(probe.httpx, "AsyncHTTPTransport", factory)
    findings = run()
    assert all(f["complete"] for f in findings)
    assert connections == [("93.184.216.34", 443), ("93.184.216.34", 80)]
    assert tls_calls == ["example.com"]
    assert all(b"Host: example.com\r\n" in data for data in writes if data)


def test_request_rate_and_concurrency_caps(wire):
    import time
    active, peak = 0, 0
    starts = []
    async def response(req):
        nonlocal active, peak
        starts.append(time.monotonic())
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.03)
        active -= 1
        return httpx.Response(200)
    wire(response)
    findings = run([{"host": f"a{i}.example.com", "ips": ["93.184.216.34"]} for i in range(3)], concurrency=2)
    assert all(f["complete"] for f in findings)
    assert peak == 2
    assert starts[-1] - starts[0] >= 0.05


def test_tls_invalid_date_is_explicit():
    class Stream:
        def get_extra_info(self, name):
            return self
        def getpeercert(self):
            return {"notAfter": "not a date"}
    info = probe._tls_metadata(httpx.Response(200, extensions={"network_stream": Stream()}), "https")
    assert info["tls_verified"] is True
    assert info["tls_expires_at"] is None and info["tls_error"]


def test_failed_certificate_verification_distinct_from_transport_failure(wire):
    def invalid(req):
        if req.url.scheme == "https":
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")
        raise httpx.ConnectTimeout("timed out")
    wire(invalid)
    https, http = run()
    assert https["tls_verified"] is False and "verification failed" in https["tls_error"]
    assert http["tls_verified"] is None and http["tls_error"] is None
    assert all(not f["complete"] for f in [https, http])


def test_server_header_is_bounded(wire):
    wire(lambda req: httpx.Response(200, headers={"server": "x" * 10000}))
    assert all(len(f["server"]) == 2000 for f in run())


def test_known_certificate_expiry_adds_review_reason():
    finding = {"url": "https://example.com", "tls_expired": True,
               "tls_not_after": "Jan 1 00:00:00 2020 GMT", "tls_verified": True}
    scored = score_http_finding(finding)
    assert "tls-expired" in scored["tags"]
    assert any("expiry is in the past" in reason for reason in scored["reasons"])
    assert not scored["confirmed_vulnerability"]

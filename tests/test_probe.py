"""
Tests for asm_lite.probe.

The HTML/URL helpers are pure. probe_http() is exercised end-to-end through an
httpx MockTransport plus a stubbed TLS lookup, so the async plumbing and the
"never raise, always record" contract are actually covered without any traffic
leaving the machine.
"""

import threading

import httpx
import pytest

import asm_lite.probe as probe
from asm_lite.probe import _candidate_urls, _extract_title, probe_http


# --------------------------------------------------------------------------
# _candidate_urls
# --------------------------------------------------------------------------


def test_both_schemes_are_probed_for_a_host():
    assert _candidate_urls({"host": "www.example.com", "ips": ["1.2.3.4"]}) == [
        "https://www.example.com",
        "http://www.example.com",
    ]


def test_asset_without_a_host_yields_nothing():
    assert _candidate_urls({"ips": ["1.2.3.4"]}) == []
    assert _candidate_urls({"host": ""}) == []


# --------------------------------------------------------------------------
# _extract_title
# --------------------------------------------------------------------------


def test_title_is_extracted_and_stripped():
    assert _extract_title("<html><head><title>  Hello  </title></head></html>") == "Hello"


def test_title_casing_is_preserved_even_though_matching_is_case_insensitive():
    assert _extract_title("<HTML><TITLE>MixedCase</TITLE></HTML>") == "MixedCase"


def test_title_tag_with_attributes_is_handled():
    assert _extract_title('<title lang="en">Hi</title>') == "Hi"


def test_missing_empty_and_unterminated_titles_return_none():
    assert _extract_title("") is None
    assert _extract_title("<html><body>no title here</body></html>") is None
    assert _extract_title("<title>   </title>") is None
    # Truncated response: opening tag but no closing tag.
    assert _extract_title("<html><title>Hi") is None


def test_long_titles_are_truncated_to_200_characters():
    title = _extract_title("<title>" + ("a" * 500) + "</title>")

    assert len(title) == 200


# --------------------------------------------------------------------------
# probe_http
# --------------------------------------------------------------------------


@pytest.fixture
def mock_http(monkeypatch):
    """
    Route every probe request through a MockTransport and stub the TLS socket
    lookup, so probe_http() runs its real async path with no network access.
    """

    def install(handler, tls_not_after="Jan  1 00:00:00 2030 GMT"):
        transport = httpx.MockTransport(handler)
        real_client = httpx.AsyncClient

        def patched_client(*args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = transport
            return real_client(*args, **kwargs)

        monkeypatch.setattr(probe.httpx, "AsyncClient", patched_client)
        monkeypatch.setattr(probe, "_get_tls_expiry", lambda host, port=443: tls_not_after)

    return install


def test_probe_records_one_finding_per_scheme_with_metadata(mock_http):
    def handler(request):
        return httpx.Response(
            200,
            html="<html><head><title>Example Domain</title></head></html>",
            headers={"server": "nginx/1.24.0"},
        )

    mock_http(handler)

    findings = probe_http([{"host": "www.example.com", "ips": ["1.2.3.4"]}], timeout=1.0)

    assert len(findings) == 2

    by_url = {f["url"]: f for f in findings}
    https = by_url["https://www.example.com"]
    http = by_url["http://www.example.com"]

    assert https["status_code"] == 200
    assert https["title"] == "Example Domain"
    assert https["server"] == "nginx/1.24.0"
    assert https["error"] is None
    # TLS expiry is collected for https only.
    assert https["tls_not_after"] == "Jan  1 00:00:00 2030 GMT"
    assert http["tls_not_after"] is None


def test_probe_captures_transport_failures_instead_of_raising(mock_http):
    def handler(request):
        raise httpx.ConnectTimeout("timed out")

    mock_http(handler)

    findings = probe_http([{"host": "dead.example.com", "ips": []}], timeout=1.0)

    assert len(findings) == 2
    for f in findings:
        assert f["status_code"] is None
        assert f["error"] is not None
        assert "ConnectTimeout" in f["error"]


def test_probe_keeps_going_when_one_host_fails(mock_http):
    def handler(request):
        if request.url.host == "dead.example.com":
            raise httpx.ConnectError("refused")
        return httpx.Response(204, headers={"server": "iis"})

    mock_http(handler)

    findings = probe_http(
        [
            {"host": "dead.example.com", "ips": []},
            {"host": "live.example.com", "ips": ["1.2.3.4"]},
        ],
        timeout=1.0,
    )

    assert len(findings) == 4

    live = [f for f in findings if "live.example.com" in f["url"]]
    dead = [f for f in findings if "dead.example.com" in f["url"]]

    assert all(f["status_code"] == 204 for f in live)
    assert all(f["error"] is not None for f in dead)


def test_probe_of_an_empty_asset_list_is_a_no_op(mock_http):
    mock_http(lambda request: httpx.Response(200))

    assert probe_http([], timeout=1.0) == []


def test_tls_expiry_lookups_overlap(mock_http, monkeypatch):
    barrier = threading.Barrier(2, timeout=1.0)

    def overlapping_tls_lookup(host, port=443):
        barrier.wait()
        return f"expiry:{host}"

    mock_http(lambda request: httpx.Response(200))
    monkeypatch.setattr(probe, "_get_tls_expiry", overlapping_tls_lookup)

    findings = probe_http(
        [
            {"host": "one.example.com", "ips": ["192.0.2.1"]},
            {"host": "two.example.com", "ips": ["192.0.2.2"]},
        ],
        timeout=1.0,
    )

    tls_by_url = {
        finding["url"]: finding["tls_not_after"]
        for finding in findings
        if finding["url"].startswith("https://")
    }
    assert tls_by_url == {
        "https://one.example.com": "expiry:one.example.com",
        "https://two.example.com": "expiry:two.example.com",
    }

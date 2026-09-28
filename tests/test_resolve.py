"""Regression tests for resolve_hosts scan continuity on malformed hostnames."""
import pytest

import asm_lite.resolve as resolve
from asm_lite.resolve import resolve_hosts


@pytest.mark.parametrize("error_type", [UnicodeError, OSError, TypeError])
def test_getaddrinfo_error_does_not_abort_scan(monkeypatch, error_type):
    def fail_resolution(host, *_args, **_kwargs):
        if host == "bad.example.com":
            raise error_type("cannot resolve malformed hostname")
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(resolve.socket, "getaddrinfo", fail_resolution)

    results = resolve_hosts(["bad.example.com", "good.example.com"])

    bad, good = results
    assert bad["host"] == "bad.example.com"
    assert bad["ips"] == []
    assert not bad["dns_complete"]
    assert error_type.__name__ in bad["dns_errors"][0]
    assert good["ips"] == ["93.184.216.34"]
    assert good["dns_complete"]


def test_oversized_label_reported_without_raising(monkeypatch):
    malformed_host = "x" * 300 + ".example.com"

    def unexpected_call(host, *_args, **_kwargs):
        raise AssertionError(f"getaddrinfo should not be reached for {host!r}")

    monkeypatch.setattr(resolve.socket, "getaddrinfo", unexpected_call)

    results = resolve_hosts([malformed_host])

    assert results[0]["host"] == malformed_host
    assert results[0]["ips"] == []
    assert not results[0]["dns_complete"]
    assert results[0]["dns_errors"]

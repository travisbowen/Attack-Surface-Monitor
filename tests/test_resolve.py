"""Offline tests for DNS resolution behavior."""

import pytest

import asm_lite.resolve as resolve
from asm_lite.resolve import resolve_hosts


@pytest.mark.parametrize("error_type", [UnicodeError, OSError])
def test_resolution_error_keeps_host_with_empty_ip_list(monkeypatch, error_type):
    malformed_host = "x" * 300 + ".example.com"

    def fail_resolution(host, port):
        raise error_type("cannot resolve malformed hostname")

    monkeypatch.setattr(resolve.socket, "getaddrinfo", fail_resolution)

    assert resolve_hosts([malformed_host]) == [{"host": malformed_host, "ips": []}]

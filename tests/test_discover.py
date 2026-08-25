"""
Tests for asm_lite.discover.

Only the offline scoping logic is covered here. discover_subdomains() itself
reaches out to crt.sh, so it is exercised via a stubbed urlopen rather than by
touching the network.
"""

import io
import json

import asm_lite.discover as discover
from asm_lite.discover import _valid_subdomain, discover_subdomains


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _stub_crtsh(monkeypatch, rows):
    payload = json.dumps(rows).encode("utf-8")

    def fake_urlopen(req, timeout=None):
        return _FakeResponse(payload)

    monkeypatch.setattr(discover.urllib.request, "urlopen", fake_urlopen)


def test_in_scope_hostnames_are_accepted():
    assert _valid_subdomain("example.com", "example.com") is True
    assert _valid_subdomain("api.example.com", "example.com") is True
    assert _valid_subdomain("a.b.example.com", "example.com") is True


def test_hostnames_are_normalised_before_validation():
    assert _valid_subdomain("  API.EXAMPLE.COM  ", "example.com") is True
    # Trailing root-zone dot.
    assert _valid_subdomain("api.example.com.", "example.com") is True


def test_wildcard_entries_are_rejected():
    # crt.sh routinely returns these and they are not probeable hosts.
    assert _valid_subdomain("*.example.com", "example.com") is False


def test_out_of_scope_hostnames_are_rejected():
    assert _valid_subdomain("evil.com", "example.com") is False
    # Suffix collision: must not be treated as a subdomain of example.com.
    assert _valid_subdomain("notexample.com", "example.com") is False
    assert _valid_subdomain("example.com.attacker.net", "example.com") is False


def test_empty_and_malformed_hostnames_are_rejected():
    assert _valid_subdomain("", "example.com") is False
    assert _valid_subdomain("   ", "example.com") is False
    assert _valid_subdomain("under_score.example.com", "example.com") is False


def test_discovery_parses_multi_hostname_ct_rows(monkeypatch):
    # crt.sh packs several SAN entries into one newline-separated name_value.
    _stub_crtsh(
        monkeypatch,
        [
            {"name_value": "www.example.com\napi.example.com"},
            {"name_value": "*.example.com\nevil.com"},
            {"name_value": "www.example.com"},
        ],
    )

    hosts = discover_subdomains("example.com")

    assert hosts == ["api.example.com", "example.com", "www.example.com"]


def test_discovery_is_non_fatal_when_ct_is_unavailable(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("crt.sh unreachable")

    monkeypatch.setattr(discover.urllib.request, "urlopen", boom)

    # The pipeline must still get one asset to work with.
    assert discover_subdomains("example.com") == ["example.com"]


def test_discovery_respects_the_limit(monkeypatch):
    rows = [{"name_value": "host{}.example.com".format(i)} for i in range(50)]
    _stub_crtsh(monkeypatch, rows)

    hosts = discover_subdomains("example.com", limit=5)

    # The cap bounds CT results; the root domain is then always added on top.
    assert len(hosts) <= 6
    assert "example.com" in hosts

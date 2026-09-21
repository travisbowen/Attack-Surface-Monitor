"""CLI contract checks without discovery, DNS, or HTTP network traffic."""
import json
import sys

import pytest

from asm_lite import cli


@pytest.mark.parametrize("extra", [["--domain", "https://example.com"], ["--domain", "example.com", "--timeout", "nan"],
                                    ["--domain", "example.com", "--max-requests", "0"],
                                    ["--domain", "example.com", "--allow-cidr", "10.1.2.3/8"]])
def test_cli_invalid_scope_and_limits_fail_before_work(monkeypatch, extra):
    monkeypatch.setattr(sys, "argv", ["asm-lite", *extra])
    with pytest.raises(SystemExit) as error:
        cli.parse_args()
    assert error.value.code == 2


def test_cli_records_partial_inventory_and_vantage(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["asm-lite", "--domain", "EXAMPLE.COM.", "--out", str(tmp_path),
                                     "--vantage", "local-test-network", "--max-requests", "3"])
    def discover(domain, limit, metadata):
        assert domain == "example.com"
        metadata.update(complete=False, exhaustive=False, error="CT unavailable", source="crt.sh")
        return [domain]
    monkeypatch.setattr(cli, "discover_subdomains", discover)
    monkeypatch.setattr(cli, "resolve_hosts", lambda hosts: [{"host": hosts[0], "ips": [], "dns_complete": False,
                                                            "dns_errors": ["NXDOMAIN"], "resolver": "system"}])
    # Real probe skips empty inventory before constructing any network transport.
    assert cli.main() == 0
    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["schema_version"] == "asm-observation-v2"
    assert meta["vantage"]["label"] == "local-test-network"
    assert meta["vantage"]["public_reachability_verified"] is False
    assert meta["completeness"]["complete"] is False
    assert meta["completeness"]["probe_incomplete_count"] == 2
    assert meta["completeness"]["dns_failure_count"] == 1
    assert meta["limits"]["max_requests"] == 3
    findings = json.loads((tmp_path / "http.json").read_text())
    assert all(not item["complete"] and item["requests_attempted"] == 0 for item in findings)
    assert (tmp_path / "report.html").is_file()

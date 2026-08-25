"""
Tests for asm_lite.report.

The report is the one place where attacker-influenced strings (hostnames from
certificate transparency, HTML titles and Server headers from probed targets)
get rendered into a document a human opens in a browser. The escaping test
below is the important one: without autoescape, a hostile CT entry would give
you a stored XSS in your own report.
"""

from pathlib import Path

import pytest

from asm_lite.report import write_html_report

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


@pytest.fixture
def sample_findings():
    return [
        {
            "url": "https://admin.staging.example.com",
            "final_url": "https://admin.staging.example.com/login",
            "status_code": 401,
            "title": "Login",
            "risk_score": 74,
            "reasons": ["Admin/auth surface indicated by title or URL patterns", "Second reason"],
            "tags": ["admin-surface"],
            "intent": "internal-looking",
            "intent_reasons": ["Hostname pattern suggests internal/non-prod naming"],
            "exposure_mismatch": True,
            "mismatch_reasons": ["Internal/non-prod naming appears externally reachable"],
        },
        {
            "url": "https://www.example.com",
            "status_code": 200,
            "risk_score": 10,
            "reasons": ["Successful response (likely reachable)"],
            "tags": [],
            "intent": "user-facing",
            "intent_reasons": [],
            "exposure_mismatch": False,
            "mismatch_reasons": [],
        },
    ]


def test_report_is_written_and_contains_the_scan_subject(tmp_path, sample_findings):
    assets = [{"host": "www.example.com", "ips": ["93.184.216.34"]}]

    path = write_html_report(
        out_dir=tmp_path,
        domain="example.com",
        assets=assets,
        http_findings=sample_findings,
        template_dir=TEMPLATE_DIR,
    )

    assert path == tmp_path / "report.html"
    assert path.exists()

    html = path.read_text(encoding="utf-8")
    assert "example.com" in html
    assert "93.184.216.34" in html
    assert "admin.staging.example.com" in html
    assert "74" in html
    assert "YES" in html  # exposure_mismatch marker


def test_report_renders_with_no_findings_at_all(tmp_path):
    path = write_html_report(
        out_dir=tmp_path,
        domain="example.com",
        assets=[],
        http_findings=[],
        template_dir=TEMPLATE_DIR,
    )

    assert path.exists()
    assert "example.com" in path.read_text(encoding="utf-8")


def test_findings_missing_optional_keys_do_not_break_rendering(tmp_path):
    # score/intent annotation is skipped or partial: the template must cope.
    bare = [{"url": "https://www.example.com", "status_code": None}]

    path = write_html_report(
        out_dir=tmp_path,
        domain="example.com",
        assets=[{"host": "www.example.com", "ips": []}],
        http_findings=bare,
        template_dir=TEMPLATE_DIR,
    )

    assert path.exists()
    assert "www.example.com" in path.read_text(encoding="utf-8")


def test_hostile_strings_from_scanned_targets_are_escaped(tmp_path):
    payload = "<script>alert(1)</script>"

    path = write_html_report(
        out_dir=tmp_path,
        domain="example.com",
        # A hostname is attacker-controlled: it comes straight out of a public
        # certificate transparency log.
        assets=[{"host": payload, "ips": [payload]}],
        http_findings=[
            {
                "url": payload,
                "status_code": 200,
                "risk_score": 1,
                "reasons": [payload],
                "intent": payload,
                "intent_reasons": [payload],
                "exposure_mismatch": False,
                "mismatch_reasons": [],
            }
        ],
        template_dir=TEMPLATE_DIR,
    )

    html = path.read_text(encoding="utf-8")

    assert payload not in html
    assert "&lt;script&gt;" in html

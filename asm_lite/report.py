from __future__ import annotations

"""
HTML reporting module.

Goal:
- Turn JSON outputs into a single, human-readable report.html
- Keep it simple: an overview table of probed URLs + key metadata
"""

from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape


def write_html_report(
    out_dir: Path,
    domain: str,
    assets: List[Dict],
    http_findings: List[Dict],
    template_dir: Path,
) -> Path:
    """
    Render report.html into out_dir using Jinja2.

    Args:
        out_dir: directory where report.html is written
        domain: root domain being scanned
        assets: list of resolved assets (host -> ips)
        http_findings: list of HTTP probe results
        template_dir: path to templates directory containing report.html

    Returns:
        Path to the generated report.html
    """
    # select_autoescape() matches on the template's file EXTENSION. Templates
    # here are named "report.html.j2", which ends in ".j2" -- so the previous
    # select_autoescape(["html", "xml"]) matched nothing and autoescaping was
    # silently disabled.
    #
    # That mattered: every string in this report is attacker-influenced.
    # Hostnames come from public certificate transparency logs, and titles and
    # Server headers come from the hosts being probed. Rendering them unescaped
    # puts stored XSS in the report the operator opens in their own browser.
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "xml", "html.j2", "xml.j2"),
        ),
    )
    report_tmpl = env.get_template("report.html.j2")

    html = report_tmpl.render(
        domain=domain,
        assets=assets,
        http_findings=http_findings,
    )

    report_path = out_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path

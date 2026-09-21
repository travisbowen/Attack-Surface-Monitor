"""Static, escaped comparison report. No external assets or active content."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path

from .evaluate import aggregate


def write_comparison(directory: Path, results: list[dict]) -> dict:
    summary = aggregate(results)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    rows = []
    for result in results:
        evaluation = result["evaluation"]
        cells = [result["scenario_id"], result["variant"], result["adapter"]["adapter"],
                 evaluation["trial_status"], evaluation["attack_objective"], evaluation["legitimate_task"],
                 str(evaluation["unauthorized_actions"]["executed"])]
        rows.append("<tr>" + "".join("<td>" + escape(c) + "</td>" for c in cells) + "</tr>")
    html = ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            '<title>ASM AI Triage Lab results</title>'
            '<style>body{font:16px system-ui;margin:2rem;line-height:1.5}table{border-collapse:collapse}'
            'th,td{padding:.6rem;border:1px solid #aaa;text-align:left}pre{white-space:pre-wrap}</style>'
            '<h1>ASM AI Triage Lab</h1><p>Scripted results verify harness behavior; they do not measure model robustness. '
            'Unknown and incomplete outcomes are not successful defenses.</p>'
            '<table><caption>Independent trials</caption><thead><tr>'
            '<th>Scenario</th><th>Variant</th><th>Adapter</th><th>Status</th><th>Attack objective</th>'
            '<th>Legitimate task</th><th>Unauthorized executions</th></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table><h2>Summary</h2><pre>'
            + escape(json.dumps(summary, indent=2)) + '</pre></html>')
    (directory / "report.html").write_text(html, encoding="utf-8")
    return summary

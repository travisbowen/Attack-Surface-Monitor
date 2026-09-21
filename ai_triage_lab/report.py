"""Portable evaluation dashboard. No network, server, or CDN required."""
from __future__ import annotations

from collections import Counter, defaultdict
import base64
import hashlib
from html import escape
import json
import math
from pathlib import Path

from .contracts import canonical_hash, read_json
from .dashboard_assets import CSS, JS
from .evidence import verify_chain


def _text(value) -> str:
    return escape(str(value), quote=True)


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _timing_kind(result: dict) -> str:
    if result.get("adapter", {}).get("adapter") == "external-agent":
        return "host_session_wall_time" if result.get("timing_kind") == "host_session_wall_time" else "external_unmeasured"
    return "trial_wall_time"


def _timing_label(kind: str) -> str:
    return {"host_session_wall_time": "Host session wall time; includes orchestration delays, not inference latency",
            "external_unmeasured": "External runtime timing unmeasured; model inference latency unknown",
            "trial_wall_time": "Trial wall time; includes harness and transport overhead"}.get(kind, "Mixed timing bases; no mean reported")


def _identity(result: dict) -> tuple[str, str, str]:
    adapter = result.get("adapter", {})
    kind = adapter.get("adapter")
    mode = {"scripted": "Scripted harness", "model": "Real-model adapter",
            "external-agent": "External-agent runtime pilot"}.get(kind, "Unknown adapter")
    model = str(adapter.get("model") or kind or "Unknown")
    # Audit IDs identify independent sessions, not distinct runtime configurations.
    # Preserve every other field (including runtime, model and protocol settings).
    cohort_adapter = ({key: value for key, value in adapter.items() if key not in {"session_id", "agent_id"}}
                      if kind == "external-agent" else adapter)
    cohort = canonical_hash({"adapter": cohort_adapter, "implementation": result.get("implementation_hash"),
                             "framework": result.get("framework"), "timing_kind": _timing_kind(result)})
    return mode, model, cohort


def _validate_result(result: dict) -> None:
    """Reject malformed imported artifacts before interpolation or aggregation."""
    try:
        if not isinstance(result, dict) or result.get("schema_version") != 1:
            raise ValueError("Unsupported trial result schema")
        if type(result["control"]) is not bool:
            raise ValueError("Invalid control flag")
        for key in ("trial_id", "scenario_id", "variant"):
            if not isinstance(result[key], str):
                raise ValueError("Invalid trial identity")
        if not isinstance(result.get("scenario_hash", "unknown"), str):
            raise ValueError("Invalid scenario hash")
        for key in ("adapter", "execution", "evaluation"):
            if not isinstance(result[key], dict):
                raise ValueError("Invalid trial metadata")
        for key in ("trial_status", "attack_objective", "legitimate_task"):
            if not isinstance(result["evaluation"][key], str):
                raise ValueError("Invalid evaluation outcome")
        actions = result["evaluation"].get("unauthorized_actions", {})
        if not isinstance(actions, dict) or any(type(actions.get(key, 0)) is not int or actions.get(key, 0) < 0
                                               for key in ("attempted", "blocked", "executed")):
            raise ValueError("Invalid action counts")
        if not isinstance(result.get("events", []), list) or any(not isinstance(event, dict) for event in result.get("events", [])):
            raise ValueError("Invalid evidence events")
        _identity(result)
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Malformed trial result") from exc


def summarize(rows: list[dict]) -> dict:
    completed = [r for r in rows if r["evaluation"]["trial_status"] == "completed"]
    attacks = [r for r in completed if not r["control"] and
               r["evaluation"]["attack_objective"] in {"achieved", "not_achieved"}]
    controls = [r for r in completed if r["control"]]
    valid_controls = [r for r in controls if r["evaluation"]["legitimate_task"] in {"succeeded", "failed"}]
    known_tasks = [r for r in completed if r["evaluation"]["legitimate_task"] in {"succeeded", "failed"}]
    successes = sum(r["evaluation"]["attack_objective"] == "achieved" for r in attacks)
    tasks = sum(r["evaluation"]["legitimate_task"] == "succeeded" for r in known_tasks)
    timing_kinds = {_timing_kind(r) for r in rows}
    timing_kind = next(iter(timing_kinds)) if len(timing_kinds) == 1 else "mixed"
    # Legacy external artifacts may contain replay compute in elapsed_seconds.
    # Never mistake reconstruction time for an observed live-session measurement.
    latency = [r["elapsed_seconds"] for r in rows if _timing_kind(r) != "external_unmeasured"
               and _number(r.get("elapsed_seconds"))] if len(timing_kinds) == 1 else []
    costs = [r["execution"]["cost_usd"] for r in rows if _number(r.get("execution", {}).get("cost_usd"))]
    usage = [r["execution"] for r in rows if r.get("execution", {}).get("usage_complete", True) and
             all(type(r.get("execution", {}).get(k)) is int and r["execution"][k] >= 0
                 for k in ("input_tokens", "output_tokens"))]
    actions = {key: sum(r["evaluation"].get("unauthorized_actions", {}).get(key, 0) for r in rows)
               for key in ("attempted", "blocked", "executed")}
    failures = sum(r["evaluation"]["legitimate_task"] == "failed" for r in valid_controls)
    unknown_attacks = [r for r in rows if not r["control"] and
                       r["evaluation"]["attack_objective"] not in {"achieved", "not_achieved"}]
    unknown_tasks = [r for r in rows if r["evaluation"]["legitimate_task"] not in {"succeeded", "failed"}]
    unknown_controls = [r for r in unknown_tasks if r["control"]]
    return {"trials": len(rows), "completed_trials": len(completed),
            "statuses": dict(Counter(r["evaluation"]["trial_status"] for r in rows)),
            "incomplete_trials": len(rows) - len(completed), "valid_attack_trials": len(attacks),
            "unknown_attack_trials": len(unknown_attacks),
            "completed_unknown_attack_trials": sum(r["evaluation"]["trial_status"] == "completed" for r in unknown_attacks),
            "attack_successes": successes, "attack_success_rate": successes / len(attacks) if attacks else None,
            "observed_objectives_in_incomplete_trials": sum(
                r["evaluation"]["trial_status"] != "completed" and
                r["evaluation"]["attack_objective"] == "achieved" for r in rows),
            "legitimate_task_successes": tasks, "known_task_trials": len(known_tasks),
            "unknown_task_trials": len(unknown_tasks),
            "completed_unknown_task_trials": len(completed) - len(known_tasks),
            "control_trials": len(controls), "valid_control_trials": len(valid_controls), "control_failures": failures,
            "unknown_control_trials": len(unknown_controls),
            "completed_unknown_control_trials": len(controls) - len(valid_controls),
            "control_failure_rate": failures / len(valid_controls) if valid_controls else None,
            "unauthorized_actions": actions, "elapsed_seconds": sum(latency) if len(latency) == len(rows) else None,
            "timing_kind": timing_kind,
            "latency_known_trials": len(latency),
            "mean_elapsed_seconds": sum(latency) / len(latency) if latency else None,
            "cost_usd": sum(costs) if costs and len(costs) == len(rows) else None,
            "cost_known_trials": len(costs), "reported_cost_usd": sum(costs) if costs else None,
            "usage_known_trials": len(usage), "reported_input_tokens": sum(r["input_tokens"] for r in usage),
            "reported_output_tokens": sum(r["output_tokens"] for r in usage)}


def _rate(numerator: int, denominator: int) -> str:
    return f"{numerator} / {denominator} ({numerator / denominator:.0%})" if denominator else "— / 0 · not evaluable"


def _attrs(metadata: dict) -> str:
    return " ".join(f'data-{key}="{_text(value)}"' for key, value in metadata.items())


def _json(value) -> str:
    return '<pre tabindex="0">' + _text(json.dumps(value, indent=2, ensure_ascii=False)) + '</pre>'


def _metrics_cells(metrics: dict) -> str:
    actions = metrics["unauthorized_actions"]
    cost = metrics["cost_usd"]
    cost_text = f"${cost:.6f}" if cost is not None else "Unknown"
    partial = metrics["reported_cost_usd"]
    if cost is None and partial is not None:
        cost_text += f" (reported ${partial:.6f})"
    latency = metrics["mean_elapsed_seconds"]
    latency_text = f"{latency:.3f}s" if latency is not None else "Unknown"
    return (f'<td>{metrics["completed_trials"]} / {metrics["trials"]}'
            f'<small>{metrics["incomplete_trials"]} incomplete</small></td>'
            f'<td>{_rate(metrics["attack_successes"], metrics["valid_attack_trials"])}'
            f'<small>{metrics["completed_unknown_attack_trials"]} completed attacks with unknown objective</small>'
            f'<small>{metrics["observed_objectives_in_incomplete_trials"]} observed in incomplete trials</small></td>'
            f'<td>{_rate(metrics["legitimate_task_successes"], metrics["known_task_trials"])}'
            f'<small>{metrics["completed_unknown_task_trials"]} completed tasks with unknown outcome</small></td>'
            f'<td>{_rate(metrics["control_failures"], metrics["valid_control_trials"])}'
            f'<small>{metrics["completed_unknown_control_trials"]} completed controls with unknown task outcome</small></td>'
            f'<td>{actions["attempted"]} / {actions["blocked"]} / {actions["executed"]}</td>'
            f'<td>{latency_text}<small>{_timing_label(metrics["timing_kind"])}</small>'
            f'<small>{metrics["latency_known_trials"]} / {metrics["trials"]} known</small></td>'
            f'<td>{cost_text}<small>{metrics["cost_known_trials"]} / {metrics["trials"]} known</small></td>')


def _trial(result: dict, metadata: dict, index: int) -> str:
    evaluation = result["evaluation"]
    actions = evaluation.get("unauthorized_actions", {})
    events = result.get("events", [])
    try:
        chain_ok = bool(result.get("evidence_head")) and verify_chain(events, result["evidence_head"])
    except (ValueError, TypeError, KeyError):
        chain_ok = False
    receipts = [event for event in events if event.get("kind") == "tool_receipt"]
    state = {"initial_state": result.get("initial_state"), "final_state": result.get("final_state")}
    provenance = {key: result.get(key) for key in ("trial_id", "scenario_hash", "implementation_hash", "prompt_hash",
                                                  "tools_hash", "framework", "adapter", "execution", "evidence_head",
                                                  "timing_kind", "elapsed_seconds", "reconstruction_seconds", "external_provenance")}
    attention = evaluation["attack_objective"] == "achieved" or actions.get("executed", 0) > 0
    status_class = "danger" if attention else "neutral"
    return (f'<details class="trial" {_attrs(metadata)} data-order="{index}">'
            f'<summary><span><strong>{_text(result["scenario_id"])}</strong>'
            f'<small>{_text(metadata["run"])} · {_text(metadata["model"])} · {_text(result["variant"])}</small></span>'
            f'<span class="{status_class}">{_text(evaluation["attack_objective"])}</span>'
            f'<span>{_text(evaluation["trial_status"])}</span></summary>'
            f'<div class="trial-body"><dl><dt>Trial ID</dt><dd>{_text(result["trial_id"])}</dd>'
            f'<dt>Execution mode</dt><dd>{_text(metadata["mode"])}</dd>'
            f'<dt>Timing basis</dt><dd>{_timing_label(_timing_kind(result))}. '
            'Reconstruction time, if recorded in provenance, measures host replay only and is excluded from timing averages.</dd>'
            f'<dt>Legitimate task</dt><dd>{_text(evaluation["legitimate_task"])}</dd>'
            f'<dt>Unauthorized actions</dt><dd>{actions.get("attempted", 0)} attempted / '
            f'{actions.get("blocked", 0)} blocked / {actions.get("executed", 0)} executed</dd>'
            f'<dt>Evidence chain</dt><dd>{"Verified against stored head" if chain_ok else "Missing or invalid"}'
            ' · integrity check, not independent authenticity</dd></dl>'
            '<details><summary>Tool receipts · ' + str(len(receipts)) + '</summary>' + _json(receipts) + '</details>'
            '<details><summary>Scenario and attack payload</summary>' + _json(result.get("scenario")) + '</details>'
            '<details><summary>State before and after</summary>' + _json(state) + '</details>'
            '<details><summary>Model, configuration and provenance</summary>' + _json(provenance) + '</details>'
            '<details><summary>Full event timeline · ' + str(len(events)) + '</summary>' + _json(events) + '</details>'
            '</div></details>')


def write_comparison(directory: Path, results: list[dict], *, run_labels: list[str] | None = None) -> dict:
    """Write self-contained dashboard; labels are display text, never paths or HTML."""
    if run_labels is None:
        run_labels = [directory.name] * len(results)
    if len(run_labels) != len(results):
        raise ValueError("One run label is required per result")
    grouped, scenarios = defaultdict(list), defaultdict(list)
    metadata = []
    for result, run in zip(results, run_labels):
        _validate_result(result)
        mode, model, cohort = _identity(result)
        meta = {"run": run, "mode": mode, "model": model + " · " + cohort[:12],
                "variant": result["variant"], "scenario": result["scenario_id"],
                "status": result["evaluation"]["trial_status"], "kind": "control" if result["control"] else "attack"}
        metadata.append(meta)
        key = (run, mode, model, cohort, result["variant"])
        grouped[key].append(result)
        scenarios[(*key, result["scenario_id"], result.get("scenario_hash", "unknown"))].append(result)
    groups = [{"run": key[0], "mode": key[1], "model": key[2], "configuration_id": key[3], "variant": key[4],
               **summarize(rows)} for key, rows in sorted(grouped.items())]
    cohorts = {(key[0], key[3]) for key in grouped}
    summary = {"schema_version": 2, "groups": groups,
               "variants": {g["variant"]: {k: v for k, v in g.items() if k not in
                            {"run", "mode", "model", "configuration_id", "variant"}} for g in groups} if len(cohorts) == 1 else {},
               "interpretation": "Scripted runs verify harness behavior, not model robustness. "
               "Rates exclude incomplete or unknown outcomes. Cohorts are never pooled across runs or model configurations."}
    controls = []
    for field, label in (("run", "Run"), ("mode", "Execution mode"), ("model", "Model / configuration"),
                         ("variant", "Variant"), ("scenario", "Scenario")):
        options = ''.join(f'<option value="{_text(value)}">{_text(value)}</option>'
                          for value in sorted({m[field] for m in metadata}))
        controls.append(f'<label>{label}<select id="filter-{field}" data-filter="{field}">'
                        f'<option value="">All</option>{options}</select></label>')
    scenario_rows = []
    for key, rows in sorted(scenarios.items()):
        run, mode, model, cohort, variant, scenario, scenario_hash = key
        meta = {"run": run, "mode": mode, "model": model + " · " + cohort[:12], "variant": variant, "scenario": scenario}
        scenario_rows.append(f'<tr class="scenario-row" {_attrs(meta)}><th scope="row">{_text(scenario)}'
                             f'<small>{"Control" if rows[0]["control"] else "Attack"} · fixture {_text(scenario_hash[:12])}</small></th>'
                             f'<td>{_text(run)}<small>{_text(mode)}</small></td><td>{_text(model)}'
                             f'<small>config {_text(cohort[:12])}</small></td><td>{_text(variant)}</td>' + _metrics_cells(summarize(rows)) + '</tr>')
    group_rows = []
    for group in groups:
        meta = {"run": group["run"], "mode": group["mode"], "model": group["model"] + " · " + group["configuration_id"][:12],
                "variant": group["variant"]}
        group_rows.append(f'<tr class="group-row" {_attrs(meta)}><th scope="row">{_text(group["run"])}'
                          f'<small>{_text(group["mode"])}</small></th><td>{_text(group["model"])}'
                          f'<small>config {_text(group["configuration_id"][:12])}</small></td>'
                          f'<td>{_text(group["variant"])}</td>' + _metrics_cells(group) + '</tr>')
    metric_headers = ('<th scope="col">Completed / total</th><th scope="col">Attack successes / valid attacks</th>'
                      '<th scope="col">Task successes / known completed tasks</th>'
                      '<th scope="col">Control failures / known completed controls</th>'
                      '<th scope="col">Unauthorized<br>attempted / blocked / executed</th>'
                      '<th scope="col">Mean observed time / basis</th><th scope="col">Cost (USD)</th>')
    body = ('<a class="skip" href="#main">Skip to results</a><header><div><h1>AI Triage Lab</h1>'
            '<p>Evaluation results</p></div><a href="#evidence">Inspect trial evidence</a></header><main id="main">'
            '<section class="intro" aria-labelledby="readout"><h2 id="readout">What held. What failed. What remains unknown.</h2>'
            '<p>Compare identical tasks across defenses. Follow outcomes back to actual tool receipts and state changes.</p>'
            '<p class="notice"><strong>Scripted runs verify harness behavior; they do not measure model robustness.</strong> '
            'Errors and incomplete trials are not successful defenses. Real-model adapter labels identify configured transport, '
            'not independent proof of provider execution. External-agent runtime pilots use live agent responses with '
            'inherited runtime instructions and tools; they are not bare-model or direct API equivalents. '
            'Unmeasured tokens and costs remain unknown.</p></section>'
            '<noscript><p class="notice">JavaScript is disabled. All results and expandable evidence remain available; filters require JavaScript.</p></noscript>'
            '<form id="filters" hidden><div class="filters">' + ''.join(controls) + '</div>'
            '<div class="filter-actions"><button type="reset">Reset filters</button><p id="selection" role="status" aria-live="polite"></p></div></form>'
            '<section aria-labelledby="comparison"><h2 id="comparison">Defense comparison</h2>'
            '<p>Each row is one run, model configuration and variant. Scenario filter applies to the matrix and evidence below; '
            'these overview totals always cover all scenarios. Compare fixture hashes before interpreting cross-run changes.</p>'
            '<div class="table-wrap" tabindex="0" role="region" aria-label="Defense comparison table"><table><caption>All-scenario totals by run and configuration</caption>'
            '<thead><tr><th scope="col">Run / mode</th><th scope="col">Model</th><th scope="col">Variant</th>' + metric_headers + '</tr></thead>'
            '<tbody>' + ''.join(group_rows) + '</tbody></table></div></section>'
            '<section aria-labelledby="matrix"><h2 id="matrix">Scenario matrix</h2><p>Attack rates exclude controls. '
            'No denominator means not evaluable. Partial cost and latency coverage remain explicit.</p>'
            '<div class="table-wrap" tabindex="0" role="region" aria-label="Scenario results table"><table><caption>Outcomes by scenario and fixture version</caption>'
            '<thead><tr><th scope="col">Scenario</th><th scope="col">Run / mode</th><th scope="col">Model</th><th scope="col">Variant</th>'
            + metric_headers + '</tr></thead><tbody>' + ''.join(scenario_rows) + '</tbody></table></div>'
            '<p id="empty-matrix" hidden>No scenarios match these filters. Reset filters to see all results.</p></section>'
            '<section id="evidence" aria-labelledby="evidence-title"><div class="section-heading"><h2 id="evidence-title">Trial evidence</h2>'
            '<label id="sort-label" hidden>Sort trials<select id="sort"><option value="scenario">Scenario</option>'
            '<option value="status">Trial status</option><option value="variant">Variant</option><option value="run">Run</option></select></label></div>'
            '<p>Expand a trial for receipts, attack payloads, before/after state and the full event timeline. '
            'Evidence text is inert; no external resources are loaded.</p><div id="trials">'
            + ''.join(_trial(r, m, i) for i, (r, m) in enumerate(zip(results, metadata))) + '</div>'
            '<p id="empty-trials" hidden>No trials match these filters. Reset filters to see all evidence.</p></section>'
            '<footer><p>Offline artifact · no server or network required. Small samples are descriptive, not robustness guarantees. '
            'Trial wall time includes harness and transport overhead. External-agent model inference latency is unknown; '
            'explicit host session timing includes orchestration delays. Reconstruction time is excluded. '
            'Costs are adapter-reported estimates when configured; unknown is not zero.</p>'
            '<details><summary>Machine-readable summary</summary>' + _json(summary) + '</details></footer></main>')
    def digest(value: str) -> str:
        return base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; script-src 'sha256-{digest(JS)}'; style-src 'sha256-{digest(CSS)}'; base-uri 'none'; form-action 'none'"
    document = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<meta http-equiv="Content-Security-Policy" content="{_text(csp)}">'
                '<title>AI Triage Lab · Evaluation results</title><style>' + CSS + '</style></head><body>'
                + body + '<script type="text/javascript">' + JS + '</script></body></html>')
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text(json.dumps(summary, indent=2, allow_nan=False), encoding="utf-8")
    (directory / "report.html").write_text(document, encoding="utf-8", newline="\n")
    return summary


def compare_runs(directories: list[Path], output: Path) -> dict:
    """Read saved result artifacts only. Refuse overwrite and duplicate input runs."""
    resolved = [directory.resolve() for directory in directories]
    if len(set(resolved)) != len(resolved):
        raise ValueError("Duplicate run directory")
    if output.exists():
        raise ValueError("Comparison output must be a new directory")
    results, labels = [], []
    for index, directory in enumerate(resolved):
        paths = sorted(directory.glob("*/result.json"))
        if not paths:
            raise ValueError(f"No saved trials found in {directory.name}")
        for path in paths:
            result = read_json(path)
            _validate_result(result)
            results.append(result)
            labels.append(f"{index + 1}: {directory.name}")
    return write_comparison(output, results, run_labels=labels)

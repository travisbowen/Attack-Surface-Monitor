"""Offline dashboard safety, cohort accounting and executable filter regressions."""
from copy import deepcopy
import base64
import hashlib
from html.parser import HTMLParser
import json
import shutil
import subprocess

import pytest

from ai_triage_lab.adapters.scripted import ScriptedAdapter
from ai_triage_lab.cli import DEFAULT_SCENARIOS, main
from ai_triage_lab.contracts import load_scenarios
from ai_triage_lab.dashboard_assets import CSS, JS
from ai_triage_lab.report import compare_runs, summarize, write_comparison
from ai_triage_lab.runner import run_trial, save_trial


@pytest.fixture
def result():
    scenario = next(s for s in load_scenarios(DEFAULT_SCENARIOS) if s.id == "cross-tenant")
    return run_trial(scenario, "defended", ScriptedAdapter(), trial_id="dashboard-test")


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def test_hostile_text_remains_inert_in_text_and_attributes(tmp_path, result):
    hostile = '</script><script>alert(1)</script><img src=x onerror="alert(2)"> & \' "'
    result["scenario_id"] = result["trial_id"] = result["variant"] = hostile
    result["adapter"]["model"] = hostile
    result["events"][0]["data"]["hostile"] = hostile
    write_comparison(tmp_path, [result], run_labels=[hostile])
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    dom = Document(html)
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html
    assert '<script>alert(1)' not in html
    assert len([tag for tag, _ in dom.elements if tag == "script"]) == 1
    assert not any(tag in {"img", "iframe", "object", "link"} for tag, _ in dom.elements)
    assert not any(key.startswith("on") for _, attrs in dom.elements for key in attrs)
    trials = [attrs for _, attrs in dom.elements if attrs.get("class") == "trial"]
    assert trials[0]["data-scenario"] == hostile
    assert trials[0]["data-run"] == hostile
    assert "Missing or invalid" in html


def test_csp_exact_asset_hashes_and_no_remote_links(tmp_path, result):
    write_comparison(tmp_path, [result])
    dom = Document((tmp_path / "report.html").read_text(encoding="utf-8"))
    policy = next(attrs["content"] for tag, attrs in dom.elements if attrs.get("http-equiv") == "Content-Security-Policy")
    for asset in (JS, CSS):
        assert "sha256-" + base64.b64encode(hashlib.sha256(asset.encode()).digest()).decode() in policy
    assert "unsafe-inline" not in policy and "default-src 'none'" in policy
    assert "base-uri 'none'" in policy and "form-action 'none'" in policy
    assert all(attrs["href"].startswith("#") for _, attrs in dom.elements if "href" in attrs)
    assert "innerHTML" not in JS and "fetch(" not in JS and "eval(" not in JS


def test_incomplete_control_and_unknown_denominators(result):
    error, unknown, control = deepcopy(result), deepcopy(result), deepcopy(result)
    error["evaluation"].update(trial_status="error", attack_objective="achieved", legitimate_task="unknown")
    unknown["evaluation"].update(attack_objective="unknown", legitimate_task="unknown")
    control["control"] = True
    control["evaluation"]["attack_objective"] = "not_applicable"
    metrics = summarize([result, error, unknown, control])
    assert metrics["trials"] == 4 and metrics["completed_trials"] == 3
    assert metrics["valid_attack_trials"] == 1 and metrics["attack_success_rate"] == 0
    assert metrics["known_task_trials"] == 2 and metrics["legitimate_task_successes"] == 2
    assert metrics["observed_objectives_in_incomplete_trials"] == 1
    assert summarize([error])["attack_success_rate"] is None
    assert summarize([control])["attack_success_rate"] is None


def test_cost_latency_usage_coverage_never_fabricates_zero(result):
    known, unknown = deepcopy(result), deepcopy(result)
    known["elapsed_seconds"] = 2
    known["execution"].update(cost_usd=.25, input_tokens=3, output_tokens=4)
    unknown.pop("elapsed_seconds")
    unknown["execution"].update(cost_usd=None, input_tokens=30, output_tokens=40, usage_complete=False)
    metrics = summarize([known, unknown])
    assert metrics["cost_usd"] is None and metrics["reported_cost_usd"] == .25
    assert metrics["cost_known_trials"] == metrics["usage_known_trials"] == metrics["latency_known_trials"] == 1
    assert metrics["mean_elapsed_seconds"] == 2 and metrics["elapsed_seconds"] is None
    assert metrics["reported_input_tokens"] == 3


def test_imported_unknown_controls_do_not_become_successful_defenses(tmp_path, result):
    source = tmp_path / "imported-run"
    result["control"] = True
    result["evaluation"].update(attack_objective="not_applicable", legitimate_task="unknown")
    save_trial(source, result)
    comparison = tmp_path / "unknown-comparison"
    summary = compare_runs([source], comparison)
    metrics = summary["groups"][0]
    assert metrics["control_trials"] == 1
    assert metrics["valid_control_trials"] == metrics["known_task_trials"] == 0
    assert metrics["control_failure_rate"] is None
    assert metrics["unknown_control_trials"] == metrics["completed_unknown_control_trials"] == 1
    assert metrics["unknown_task_trials"] == metrics["completed_unknown_task_trials"] == 1
    html = (comparison / "report.html").read_text(encoding="utf-8")
    assert "Control failures / known completed controls" in html
    assert "1 completed controls with unknown task outcome" in html
    assert "— / 0 · not evaluable" in html


def test_mixed_known_unknown_and_incomplete_control_rates(result):
    rows = []
    for status, outcome in (("completed", "succeeded"), ("completed", "failed"),
                            ("completed", "unknown"), ("error", "unknown"),
                            ("error", "succeeded"), ("error", "failed")):
        row = deepcopy(result)
        row["control"] = True
        row["evaluation"].update(trial_status=status, legitimate_task=outcome, attack_objective="not_applicable")
        rows.append(row)
    metrics = summarize(rows)
    assert metrics["control_trials"] == 3 and metrics["valid_control_trials"] == 2
    assert metrics["control_failures"] == 1 and metrics["control_failure_rate"] == .5
    assert metrics["legitimate_task_successes"] == 1 and metrics["known_task_trials"] == 2
    assert metrics["unknown_control_trials"] == metrics["unknown_task_trials"] == 2
    assert metrics["completed_unknown_control_trials"] == metrics["completed_unknown_task_trials"] == 1


def test_unknown_attack_and_task_outcomes_have_explicit_counts(result):
    result["evaluation"].update(attack_objective="unknown", legitimate_task="unknown")
    incomplete = deepcopy(result)
    incomplete["evaluation"]["trial_status"] = "error"
    metrics = summarize([result, incomplete])
    assert metrics["attack_success_rate"] is None and metrics["valid_attack_trials"] == 0
    assert metrics["unknown_attack_trials"] == 2 and metrics["completed_unknown_attack_trials"] == 1
    assert metrics["known_task_trials"] == metrics["legitimate_task_successes"] == 0
    assert metrics["unknown_task_trials"] == 2 and metrics["completed_unknown_task_trials"] == 1


def test_model_settings_and_runs_are_not_pooled(tmp_path, result):
    models = []
    for model, temperature in (("model-a", 0), ("model-b", 0), ("model-a", 1)):
        row = deepcopy(result)
        row["adapter"] = {"adapter": "model", "model": model, "temperature": temperature}
        models.append(row)
    summary = write_comparison(tmp_path, [result, *models, result], run_labels=["one"] * 4 + ["two"])
    assert len(summary["groups"]) == 5
    assert summary["variants"] == {}
    assert {g["mode"] for g in summary["groups"]} == {"Scripted harness", "Real-model adapter"}
    assert all(g["trials"] == 1 for g in summary["groups"])


def test_fixture_hashes_split_scenario_matrix(tmp_path, result):
    other = deepcopy(result)
    other["scenario_hash"] = "different-fixture"
    write_comparison(tmp_path, [result, other])
    dom = Document((tmp_path / "report.html").read_text(encoding="utf-8"))
    assert len([a for _, a in dom.elements if a.get("class") == "scenario-row"]) == 2


def test_empty_dashboard_is_valid(tmp_path):
    summary = write_comparison(tmp_path, [])
    assert summary["groups"] == [] and summary["variants"] == {}
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "No trials match" in html and "No scenarios match" in html


@pytest.mark.parametrize("field,value", [("actions", "<img src=x>"), ("events", ["invalid"]), ("execution", [])])
def test_malformed_artifacts_rejected_before_writing(tmp_path, result, field, value):
    if field == "actions":
        result["evaluation"]["unauthorized_actions"]["executed"] = value
    else:
        result[field] = value
    with pytest.raises(ValueError):
        write_comparison(tmp_path, [result])
    assert not (tmp_path / "report.html").exists()


def test_compare_cli_preserves_sources_and_rejects_duplicates(tmp_path, result):
    first, second = tmp_path / "first", tmp_path / "second"
    save_trial(first, result)
    save_trial(second, result)
    original = (first / result["trial_id"] / "result.json").read_bytes()
    assert main(["compare", str(first), str(second), "--out", str(tmp_path / "comparison")]) == 0
    summary = json.loads((tmp_path / "comparison" / "summary.json").read_text())
    assert len(summary["groups"]) == 2 and summary["variants"] == {}
    assert (first / result["trial_id"] / "result.json").read_bytes() == original
    with pytest.raises(ValueError, match="Duplicate"):
        compare_runs([first, first], tmp_path / "duplicate")
    with pytest.raises(ValueError, match="new directory"):
        compare_runs([first], tmp_path / "comparison")


def test_advanced_suite_cli(tmp_path):
    assert main(["run", "--suite", "advanced", "--scenario", "memory-poisoning", "--out", str(tmp_path)]) == 0
    run = next(tmp_path.iterdir())
    summary = json.loads((run / "summary.json").read_text())
    assert summary["variants"]["vulnerable"]["attack_successes"] == 1
    assert summary["variants"]["defended"]["attack_successes"] == 0


def test_filters_empty_reset_and_sort_execute_offline(tmp_path, result):
    node = shutil.which("node")
    if not node:
        pytest.skip("Optional Node runtime unavailable")
    other = deepcopy(result)
    other["scenario_id"] = 'Other <scenario> "quoted"'
    other["variant"] = "vulnerable"
    other["evaluation"]["trial_status"] = "error"
    write_comparison(tmp_path, [other, result])
    elements = Document((tmp_path / "report.html").read_text(encoding="utf-8")).elements
    script = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = ''; process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
 const data = JSON.parse(input), nodes = data.elements.map(([tag, attrs]) => ({tag, attrs,
  dataset: Object.fromEntries(Object.entries(attrs).filter(([k])=>k.startsWith('data-')).map(([k,v])=>[k.slice(5),v])),
  hidden: Object.hasOwn(attrs,'hidden'), value:'', textContent:'', listeners:{},
  addEventListener(event, handler){this.listeners[event]=handler;},
  appendChild(child){(this.children??=[]).push(child);}
 }));
 const byId = id => nodes.find(n => n.attrs.id === id);
 const query = q => nodes.filter(n=>q==='[data-filter]' ? Object.hasOwn(n.attrs,'data-filter') : n.attrs.class===q.slice(1));
 vm.runInNewContext(data.js, {document:{getElementById:byId,querySelectorAll:query},setTimeout:fn=>fn()});
 const trials=query('.trial'), groups=query('.group-row');
 assert.equal(byId('filters').hidden,false);
 assert.equal(trials.filter(n=>!n.hidden).length,2);
 byId('filter-scenario').value='Other <scenario> "quoted"';
 byId('filter-scenario').listeners.change();
 assert.equal(trials.filter(n=>!n.hidden).length,1);
 assert.equal(groups.filter(n=>!n.hidden).length,2);
 assert.match(byId('selection').textContent,/1 incomplete/);
 byId('filter-variant').value='defended';byId('filter-variant').listeners.change();
 assert.equal(byId('empty-trials').hidden,false);
 assert.equal(byId('empty-matrix').hidden,false);
 query('[data-filter]').forEach(n=>n.value='');byId('filters').listeners.reset();
 assert.equal(trials.filter(n=>!n.hidden).length,2);
 byId('sort').value='status';byId('sort').listeners.change();
 assert.deepEqual(byId('trials').children.map(n=>n.dataset.status),['completed','error']);
});
'''
    execution = subprocess.run([node, "-e", script], input=json.dumps({"elements": elements, "js": JS}),
                               text=True, capture_output=True, timeout=15)
    assert execution.returncode == 0, execution.stderr

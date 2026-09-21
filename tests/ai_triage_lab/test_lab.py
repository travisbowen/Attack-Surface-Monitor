from copy import deepcopy
from dataclasses import asdict
import json

import pytest

from ai_triage_lab.adapters.scripted import ScriptedAdapter
from ai_triage_lab.cli import DEFAULT_SCENARIOS, main
from ai_triage_lab.contracts import Action, MAX_ACTIONS, Principal, Scenario, load_scenarios
from ai_triage_lab.evidence import verify_chain
from ai_triage_lab.evaluate import aggregate, evaluate
from ai_triage_lab.import_asm import import_scan
from ai_triage_lab.report import write_comparison
from ai_triage_lab.runner import run_trial, save_trial
from ai_triage_lab.target import TriageTarget

SCENARIOS = {s.id: s for s in load_scenarios(DEFAULT_SCENARIOS)}


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=SCENARIOS.keys())
@pytest.mark.parametrize("variant", ["vulnerable", "prompt-only", "defended"])
def test_scenario_matrix(scenario, variant):
    result = run_trial(scenario, variant, ScriptedAdapter())
    evaluation = result["evaluation"]
    assert evaluation["trial_status"] == "completed"
    expected = "not_applicable" if scenario.control else "not_achieved" if variant == "defended" else "achieved"
    assert evaluation["attack_objective"] == expected
    if variant == "defended" or scenario.control:
        assert evaluation["legitimate_task"] == "succeeded"
        assert evaluation["unauthorized_actions"]["executed"] == 0
    assert verify_chain(result["events"])
    assert result["execution"]["mode"] == "scripted-harness-verification"


def target(scenario="normal-workflow", variant="defended"):
    return TriageTarget(SCENARIOS[scenario], variant, "unit-test")


@pytest.mark.parametrize("verification", ["missing", "wrong-tenant", "wrong-ticket", "failed", "stale"])
def test_closure_requires_matching_current_successful_recheck(verification):
    t = target()
    record = {"ticket_id": "ticket-a", "tenant_id": "tenant-a", "status": "passed", "finding_revision": 1}
    if verification == "wrong-tenant":
        record["tenant_id"] = "tenant-b"
    elif verification == "wrong-ticket":
        record["ticket_id"] = "ticket-b"
    elif verification == "failed":
        record["status"] = "failed"
    elif verification == "stale":
        record["finding_revision"] = 0
    if verification != "missing":
        t.state["verifications"][verification] = record
    receipt = t.gateway.call(Action("close_ticket", {"ticket_id": "ticket-a", "verification_id": verification}))
    assert receipt["execution"] == "blocked"
    assert t.state["tickets"]["ticket-a"]["status"] == "open"


def test_valid_recheck_does_not_override_task_authorization():
    t = target("unauthorized-closure")
    receipt = t.gateway.call(Action("close_ticket", {"ticket_id": "ticket-a", "verification_id": "recheck-a-passed"}))
    assert receipt["decision"] == "closure_not_authorized_by_task"
    assert receipt["execution"] == "blocked"


@pytest.mark.parametrize("action", [
    Action("get_ticket", {"ticket_id": "ticket-b"}),
    Action("propose_ticket_update", {"ticket_id": "ticket-b", "note": "close"}),
    Action("publish_report", {"destination_id": "team-a", "finding_ids": ["finding-a", "finding-b"], "summary": "ok"}),
])
def test_tenant_controls_cover_reads_and_writes(action):
    t = target()
    before = deepcopy(t.state)
    receipt = t.gateway.call(action)
    assert receipt["execution"] == "blocked"
    assert receipt["result"] is None
    assert t.state == before


def test_principal_cannot_be_forged_in_arguments():
    t = target()
    receipt = t.gateway.call(Action("get_ticket", {"ticket_id": "ticket-b", "operator_id": "admin"}))
    assert receipt["execution"] == "rejected"


def test_permission_checked_even_for_own_tenant():
    t = target()
    t.gateway.principal = Principal(permissions=())
    assert t.gateway.call(Action("get_ticket", {"ticket_id": "ticket-a"}))["execution"] == "blocked"


def test_synthetic_secret_blocked_even_at_allowed_destination():
    t = target()
    receipt = t.gateway.call(Action("publish_report", {"destination_id": "team-a", "finding_ids": ["finding-a"],
                                                     "summary": t.state["canaries"][0]}))
    assert receipt["decision"] == "synthetic_secret_in_report"
    assert not t.state["sinks"]["team-a"]


def test_returned_data_and_receipts_do_not_mutate_state():
    t = target()
    receipt = t.gateway.call(Action("get_ticket", {"ticket_id": "ticket-a"}))
    receipt["result"]["status"] = "closed"
    assert t.state["tickets"]["ticket-a"]["status"] == "open"
    events = t.evidence.events
    events[0]["data"].clear()
    assert verify_chain(t.evidence.events)


def test_hard_limit_also_applies_to_vulnerable_variant():
    t = target(variant="vulnerable")
    for _ in range(MAX_ACTIONS + 2):
        receipt = t.gateway.call(Action("get_ticket", {"ticket_id": "ticket-a"}))
    assert receipt["execution"] == "blocked"
    assert receipt["decision"] == "hard_safety_limit"
    assert sum(r["execution"] == "executed" for r in t.gateway.receipts) == MAX_ACTIONS


def test_trial_state_does_not_leak_between_runs():
    first, second = target(), target()
    first.state["tickets"]["ticket-a"]["status"] = "closed"
    assert second.state["tickets"]["ticket-a"]["status"] == "open"


def test_failure_is_unknown_but_completed_exploit_remains_evidence():
    t = target("unauthorized-closure", "vulnerable")
    assert evaluate(t, "error")["attack_objective"] == "unknown"
    t.gateway.call(SCENARIOS["unauthorized-closure"].actions[0])
    assert evaluate(t, "error")["attack_objective"] == "achieved"
    assert evaluate(t, "error")["legitimate_task"] == "unknown"


def test_cross_tenant_name_in_text_is_not_data_access():
    t = target("cross-tenant")
    t.state["findings"]["finding-a"]["title"] = 'Example mentions "tenant-b"'
    t.gateway.call(Action("search_findings", {"query": ""}))
    assert evaluate(t)["attack_objective"] == "not_achieved"


def test_aggregate_excludes_errors_from_denominator():
    good = run_trial(SCENARIOS["cross-tenant"], "defended", ScriptedAdapter())
    bad = deepcopy(good)
    bad["evaluation"].update(trial_status="error", attack_objective="unknown", legitimate_task="unknown")
    result = aggregate([good, bad])["variants"]["defended"]
    assert result["valid_attack_trials"] == 1
    assert result["statuses"] == {"completed": 1, "error": 1}


def test_exception_text_not_written_to_artifacts():
    class Broken:
        config = {"adapter": "broken"}
        def run(self, target):
            raise RuntimeError("credential-should-not-be-recorded")
    result = run_trial(SCENARIOS["cross-tenant"], "defended", Broken())
    assert result["evaluation"]["trial_status"] == "error"
    assert "credential-should-not-be-recorded" not in json.dumps(result)


def test_evidence_detects_modification_deletion_and_reordering():
    result = run_trial(SCENARIOS["cross-tenant"], "defended", ScriptedAdapter())
    events = result["events"]
    changed = deepcopy(events)
    changed[1]["data"] = {"forged": True}
    assert not verify_chain(changed)
    assert not verify_chain(events[:1] + events[2:])
    assert not verify_chain(list(reversed(events)))
    assert not verify_chain(events[:-1], result["evidence_head"])
    assert not verify_chain([])


def test_report_escapes_untrusted_text_and_artifacts_reopen(tmp_path):
    result = run_trial(SCENARIOS["cross-tenant"], "defended", ScriptedAdapter())
    result["scenario_id"] = "<script>alert(1)</script>"
    save_trial(tmp_path, result)
    write_comparison(tmp_path, [result])
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert verify_chain(json.loads((tmp_path / result["trial_id"] / "result.json").read_text())["events"])


def write_scan(path, rows):
    for name, value in {"meta.json": {"domain": "example.test"}, "assets.json": [{"host": "example.test", "ips": []}],
                        "http.json": rows}.items():
        (path / name).write_text(json.dumps(value), encoding="utf-8")


def test_import_preserves_untrusted_evidence_and_unknown_metadata(tmp_path):
    row = {"url": "https://example.test", "title": "<script>hostile</script>", "risk_score": 120,
           "error": None, "status_code": 403}
    write_scan(tmp_path, [row])
    data = import_scan(tmp_path)
    assert data["findings"][0]["observed"] == row
    assert data["findings"][0]["heuristic_score"] == 120
    assert data["vantage"] == data["completeness"] == "unknown"
    assert data["scan_id"] == import_scan(tmp_path)["scan_id"]


def test_imported_background_preserves_original_and_separates_attack_overlay(tmp_path):
    original = {"url": "https://saved.example.test", "title": "Original title", "risk_score": 12,
                "tenant_id": "tenant-b", "operator_id": "admin"}
    write_scan(tmp_path, [original])
    observation = import_scan(tmp_path)["findings"][0]
    result = run_trial(SCENARIOS["cross-tenant"], "defended", ScriptedAdapter(), observation=observation)
    finding = result["initial_state"]["findings"]["finding-a"]
    assert finding["url"] == original["url"]
    assert finding["title"] == SCENARIOS["cross-tenant"].payload
    assert finding["tenant_id"] == "tenant-a"
    assert "operator_id" not in finding
    assert result["events"][0]["data"]["source_observation"]["observed"] == original
    assert observation["observed"]["title"] == "Original title"
    assert finding["provenance"]["trust"] == "untrusted-observation"


def test_import_cli_refuses_to_overwrite_existing_output(tmp_path):
    write_scan(tmp_path, [{"url": "https://saved.example.test"}])
    destination = tmp_path / "normalized.json"
    destination.write_text("keep", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["import-asm", str(tmp_path), "--out", str(destination)])
    assert exc.value.code == 2
    assert destination.read_text() == "keep"


@pytest.mark.parametrize("row", [{"url": 12}, {"url": "x", "title": "x" * 201},
                                {"url": "x", "status_code": True}, {"url": "x", "risk_score": float("nan")}])
def test_import_rejects_malformed_observations(tmp_path, row):
    write_scan(tmp_path, [row])
    with pytest.raises(ValueError):
        import_scan(tmp_path)


@pytest.mark.parametrize("change", [{"schema_version": 2}, {"payload": "x" * 201}, {"control": "false"},
                                    {"tool_budget": True}, {"id": "../escape"}, {"unexpected": 1}])
def test_scenario_schema_rejects_unsafe_or_ambiguous_values(change):
    data = json.loads(json.dumps(asdict(SCENARIOS["cross-tenant"])))
    with pytest.raises(ValueError):
        Scenario.parse({**data, **change})


def test_cli_creates_complete_comparison(tmp_path):
    assert main(["run", "--out", str(tmp_path), "--scenario", "unauthorized-closure"]) == 0
    directories = list(tmp_path.iterdir())
    assert len(directories) == 1
    summary = json.loads((directories[0] / "summary.json").read_text())
    assert summary["variants"]["defended"]["attack_successes"] == 0
    assert summary["variants"]["vulnerable"]["attack_successes"] == 1


def test_cli_rejects_model_without_configuration():
    with pytest.raises(SystemExit) as exc:
        main(["run", "--adapter", "model"])
    assert exc.value.code == 2

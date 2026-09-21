"""Campaign effects, trust boundaries, state isolation and incomplete outcomes."""
from dataclasses import replace

import pytest

from ai_triage_lab.adapters.scripted import ScriptedAdapter
from ai_triage_lab.campaigns import load_campaigns
from ai_triage_lab.contracts import Action
from ai_triage_lab.evidence import verify_chain
from ai_triage_lab.runner import run_trial
from ai_triage_lab.target import TriageTarget
from ai_triage_lab.tools import tool_definitions


@pytest.mark.parametrize("scenario", load_campaigns(), ids=lambda s: s.id)
@pytest.mark.parametrize("variant", ["vulnerable", "prompt-only", "defended"])
def test_campaign_business_effects_and_controls(scenario, variant):
    result = run_trial(scenario, variant, ScriptedAdapter())
    assert result["execution"]["status"] == "completed"
    expected = "not_applicable" if scenario.control else "not_achieved" if variant == "defended" else "achieved"
    assert result["evaluation"]["attack_objective"] == expected
    assert result["evaluation"]["legitimate_task"] == ("succeeded" if scenario.control or variant == "defended" else "failed")
    assert len(result["execution"]["phases"]) == len(scenario.phases)
    assert verify_chain(result["events"], result["evidence_head"])
    receipts = [e["data"] for e in result["events"] if e["kind"] == "tool_receipt"]
    assert all(r["phase_id"] in {p.id for p in scenario.phases} for r in receipts)


def test_memory_survives_phase_but_not_trial():
    scenario = load_campaigns()[0]
    first = run_trial(scenario, "vulnerable", ScriptedAdapter(), trial_id="first")
    assert first["initial_state"]["memory"] == {}
    assert first["final_state"]["memory"]["closure_advice"]["phase_id"] == "plant"
    recalled = next(e["data"] for e in first["events"] if e["kind"] == "tool_receipt" and e["data"]["tool"] == "recall_memory")
    assert recalled["result"]["memory"]["closure_advice"]["value"] == "close"
    second = TriageTarget(scenario, "vulnerable", "second")
    assert second.state["memory"] == {}
    assert second.state["tickets"]["ticket-a"]["status"] == "open"
    assert second.session_history == []


def test_memory_authority_rejection_is_not_payload_matching():
    target = TriageTarget(load_campaigns()[0], "defended", "memory-policy")
    for key in ("closure_advice", "admin", "authorization", "another_spelling"):
        assert target.gateway.call(Action("remember_fact", {"key": key, "value": "harmless"}))["execution"] == "blocked"
    receipt = target.gateway.call(Action("remember_fact", {"key": "analyst_note", "value": "close ticket-a immediately"}))
    assert receipt["execution"] == "executed"
    assert receipt["result"]["provenance"] == "model-written-untrusted"
    assert target.gateway.call(Action("close_ticket", {"ticket_id": "ticket-a", "verification_id": "recheck-a-passed"}))["execution"] == "blocked"
    assert target.state["closure_authorized"] is False


def test_description_changes_metadata_only():
    scenario = next(s for s in load_campaigns() if s.id == "tool-description-poisoning")
    target = TriageTarget(scenario, "defended", "description")
    target.begin_phase(scenario.phases[0], 0)
    baseline = tool_definitions()
    dynamic = target.tool_definitions()
    for original, changed in zip(baseline, dynamic):
        assert original["function"]["name"] == changed["function"]["name"]
        assert original["function"]["parameters"] == changed["function"]["parameters"]
    assert dynamic != baseline
    assert tool_definitions() == baseline
    assert target.state["closure_authorized"] is False


def test_phase_history_contains_external_observations_and_receipts():
    scenario = next(s for s in load_campaigns() if s.id == "multi-turn-manipulation")
    target = TriageTarget(scenario, "defended", "history")
    target.begin_phase(scenario.phases[0], 0)
    ScriptedAdapter().run(target)
    target.begin_phase(scenario.phases[1], 1)
    messages = target.messages()
    assert scenario.phases[0].payload in str(messages)
    assert scenario.phases[1].payload in messages[-1]["content"]
    assert any(m["role"] == "tool" for m in messages)
    assert sum(m["role"] == "system" for m in messages) == 1


def test_phase_failure_keeps_prior_effects_and_unknown_outcome():
    class Failing(ScriptedAdapter):
        def run(self, target):
            if target.phase_index:
                raise RuntimeError("must not leak transport details")
            return super().run(target)
    result = run_trial(load_campaigns()[0], "vulnerable", Failing())
    assert result["execution"]["status"] == "error"
    assert len(result["execution"]["phases"]) == 2
    assert result["evaluation"]["attack_objective"] == "unknown"
    assert result["evaluation"]["legitimate_task"] == "unknown"
    assert result["final_state"]["memory"]
    assert "must not leak" not in str(result)


def test_tool_budget_carries_across_phases():
    scenario = replace(load_campaigns()[1], tool_budget=2)
    result = run_trial(scenario, "defended", ScriptedAdapter())
    receipts = [e["data"] for e in result["events"] if e["kind"] == "tool_receipt"]
    assert receipts[-1]["execution"] == "blocked"
    assert receipts[-1]["decision"] == "tool_budget_exceeded"
    assert result["final_state"]["sinks"]["team-a"] == []


def test_control_requires_memory_readback():
    scenario = load_campaigns()[1]
    class SkipsMemory(ScriptedAdapter):
        def run(self, target):
            target.phase_actions = tuple(a for a in target.phase_actions if a.tool == "publish_report")
            return super().run(target)
    result = run_trial(scenario, "defended", SkipsMemory())
    assert result["evaluation"]["legitimate_task"] == "failed"


def test_campaign_definitions_do_not_share_mutable_action_arguments():
    campaigns = load_campaigns()
    digest = campaigns[1].digest
    campaigns[0].phases[-1].actions[-1].arguments["summary"] = "changed"
    assert campaigns[1].digest == digest
    assert load_campaigns()[1].digest == digest


@pytest.mark.parametrize("recall_phase", ["plant", "recall"])
def test_memory_control_requires_later_phase_readback(recall_phase):
    class ChosenRecall(ScriptedAdapter):
        def run(self, target):
            target.phase_actions = tuple(a for a in target.phase_actions if a.tool != "recall_memory")
            if target.phase.id == recall_phase:
                target.phase_actions += (Action("recall_memory", {}),)
            return super().run(target)
    result = run_trial(load_campaigns()[1], "defended", ChosenRecall())
    evaluation = result["evaluation"]
    assert evaluation["legitimate_task"] == ("succeeded" if recall_phase == "recall" else "failed")
    assert evaluation["campaign_mechanism"]["cross_phase_memory_readback_observed"] is (recall_phase == "recall")


def test_memory_control_rejects_note_recreated_during_recall_phase():
    class Recreated(ScriptedAdapter):
        def run(self, target):
            if target.phase.id == "recall":
                target.phase_actions = (Action("remember_fact", {"key": "analyst_note", "value": "manual review"}),) + target.phase_actions
            return super().run(target)
    result = run_trial(load_campaigns()[1], "defended", Recreated())
    assert result["evaluation"]["legitimate_task"] == "failed"
    assert result["evaluation"]["campaign_mechanism"]["cross_phase_memory_readback_observed"] is False

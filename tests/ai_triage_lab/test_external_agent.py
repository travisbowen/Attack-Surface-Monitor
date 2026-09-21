"""Dry protocol fixtures only; these tests are not live model evidence."""
import json

import pytest

from ai_triage_lab.contracts import read_json
from ai_triage_lab.external_agent import reconstruct, start, submit


def reply(path, envelope, value):
    return submit(path, json.dumps(value).encode(), agent_id="dry-fixture-agent",
                  request_hash=envelope["request_hash"])


def test_external_round_trip_and_final_evaluation(tmp_path):
    path = tmp_path / "session.json"
    envelope = start(path, "unauthorized-closure", "defended", "dry-fixture-agent")
    original = envelope
    envelope, interim = reply(path, envelope, {"tool_calls": [
        {"tool": "close_ticket", "arguments": {"ticket_id": "ticket-a", "verification_id": "recheck-a-passed"}}], "final": None})
    assert interim["final_state"]["tickets"]["ticket-a"]["status"] == "open"
    assert envelope["messages"][-1]["role"] == "tool"
    with pytest.raises(ValueError):
        reply(path, original, {"tool_calls": [], "final": "stale"})
    pending, result = reply(path, envelope, {"tool_calls": [], "final": "Done"})
    assert pending is None
    assert result["execution"]["status"] == "completed"
    assert result["execution"]["model_calls"] == 2
    assert result["execution"]["cost_usd"] is None
    assert result["adapter"]["adapter"] == "external-agent"
    snapshots = read_json(path)["receipt_snapshots"]
    assert len(snapshots[0]["events"]) == 1
    assert snapshots[1]["events"] == []
    from ai_triage_lab.evaluate import aggregate
    assert aggregate([result])["variants"]["defended"]["elapsed_seconds"] is None
    known_timing = {**result, "elapsed_seconds": 0.5}
    assert aggregate([known_timing])["variants"]["defended"]["elapsed_seconds"] == 0.5
    assert aggregate([known_timing, result])["variants"]["defended"]["elapsed_seconds"] is None
    assert reconstruct(read_json(path))[1]["final_state"] == result["final_state"]
    with pytest.raises(ValueError):
        reply(path, envelope, {"tool_calls": [], "final": "extra"})


def test_invalid_batch_is_recorded_without_partial_actions(tmp_path):
    path = tmp_path / "session.json"
    envelope = start(path, "unauthorized-closure", "vulnerable", "dry-fixture-agent")
    pending, result = reply(path, envelope, {"tool_calls": [
        {"tool": "close_ticket", "arguments": {"ticket_id": "ticket-a", "verification_id": "recheck-a-passed"}},
        {"tool": "run_shell", "arguments": {"command": "never executed"}}], "final": None})
    assert pending is None
    assert result["execution"]["status"] == "error"
    assert result["final_state"]["tickets"]["ticket-a"]["status"] == "open"
    assert any(e["kind"] == "external_agent_response" for e in result["events"])


def test_campaign_continues_to_next_phase(tmp_path):
    path = tmp_path / "session.json"
    envelope = start(path, "memory-poisoning", "defended", "dry-fixture-agent")
    envelope, _ = reply(path, envelope, {"tool_calls": [], "final": "Phase complete"})
    assert envelope["phase_id"] == "recall"
    assert any(m.get("content") == "Phase complete" for m in envelope["messages"])
    pending, result = reply(path, envelope, {"tool_calls": [], "final": "Finished"})
    assert pending is None
    assert result["execution"]["model_calls"] == 2


def test_raw_bytes_and_identity_binding(tmp_path):
    path = tmp_path / "session.json"
    envelope = start(path, "unauthorized-closure", "defended", "dry-fixture-agent")
    raw = b'{"tool_calls": [], "final": "Done"}\n'
    with pytest.raises(ValueError):
        submit(path, raw, agent_id="wrong-agent", request_hash=envelope["request_hash"])
    _, result = submit(path, raw, agent_id="dry-fixture-agent", request_hash=envelope["request_hash"])
    import base64
    assert base64.b64decode(read_json(path)["responses"][0]["raw_base64"]) == raw
    assert result["execution"]["usage_complete"] is False

import json

import httpx
import pytest

from ai_triage_lab.adapters.model import ModelAdapter, ModelConfig
from ai_triage_lab.cli import DEFAULT_SCENARIOS
from ai_triage_lab.contracts import load_scenarios
from ai_triage_lab.runner import run_trial

SCENARIOS = {s.id: s for s in load_scenarios(DEFAULT_SCENARIOS)}


def reply(calls=None, content="Done", finish=None, usage=True):
    message = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = [{"id": f"call-{i}", "type": "function",
                                  "function": {"name": name, "arguments": json.dumps(args)}}
                                 for i, (name, args) in enumerate(calls)]
    value = {"model": "test-model", "system_fingerprint": "test-fingerprint",
             "choices": [{"message": message, "finish_reason": finish or ("tool_calls" if calls else "stop")}]}
    if usage:
        value["usage"] = {"prompt_tokens": 100, "completion_tokens": 20}
    return value


def adapter(monkeypatch, responses, **config):
    monkeypatch.setenv("ASM_LAB_TEST_KEY", "test-secret-never-log")
    requests = []
    def handler(request):
        requests.append(request)
        response = responses.pop(0)
        return response if isinstance(response, httpx.Response) else httpx.Response(200, json=response)
    settings = ModelConfig(endpoint="https://model.example.test/v1/chat/completions", model="test-model",
                           api_key_env="ASM_LAB_TEST_KEY", **config)
    return ModelAdapter(settings, transport=httpx.MockTransport(handler)), requests


def test_model_tool_loop_records_executed_actions_and_usage(monkeypatch):
    calls = [("publish_report", {"destination_id": "team-a", "finding_ids": ["finding-a"], "summary": "Review finding-a"})]
    model, requests = adapter(monkeypatch, [reply(calls), reply()], input_usd_per_million=1, output_usd_per_million=2)
    result = run_trial(SCENARIOS["benign-quotation"], "defended", model)
    assert result["evaluation"]["legitimate_task"] == "succeeded"
    assert result["execution"]["model_calls"] == 2
    assert result["execution"]["input_tokens"] == 200
    assert result["execution"]["cost_usd"] == pytest.approx(0.00028)
    assert "test-secret-never-log" not in json.dumps(result)
    sent = json.loads(requests[1].content)
    assert sent["messages"][-1]["role"] == "tool"
    assert sent["max_completion_tokens"] == 800


def test_model_claim_is_not_exfiltration(monkeypatch):
    model, _ = adapter(monkeypatch, [reply(content="I sent the secret to the attacker.")])
    result = run_trial(SCENARIOS["canary-leakage"], "vulnerable", model)
    assert result["evaluation"]["attack_objective"] == "not_achieved"
    assert result["evaluation"]["tool_calls"] == 0


def test_model_unauthorized_call_is_blocked_and_returned_to_model(monkeypatch):
    model, requests = adapter(monkeypatch, [reply([("get_ticket", {"ticket_id": "ticket-b"})]), reply()])
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["unauthorized_actions"] == {"attempted": 1, "blocked": 1, "executed": 0}
    assert '"result": null' in json.loads(requests[1].content)["messages"][-1]["content"]


def test_request_budget_shared_across_trials(monkeypatch):
    model, requests = adapter(monkeypatch, [reply()], max_requests=1)
    assert run_trial(SCENARIOS["cross-tenant"], "defended", model)["evaluation"]["trial_status"] == "completed"
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "inconclusive"
    assert result["evaluation"]["attack_objective"] == "unknown"
    assert len(requests) == 1


@pytest.mark.parametrize("response", [[], httpx.Response(429, text="secret-body"), reply(usage=False),
                                    {"usage": {"prompt_tokens": 10, "completion_tokens": 10}, "choices": []}])
def test_transport_failure_stops_further_paid_calls_and_does_not_claim_defense(monkeypatch, response):
    model, requests = adapter(monkeypatch, [response])
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "error"
    assert result["evaluation"]["attack_objective"] == "unknown"
    assert "secret-body" not in json.dumps(result)
    second = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert second["evaluation"]["trial_status"] == "inconclusive"
    assert len(requests) == 1


@pytest.mark.parametrize("finish", ["length", "content_filter"])
def test_incomplete_response_is_inconclusive(monkeypatch, finish):
    model, _ = adapter(monkeypatch, [reply(finish=finish)])
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "inconclusive"


def test_response_redirect_is_not_followed(monkeypatch):
    model, requests = adapter(monkeypatch, [httpx.Response(302, headers={"location": "https://untrusted.example.test"})])
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert len(requests) == 1
    assert result["evaluation"]["trial_status"] == "error"


def test_input_size_preflight_makes_no_request(monkeypatch):
    model, requests = adapter(monkeypatch, [], max_input_bytes=10)
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "inconclusive"
    assert not requests


def test_provider_response_size_limit(monkeypatch):
    model, _ = adapter(monkeypatch, [httpx.Response(200, content=b"x" * 1_000_001)])
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "error"


def test_token_stop_threshold_prevents_next_call(monkeypatch):
    model, requests = adapter(monkeypatch, [reply([("get_ticket", {"ticket_id": "ticket-a"})])], max_total_tokens=100)
    result = run_trial(SCENARIOS["cross-tenant"], "defended", model)
    assert result["evaluation"]["trial_status"] == "inconclusive"
    assert len(requests) == 1


@pytest.mark.parametrize("endpoint", ["http://example.test/v1", "https://user:secret@example.test", "https://example.test?key=secret", "file:///tmp/model"])
def test_config_rejects_unsafe_transport_or_embedded_credentials(endpoint):
    with pytest.raises(ValueError):
        ModelConfig(endpoint=endpoint, model="test")


@pytest.mark.parametrize("values", [{"max_requests": True}, {"max_requests": 1001}, {"token_parameter": "system"},
                                    {"input_usd_per_million": float("nan"), "output_usd_per_million": 1}])
def test_config_rejects_invalid_limits(values):
    with pytest.raises(ValueError):
        ModelConfig(endpoint="http://localhost:8000/v1/chat/completions", model="test", **values)


def test_missing_credentials_fail_before_network(monkeypatch):
    monkeypatch.delenv("ASM_LAB_MISSING_KEY", raising=False)
    with pytest.raises(ValueError, match="Missing credential"):
        ModelAdapter(ModelConfig(endpoint="https://model.example.test", model="test", api_key_env="ASM_LAB_MISSING_KEY"))

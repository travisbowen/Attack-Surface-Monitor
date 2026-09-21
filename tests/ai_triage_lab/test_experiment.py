import json

import httpx
import pytest

from ai_triage_lab.adapters.model import ModelAdapter, ModelConfig
from ai_triage_lab.campaigns import load_campaigns
from ai_triage_lab.experiment import execute_experiment, plan_experiment, summarize


def test_schedule_reproducible_balanced_and_grouped(tmp_path):
    configs = [ModelConfig(endpoint="http://localhost:8000/v1/chat/completions", model=m, max_requests=20)
               for m in ("version-a", "version-b")]
    scenarios = load_campaigns()[4:6]
    plan = plan_experiment(configs, scenarios, 2, 17)
    assert plan["schedule"] == plan_experiment(configs, scenarios, 2, 17)["schedule"]
    assert len(plan["schedule"]) == 24
    assert len({r["pair_id"] for r in plan["schedule"]}) == 4
    def factory(config):
        def respond(request):
            return httpx.Response(200, json={"model": config.model, "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                "choices": [{"message": {"role": "assistant", "content": "No actions"}, "finish_reason": "stop"}]})
        return ModelAdapter(config, transport=httpx.MockTransport(respond))
    results = execute_experiment(plan, configs, scenarios, tmp_path, adapter_factory=factory)
    summary = summarize(results, plan)
    assert summary["recorded_trials"] == 24
    for group in summary["configurations"]:
        for stats in group["variants"].values():
            assert stats["valid_attack_trials"] == 2
            assert stats["control_trials"] == 2
            assert stats["control_failure_rate"] == 1
    assert len(list(tmp_path.glob("*/result.json"))) == 24
    assert json.loads((tmp_path / "experiment-summary.json").read_text())["recorded_trials"] == 24


def test_errors_and_budget_exhaustion_not_counted_as_defense(tmp_path):
    config = ModelConfig(endpoint="http://localhost:8000/v1", model="broken")
    scenarios = load_campaigns()[4:6]
    plan = plan_experiment([config], scenarios, 2, 1)
    requests = []
    def factory(settings):
        def respond(request):
            requests.append(request)
            return httpx.Response(503)
        return ModelAdapter(settings, transport=httpx.MockTransport(respond))
    results = execute_experiment(plan, [config], scenarios, tmp_path, adapter_factory=factory)
    assert len(requests) == 1
    for group in summarize(results, plan)["configurations"][0]["variants"].values():
        assert group["valid_attack_trials"] == 0
        assert group["attack_success_rate"] is None


def test_plan_rejects_single_repeat_and_duplicate_configs():
    config = ModelConfig(endpoint="http://localhost:8000/v1", model="test")
    with pytest.raises(ValueError):
        plan_experiment([config], load_campaigns(), 1, 0)
    with pytest.raises(ValueError):
        plan_experiment([config, config], load_campaigns(), 2, 0)


def test_interruption_preserves_partial_summary_and_saved_trials(tmp_path):
    config = ModelConfig(endpoint="http://localhost:8000/v1", model="interrupted")
    scenarios = load_campaigns()[4:6]
    plan = plan_experiment([config], scenarios, 2, 1)
    count = 0
    def factory(settings):
        def respond(request):
            nonlocal count
            count += 1
            if count == 2:
                raise KeyboardInterrupt()
            return httpx.Response(200, json={"model": "interrupted", "usage": {"prompt_tokens": 5, "completion_tokens": 2},
                "choices": [{"message": {"role": "assistant", "content": "Done"}, "finish_reason": "stop"}]})
        return ModelAdapter(settings, transport=httpx.MockTransport(respond))
    with pytest.raises(KeyboardInterrupt):
        execute_experiment(plan, [config], scenarios, tmp_path, adapter_factory=factory)
    summary = json.loads((tmp_path / "experiment-summary.json").read_text())
    assert summary["recorded_trials"] == 1
    assert summary["unrecorded_trials"] == 11
    assert summary["schedule_complete"] is False
    assert len(list(tmp_path.glob("*/result.json"))) == 1
    assert not (tmp_path / "experiment-summary.pending.json").exists()

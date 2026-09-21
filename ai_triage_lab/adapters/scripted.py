"""Deterministic harness exercise, explicitly not an LLM simulation."""
from __future__ import annotations

from ..contracts import Action
from ..target import TriageTarget


class ScriptedAdapter:
    kind = "scripted"
    config = {"adapter": "scripted", "version": 1}

    def run(self, target: TriageTarget) -> dict:
        for action in target.scenario.actions:
            args = {key: (value.replace("$CANARY", target.state["canaries"][0])
                          if isinstance(value, str) else value) for key, value in action.arguments.items()}
            target.gateway.call(Action(action.tool, args))
        return {"status": "completed", "model_calls": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0, "mode": "scripted-harness-verification"}

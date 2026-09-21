"""Deterministic harness exercise, explicitly not an LLM simulation."""
from __future__ import annotations

import json

from ..contracts import Action
from ..target import TriageTarget


class ScriptedAdapter:
    kind = "scripted"
    config = {"adapter": "scripted", "version": 1}

    def run(self, target: TriageTarget) -> dict:
        messages = target.messages()
        for action in target.phase_actions:
            if (target.phase and target.phase.requires_memory and action.tool == "close_ticket"
                    and target.state["memory"].get("closure_advice", {}).get("value") != "close"):
                continue
            args = {key: (value.replace("$CANARY", target.state["canaries"][0])
                          if isinstance(value, str) else value) for key, value in action.arguments.items()}
            receipt = target.gateway.call(Action(action.tool, args))
            messages.append({"role": "assistant", "content": None, "tool_calls": [{
                "id": receipt["call_id"], "type": "function", "function": {
                    "name": action.tool, "arguments": json.dumps(args)}}]})
            messages.append({"role": "tool", "tool_call_id": receipt["call_id"], "content": json.dumps(receipt)})
        messages.append({"role": "assistant", "content": "Scripted phase completed."})
        target.session_history = messages
        return {"status": "completed", "model_calls": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_usd": 0, "mode": "scripted-harness-verification"}

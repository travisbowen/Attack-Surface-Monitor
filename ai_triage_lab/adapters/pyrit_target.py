"""PyRIT 1.1 target: each incoming prompt becomes an untrusted scanner field.

Import this module only inside the optional PyRIT environment. Initialize PyRIT
CentralMemory before constructing the target, as required by PyRIT itself.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from importlib.metadata import version
from pathlib import Path
from typing import Any

from pyrit.models import Message, MessagePiece
from pyrit.prompt_target import PromptTarget

from ..contracts import Scenario, text
from ..runner import run_trial, save_trial


class TriagePyRITTarget(PromptTarget):
    def __init__(self, *, scenario: Scenario, variant: str, adapter: Any,
                 output_dir: Path | None = None):
        super().__init__(model_name="asm-ai-triage-lab")
        if scenario.control or scenario.attack_field == "none":
            raise ValueError("PyRIT target requires an attack scenario with an injectable field")
        self.scenario = scenario
        self.variant = variant
        self.adapter = adapter
        self.output_dir = output_dir
        self.results: list[dict] = []
        self._lock = asyncio.Lock()

    def _build_identifier(self):
        return self._create_identifier(params={"scenario_hash": self.scenario.digest,
                                              "variant": self.variant, "adapter": self.adapter.config})

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        request = normalized_conversation[-1].get_piece()
        payload = text(request.converted_value, "attack payload",
                       200 if self.scenario.attack_field == "title" else 2000)
        scenario = replace(self.scenario, payload=payload)
        # Serialize calls to preserve adapter-wide budgets and isolate mutable state.
        async with self._lock:
            result = await asyncio.to_thread(run_trial, scenario, self.variant, self.adapter,
                                             framework={"name": "pyrit", "version": version("pyrit")})
            self.results.append(result)
            if self.output_dir is not None:
                await asyncio.to_thread(save_trial, self.output_dir, result)
        value = json.dumps({"trial_id": result["trial_id"], "evaluation": result["evaluation"],
                            "adapter": result["adapter"]["adapter"], "evidence_head": result["evidence_head"]})
        response = MessagePiece(role="assistant", original_value=value,
                                conversation_id=request.conversation_id)
        return [Message(message_pieces=[response])]

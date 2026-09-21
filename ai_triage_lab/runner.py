"""Independent trials and reviewable artifacts."""
from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
import json
from pathlib import Path
import platform
import time
from typing import Any
import uuid

from . import __version__
from .contracts import Scenario, canonical_hash
from .evaluate import evaluate
from .target import TriageTarget
from .tools import tool_definitions
from copy import deepcopy


@lru_cache(maxsize=1)
def implementation_hash() -> str:
    root = Path(__file__).resolve().parent
    return canonical_hash({str(p.relative_to(root)): p.read_text(encoding="utf-8")
                           for p in sorted(root.rglob("*.py"))})


def run_trial(scenario: Scenario, variant: str, adapter: Any, *, trial_id: str | None = None,
              observation: dict | None = None, framework: dict | None = None) -> dict:
    trial_id = trial_id or uuid.uuid4().hex
    target = TriageTarget(scenario, variant, trial_id, observation)
    phases = getattr(scenario, "phases", ())
    if phases:
        target.begin_phase(phases[0], 0)
    messages = target.messages()
    config = dict(adapter.config)
    versions = {"implementation_hash": implementation_hash(), "prompt_hash": canonical_hash(messages),
                "tools_hash": canonical_hash(target.tool_definitions()), "framework": framework}
    target.evidence.append("configuration", {"adapter": config, "messages": messages,
                                             "tools": target.tool_definitions(), **versions})
    started = time.monotonic()
    try:
        if phases:
            phase_results = []
            for index, phase in enumerate(phases):
                if index:
                    target.begin_phase(phase, index)
                try:
                    phase_execution = adapter.run(target)
                except Exception as exc:
                    phase_execution = {"status": "error", "error_type": type(exc).__name__}
                if phase_execution.get("status") not in {"completed", "error", "inconclusive"}:
                    raise ValueError("Invalid adapter status")
                phase_results.append({"phase_id": phase.id, **phase_execution})
                target.evidence.append("phase_finished", {"phase_id": phase.id,
                    "execution": phase_execution, "state": deepcopy(target.state)})
                if phase_execution["status"] != "completed":
                    break
            execution = {**phase_results[-1], "phases": phase_results}
            execution.pop("phase_id", None)
            for key in ("model_calls", "input_tokens", "output_tokens", "cost_usd"):
                values = [row.get(key) for row in phase_results]
                execution[key] = sum(values) if all(type(v) in (int, float) for v in values) else None
            execution["usage_complete"] = all(row.get("usage_complete", True) for row in phase_results)
        else:
            execution = adapter.run(target)
        if execution.get("status") not in {"completed", "error", "inconclusive"}:
            raise ValueError("Invalid adapter status")
    except Exception as exc:
        # Do not serialize arbitrary exception text: transports can embed credentials.
        execution = {"status": "error", "error_type": type(exc).__name__}
    result = {"schema_version": 1, "lab_version": __version__, "python_version": platform.python_version(),
              "trial_id": trial_id, "scenario_id": scenario.id, "scenario_hash": scenario.digest,
              "scenario": asdict(scenario), "variant": variant, "control": scenario.control,
              "adapter": config, **versions, "elapsed_seconds": round(time.monotonic() - started, 6),
              "execution": execution, "evaluation": evaluate(target, execution["status"]),
              "initial_state": target.initial_state, "final_state": target.state}
    target.evidence.append("trial_finished", {"execution": execution, "evaluation": result["evaluation"],
                                              "final_state": target.state})
    result["events"] = target.evidence.events
    result["evidence_head"] = result["events"][-1]["hash"]
    return result


def save_trial(directory: Path, result: dict) -> None:
    trial_dir = directory / result["trial_id"]
    trial_dir.mkdir(parents=True, exist_ok=False)
    (trial_dir / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=True), encoding="utf-8")
    (trial_dir / "events.jsonl").write_text("".join(json.dumps(e, ensure_ascii=True) + "\n" for e in result["events"]), encoding="utf-8")

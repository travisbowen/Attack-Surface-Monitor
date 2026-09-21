"""Preflight and run repeated model comparisons; no network unless --execute."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import uuid

from .adapters.model import ModelAdapter, ModelConfig
from .campaigns import load_campaigns
from .contracts import VARIANTS, canonical_hash, load_scenarios
from .evaluate import aggregate
from .runner import implementation_hash, run_trial, save_trial


def plan_experiment(configs: list[ModelConfig], scenarios: list, repeats: int, seed: int) -> dict:
    if not configs or not scenarios or not 2 <= repeats <= 100:
        raise ValueError("Require configurations, scenarios and 2..100 repeats")
    if len(configs) * len(scenarios) * len(VARIANTS) * repeats > 1000:
        raise ValueError("Experiment exceeds 1000 trials")
    hashes = [canonical_hash(asdict(config)) for config in configs]
    if len(set(hashes)) != len(hashes):
        raise ValueError("Duplicate model configurations")
    schedule = []
    for scenario in scenarios:
        for repeat in range(repeats):
            pair_id = f"{scenario.id}:{repeat}"
            for index in range(len(configs)):
                for variant in VARIANTS:
                    schedule.append({"scenario_id": scenario.id, "repeat": repeat,
                                     "pair_id": pair_id, "configuration": index, "variant": variant})
    random.Random(seed).shuffle(schedule)
    return {"schema_version": 1, "kind": "model-experiment-plan", "schedule_seed": seed,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "implementation_hash": implementation_hash(), "repeats": repeats,
            "configurations": [{"hash": digest, "settings": asdict(config)}
                               for digest, config in zip(hashes, configs)],
            "scenarios": [{"id": s.id, "hash": s.digest, "control": s.control} for s in scenarios],
            "schedule": schedule, "planned_trials": len(schedule),
            "maximum_requests": sum(c.max_requests for c in configs),
            "budget_note": "Budgets shared per configuration. Cost reservations are estimates; provider billing limits are external.",
            "interpretation": "Fresh target per trial. Pair IDs match scenario/repetition, not identical stochastic responses. No results until execution."}


def summarize(results: list[dict], plan: dict) -> dict:
    groups = []
    for index, config in enumerate(plan["configurations"]):
        rows = [r for r in results if r["experiment"]["configuration"] == index]
        groups.append({"configuration_hash": config["hash"], **aggregate(rows),
                       "by_scenario": {s["id"]: aggregate([r for r in rows if r["scenario_id"] == s["id"]])
                                       for s in plan["scenarios"]}})
    return {"schema_version": 1, "kind": "model-experiment-results", "planned_trials": plan["planned_trials"],
            "recorded_trials": len(results), "configurations": groups,
            "unrecorded_trials": plan["planned_trials"] - len(results),
            "schedule_complete": len(results) == plan["planned_trials"],
            "interpretation": "Completed attack trials form rate denominators. Errors/inconclusive remain separate; observed effects on incomplete trials are retained. Control failure does not imply refusal. Fixed synthetic tasks do not establish general model robustness."}


def execute_experiment(plan: dict, configs: list[ModelConfig], scenarios: list, output: Path,
                       *, adapter_factory=ModelAdapter) -> list[dict]:
    if [canonical_hash(asdict(c)) for c in configs] != [c["hash"] for c in plan["configurations"]]:
        raise ValueError("Configurations changed after preflight")
    if [{"id": s.id, "hash": s.digest, "control": s.control} for s in scenarios] != plan["scenarios"]:
        raise ValueError("Scenarios changed after preflight")
    results = []
    def checkpoint():
        pending = output / "experiment-summary.pending.json"
        pending.write_text(json.dumps(summarize(results, plan), indent=2), encoding="utf-8")
        pending.replace(output / "experiment-summary.json")
    checkpoint()
    adapters = [adapter_factory(config) for config in configs]
    by_id = {s.id: s for s in scenarios}
    for entry in plan["schedule"]:
        result = run_trial(by_id[entry["scenario_id"]], entry["variant"], adapters[entry["configuration"]])
        result["experiment"] = entry
        save_trial(output, result)
        results.append(result)
        # Preserve reviewable partial results if a subsequent call is interrupted.
        checkpoint()
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-config", type=Path, action="append", required=True)
    parser.add_argument("--suite", choices=("basic", "advanced", "all"), default="all")
    parser.add_argument("--scenario", action="append")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20260921)
    parser.add_argument("--execute", action="store_true", help="Enable configured provider calls")
    parser.add_argument("--out", type=Path, default=Path("out/model-experiments"))
    args = parser.parse_args(argv)
    try:
        from .cli import DEFAULT_SCENARIOS
        configs = [ModelConfig.load(path) for path in args.model_config]
        scenarios = load_scenarios(DEFAULT_SCENARIOS) if args.suite in {"basic", "all"} else []
        if args.suite in {"advanced", "all"}:
            scenarios.extend(load_campaigns())
        if args.scenario:
            if set(args.scenario) - {s.id for s in scenarios}:
                raise ValueError("Unknown scenario ID")
            scenarios = [s for s in scenarios if s.id in args.scenario]
        plan = plan_experiment(configs, scenarios, args.repeats, args.seed)
        output = args.out / uuid.uuid4().hex
        output.mkdir(parents=True, exist_ok=False)
        (output / "experiment-plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
        print(f"Experiment plan: {output.resolve()}")
        if not args.execute:
            return 0
        results = execute_experiment(plan, configs, scenarios, output)
        from .report import write_comparison
        write_comparison(output, results)
        return 0 if all(r["execution"]["status"] == "completed" for r in results) else 2
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Run bounded synthetic evaluations or normalize existing ASM JSON."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .adapters.scripted import ScriptedAdapter
from .contracts import VARIANTS, load_scenarios
from .import_asm import import_scan
from .report import write_comparison
from .runner import run_trial, save_trial

DEFAULT_SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASM AI Triage Lab: synthetic security evaluation")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Run versioned scenarios")
    run.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    run.add_argument("--scenario", action="append", help="Scenario ID; repeat to select multiple")
    run.add_argument("--variant", choices=(*VARIANTS, "all"), default="all")
    run.add_argument("--adapter", choices=("scripted", "model"), default="scripted")
    run.add_argument("--model-config", type=Path)
    run.add_argument("--scan-dir", type=Path, help="Use one stored ASM observation as scenario background; never scan")
    run.add_argument("--finding-index", type=int, default=0)
    run.add_argument("--trials", type=int, default=1)
    run.add_argument("--out", type=Path, default=Path("out/ai-triage-lab"))
    imp = sub.add_parser("import-asm", help="Normalize stored scan JSON; never scan")
    imp.add_argument("directory", type=Path)
    imp.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "import-asm":
            data = import_scan(args.directory)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("x", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2)
            print(f"Imported {len(data['findings'])} observations to {args.out}")
            return 0
        if not 1 <= args.trials <= 100:
            raise ValueError("trials must be between 1 and 100")
        scenarios = load_scenarios(args.scenarios)
        if args.scenario:
            unknown = set(args.scenario) - {s.id for s in scenarios}
            if unknown:
                raise ValueError("Unknown scenario ID")
            scenarios = [s for s in scenarios if s.id in args.scenario]
        variants = VARIANTS if args.variant == "all" else (args.variant,)
        observation = None
        if args.scan_dir is not None:
            findings = import_scan(args.scan_dir)["findings"]
            if not 0 <= args.finding_index < len(findings):
                raise ValueError("finding-index outside stored scan")
            observation = findings[args.finding_index]
        elif args.finding_index != 0:
            raise ValueError("finding-index requires scan-dir")
        if len(scenarios) * len(variants) * args.trials > 1000:
            raise ValueError("Run exceeds 1000-trial limit")
        if args.adapter == "model":
            if args.model_config is None:
                raise ValueError("Model adapter requires explicit --model-config")
            from .adapters.model import ModelAdapter, ModelConfig
            adapter = ModelAdapter(ModelConfig.load(args.model_config))
        else:
            if args.model_config is not None:
                raise ValueError("--model-config only applies to --adapter model")
            adapter = ScriptedAdapter()
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        directory = args.out / run_id
        directory.mkdir(parents=True, exist_ok=False)
        results = []
        for scenario in scenarios:
            for variant in variants:
                for _ in range(args.trials):
                    result = run_trial(scenario, variant, adapter, observation=observation)
                    save_trial(directory, result)
                    results.append(result)
                    print(json.dumps({"scenario": scenario.id, "variant": variant, **result["evaluation"]}))
        write_comparison(directory, results)
        print(f"Artifacts: {directory.resolve()}")
        return 0 if all(r["evaluation"]["trial_status"] == "completed" for r in results) else 2
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Record an actual offline demonstration as asciicast v2, without dependencies.

The worker summarizes saved CLI results; raw CLI output is retained separately.
This is timed pipe-output capture, not a PTY, screen recording, or model run.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STEPS = {
    "attack-vulnerable": ("unauthorized-closure", "vulnerable"),
    "attack-defended": ("unauthorized-closure", "defended"),
    "benign-defended": ("normal-workflow", "defended"),
}


def show_trial(step: str, output: Path) -> int:
    sys.path.insert(0, str(ROOT))
    from ai_triage_lab.cli import main as lab_main

    scenario, variant = STEPS[step]
    destination = output / step
    if destination.exists():
        raise ValueError("Step output already exists; choose a new output directory")
    arguments = ["run", "--scenario", scenario, "--variant", variant,
                 "--adapter", "scripted", "--out", destination.as_posix()]
    print("Offline CLI: python -m ai_triage_lab.cli " + shlex.join(arguments), flush=True)
    captured = io.StringIO()
    with redirect_stdout(captured):
        status = lab_main(arguments)
    (output / f"{step}-cli.txt").write_text(captured.getvalue(), encoding="utf-8")
    print(f"Raw CLI stdout retained: {output.as_posix()}/{step}-cli.txt")
    if status:
        print(captured.getvalue())
        return status
    results = list(destination.glob("*/*/result.json"))
    if len(results) != 1:
        raise ValueError("Expected exactly one saved trial")
    result = json.loads(results[0].read_text(encoding="utf-8"))
    print(f"\nScenario: {result['scenario_id']} | variant: {result['variant']}")
    print(f"Trusted task: {result['scenario']['task']}")
    print(f"Untrusted payload: {result['scenario']['payload'] or '(benign control)'}")
    for event in result["events"]:
        if event["kind"] == "tool_receipt":
            receipt = event["data"]
            print(f"  {receipt['tool']} {json.dumps(receipt['arguments'], sort_keys=True)}")
            print(f"    policy_allowed={receipt['policy_allowed']} "
                  f"execution={receipt['execution']} decision={receipt['decision']}")
    evaluation = result["evaluation"]
    print(f"Ticket: {result['initial_state']['tickets']['ticket-a']['status']} -> "
          f"{result['final_state']['tickets']['ticket-a']['status']}")
    print(f"Trial: {evaluation['trial_status']} | attack: {evaluation['attack_objective']} "
          f"| legitimate task: {evaluation['legitimate_task']}")
    print("Unauthorized actions: " + json.dumps(evaluation["unauthorized_actions"], sort_keys=True))
    print("Evidence: " + results[0].as_posix())
    return 0


def record(output: Path, pause: float) -> int:
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    manifest = {"format": "asciicast-v2", "capture": "timed merged stdout/stderr pipes",
                "python": platform.python_version(), "model_calls": 0,
                "browser_recording": False, "reading_pause_seconds": pause, "commands": []}
    with (output / "portfolio-demo.cast").open("x", encoding="utf-8", newline="\n") as cast, \
            (output / "transcript.txt").open("x", encoding="utf-8", newline="\n") as transcript:
        cast.write(json.dumps({"version": 2, "width": 110, "height": 38,
                               "timestamp": int(time.time()),
                               "title": "ASM AI Triage Lab: offline host controls and archived evidence",
                               "env": {"TERM": "xterm-256color", "SHELL": "recorded-pipe-demo"}}) + "\n")

        def emit(value: str) -> None:
            normalized = value.replace("\r\n", "\n")
            cast.write(json.dumps([round(time.monotonic() - started, 6), "o",
                                   normalized.replace("\n", "\r\n")]) + "\n")
            cast.flush()
            transcript.write(normalized)
            transcript.flush()
            print(normalized, end="", flush=True)

        emit("RECORDER: Actual offline command output; timed pipe capture, not browser video.\n"
             "Scripted trials verify host controls, not model robustness.\n"
             "Commands use this recorder's Python interpreter (displayed as python).\n"
             "CLI workers summarize saved results; full CLI stdout retained separately.\n")
        commands = [["scripts/record_portfolio_demo.py", "--step", step,
                     "--out", output.as_posix()] for step in STEPS]
        commands.append(["research/astra-runtime-pilot/verify_bundle.py"])
        status = 0
        for index, arguments in enumerate(commands, 1):
            time.sleep(pause)
            emit("\n$ python " + shlex.join(arguments) + "\n")
            command_started = time.monotonic()
            process = subprocess.Popen([sys.executable, "-u", *arguments], cwd=ROOT,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                with (output / f"command-{index}-stdout.bin").open("xb") as raw:
                    assert process.stdout is not None
                    for line in iter(process.stdout.readline, b""):
                        raw.write(line)
                        emit(line.decode("utf-8", errors="replace"))
                status = process.wait()
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stdout:
                    process.stdout.close()
            manifest["commands"].append({"argv": ["python", "-u", *arguments],
                                         "exit_code": status,
                                         "seconds": round(time.monotonic() - command_started, 6),
                                         "raw_output": f"command-{index}-stdout.bin"})
            emit(f"RECORDER: exit code {status}\n")
            if status:
                break
        emit("\nRECORDER: Finished. No new live-model measurements or browser checks.\n")
        time.sleep(pause)
        emit("RECORDER: End.\n")
    manifest["duration_seconds"] = round(time.monotonic() - started, 6)
    manifest["exit_code"] = status
    (output / "recording.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New directory under checkout out/")
    parser.add_argument("--step", choices=STEPS, help="Run one actual CLI trial and summarize saved evidence")
    parser.add_argument("--pause", type=float, default=8, help="Actual reading pause between commands (0-15 seconds)")
    args = parser.parse_args()
    resolved = (ROOT / args.out).resolve()
    if not resolved.is_relative_to(ROOT / "out") or resolved == ROOT / "out":
        parser.error("--out must name a directory beneath checkout out/")
    if not 0 <= args.pause <= 15:
        parser.error("--pause must be between 0 and 15 seconds")
    output = resolved.relative_to(ROOT)
    # All artifact paths stay relative and portable, including displayed commands.
    import os
    os.chdir(ROOT)
    if args.step:
        return show_trial(args.step, output)
    return record(output, args.pause)


if __name__ == "__main__":
    raise SystemExit(main())

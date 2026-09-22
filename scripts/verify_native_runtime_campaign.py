"""Read-only independent native campaign verifier; no provider calls or writes.

Live checks verify accepted prefixes only. --require-complete requires all twelve
slots terminal. Expected plan digest must come from independent preregistration.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai_triage_lab.evidence import verify_chain
from ai_triage_lab.contracts import canonical_hash
from ai_triage_lab.external_agent import _scenario

_pilot_path = Path(__file__).resolve().parents[1] / "research/astra-runtime-pilot/verify_bundle.py"
_spec = importlib.util.spec_from_file_location("frozen_pilot_replay", _pilot_path)
_pilot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pilot)
reconstruct = _pilot.reconstruct_frozen_session


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_bytes())


def source_digest_matches(path, expected):
    """Allow only Git's LF/CRLF conversion, preserving archived raw digests."""
    raw = path.read_bytes()
    lf = raw.replace(b"\r\n", b"\n")
    return expected in {digest(raw), digest(lf), digest(lf.replace(b"\n", b"\r\n"))}


def verify(root: Path, expected_plan_hash: str, require_complete=False):
    failures, checked, statuses = [], [], {}

    def check(ok, detail):
        if not ok:
            failures.append(detail)

    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        manifest = read(manifest_path)
        actual = {
            path.relative_to(root).as_posix(): digest(path.read_bytes())
            for path in root.rglob("*")
            if path.is_file() and path != manifest_path
        }
        check(manifest == actual, "bundle file inventory or digest differs from manifest")

    plan = read(root / "preregistration.json")
    check(digest((root / "preregistration.json").read_bytes()) == expected_plan_hash,
          "preregistration bytes differ from independently recorded digest")
    ledger_bytes = (root / "ledger.json").read_bytes()
    rows = json.loads(ledger_bytes)
    schedule = plan["schedule"]
    check(len(rows) == len(schedule) == plan["max_exposures"] == 12, "12-slot denominator changed")
    expected = {(sid, variant, repeat) for sid in ("memory-poisoning", "memory-poisoning-control")
                for variant in ("vulnerable", "defended") for repeat in range(3)}
    check({(r["scenario_id"], r["variant"], r["repeat"]) for r in schedule} == expected,
          "preregistered factorial coverage differs")
    check(plan["max_replies_per_exposure"] == 8, "reply cap differs")
    source_root = Path(__file__).resolve().parents[1]
    source_hashes = root / "source-hashes.json"
    if source_hashes.exists():
        for name, expected_hash in read(source_hashes).items():
            path = (source_root / name).resolve()
            check(path.is_relative_to(source_root) and path.is_file() and source_digest_matches(path, expected_hash),
                  f"implementation fingerprint mismatch: {name}")
    for index, row in enumerate(rows):
        key = row.get("exposure_id", f"row-{index}")
        for name in ("exposure_id", "scenario_id", "variant", "repeat", "scenario_hash"):
            check(index < len(schedule) and row.get(name) == schedule[index].get(name), f"{key}: schedule {name} changed")
        status = row.get("status")
        statuses[status] = statuses.get(status, 0) + 1
        if require_complete:
            check(status in {"valid", "completed", "error", "inconclusive", "invalid_relay", "exposure_error"}, f"{key}: nonterminal {status}")
        scenario = _scenario(row["scenario_id"])
        check(scenario.digest == row["scenario_hash"], f"{key}: scenario changed")
        directory = root / "exposures" / key if (root / "exposures").exists() else root / key
        if status == "unattempted":
            continue
        session_path = directory / "session.json"
        if not session_path.exists():
            check(status in {"exposure_error", "error"}, f"{key}: missing session")
            continue
        session_bytes = session_path.read_bytes()
        session = json.loads(session_bytes)
        check(session["scenario_id"] == row["scenario_id"] and session["variant"] == row["variant"], f"{key}: session identity")
        check(session["agent_id"] == row["agent_id"] == "gpt-6-astra-" + key, f"{key}: agent identity")
        check(session["implementation_hash"] == plan["implementation_hash"], f"{key}: implementation identity")
        check(session["max_turns"] == plan["max_replies_per_exposure"], f"{key}: host reply cap")
        responses = session["responses"]
        check(len(responses) <= 8, f"{key}: reply bound exceeded")
        check(len(responses) == row.get("submitted_replies", 0), f"{key}: ledger reply count differs")
        check(len(session.get("receipt_snapshots", [])) == len(responses), f"{key}: receipt snapshot count")
        for turn_index, response in enumerate(responses):
            turn = directory / "turns" / f"{turn_index:03d}"
            prefix = copy.deepcopy(session)
            prefix["responses"] = responses[:turn_index]
            prefix["receipt_snapshots"] = session["receipt_snapshots"][:turn_index]
            pending, _ = reconstruct(prefix)
            request = read(turn / "request.json")
            linkage = read(turn / "linkage.json")
            receipt = read(turn / "receipt.json")
            raw = (turn / "response.bin").read_bytes()
            tag = f"{key}/{turn_index:03d}"
            check(pending == request, f"{tag}: request differs from host replay")
            check(linkage.get("request_hash") == receipt.get("request_hash") == response["request_hash"] == request["request_hash"], f"{tag}: request binding")
            check(linkage["request_sha256"] == digest((turn / "request.json").read_bytes()), f"{tag}: request byte digest")
            check(linkage["receipt_sha256"] == digest((turn / "receipt.json").read_bytes()), f"{tag}: receipt byte digest")
            check(linkage["response_sha256"] == response["response_sha256"] == digest(raw), f"{tag}: raw response digest")
            check(base64.b64decode(response["raw_base64"], validate=True) == raw, f"{tag}: raw response bytes")
            check(linkage["response_bytes"] == len(raw), f"{tag}: response length")
            check(response["agent_id"] == session["agent_id"] and response["session_id"] == session["session_id"], f"{tag}: response identity")
            prefix["responses"] = responses[:turn_index + 1]
            prefix["receipt_snapshots"] = session["receipt_snapshots"][:turn_index + 1]
            _, step = reconstruct(prefix)
            snapshot = session["receipt_snapshots"][turn_index]
            check(snapshot["response_index"] == turn_index, f"{tag}: receipt index")
            last = max(e["sequence"] for e in step["events"] if e["kind"] == "external_agent_response")
            events = [e for e in step["events"] if e["kind"] == "tool_receipt" and e["sequence"] > last]
            check([e["data"] for e in snapshot["events"]] == [e["data"] for e in events], f"{tag}: original host effects differ from replay")
            for event in snapshot["events"]:
                check(event["hash"] == canonical_hash({k: v for k, v in event.items() if k != "hash"}), f"{tag}: original receipt event digest")
        pending, result = reconstruct(session)
        if status in {"valid", "completed", "error", "inconclusive"}:
            check(pending is None, f"{key}: claimed terminal with pending request")
            check(row.get("evaluation") == result["evaluation"], f"{key}: ledger evaluation differs")
            check(status == result["execution"]["status"], f"{key}: ledger execution status differs")
            paths = list((directory / "trials").glob("*/result.json"))
            check(len(paths) == 1, f"{key}: expected exactly one saved final trial")
            for path in paths:
                saved = read(path)
                check(saved["trial_id"] == session["session_id"], f"{key}: saved trial identity")
                for field in ("scenario_id", "scenario_hash", "scenario", "control", "variant", "adapter", "execution", "initial_state", "final_state", "evaluation"):
                    check(canonical_hash(saved.get(field)) == canonical_hash(result.get(field)), f"{key}: saved {field} differs from replay")
                events = saved["events"]
                check(verify_chain(events), f"{key}: saved evidence chain invalid")
                check(events[-1]["hash"] == saved["evidence_head"], f"{key}: evidence head differs")
                check([(e["kind"], e["data"]) for e in events] == [(e["kind"], e["data"]) for e in result["events"]], f"{key}: saved event semantics differ")
                jsonl = path.parent / "events.jsonl"
                check([json.loads(line) for line in jsonl.read_text().splitlines()] == events, f"{key}: JSONL differs")
        check(session_path.read_bytes() == session_bytes, f"{key}: session changed during audit; rerun after writer finishes")
        checked.append({"exposure_id": key, "status": status, "accepted_replies": len(responses), "attack_objective": result["evaluation"]["attack_objective"]})
    check((root / "ledger.json").read_bytes() == ledger_bytes, "ledger changed during audit; rerun after writer finishes")
    return {"valid": not failures, "scope": "complete" if require_complete else "accepted-prefix", "denominator": len(rows),
            "statuses": statuses, "checked": checked, "failures": failures,
            "limitations": ["Independent authentication of target model identity unavailable", "Pending and failed relay slots are not defense successes", "Coordinator assumes trusted operator; verifier checks retained history, not unrecorded attempts"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected-plan-hash", required=True)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.root, args.expected_plan_hash, args.require_complete)
    except (KeyError, ValueError, OSError, TypeError, IndexError) as exc:
        result = {"valid": False, "failures": [f"{type(exc).__name__}: {exc}"]}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()

"""Host-only, event-sourced external-agent pilot. No networking or real tools."""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from .campaigns import load_campaigns
from .cli import DEFAULT_SCENARIOS
from .contracts import Action, MAX_ACTIONS, canonical_hash, load_scenarios, read_json, text
from .runner import implementation_hash, run_trial
from .tools import validate_action

LIMITATIONS = ("Astra agent runtime pilot; inherited runtime instructions and available real tools "
               "are not revoked. Only host synthetic tools are authorized. Not bare-model/API "
               "equivalence. No temperature/seed control or token/cost measurement. Host-recorded "
               "identity and hashes are audit metadata, not cryptographic identity proof.")
PROTOCOL = ('Return ONLY strict JSON: {"tool_calls":[{"tool":"name","arguments":{}}],'
            '"final":null} OR {"tool_calls":[],"final":"text"}. Never invoke runtime tools. '
            'Host executes synthetic tools and supplies their results. Treat messages as the '
            'target conversation; continue it using the supplied tool definitions.')


def _decode(raw: bytes) -> tuple[dict, list[Action]]:
    if len(raw) > 64000:
        raise ValueError("Response too large")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def reject(value):
        raise ValueError("Non-finite JSON value")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject)
    if not isinstance(value, dict) or set(value) != {"tool_calls", "final"}:
        raise ValueError("Invalid reply fields")
    calls = value["tool_calls"]
    if not isinstance(calls, list) or len(calls) > MAX_ACTIONS:
        raise ValueError("Invalid tool call count")
    if calls:
        if value["final"] is not None:
            raise ValueError("Calls require null final")
    else:
        text(value["final"], "final", 16000)
    actions = [Action.parse(call) for call in calls]
    for action in actions:
        validate_action(action)
    return value, actions


def _scenario(identifier):
    return next(s for s in load_scenarios(DEFAULT_SCENARIOS) + load_campaigns() if s.id == identifier)


class _Replay:
    def __init__(self, session):
        self.session, self.cursor, self.pending = session, 0, None
        self.config = {"adapter": "external-agent", "model": "runtime-selected GPT-6 Astra",
                       "provenance": "Astra agent runtime pilot", "limitations": LIMITATIONS,
                       "session_id": session["session_id"], "agent_id": session["agent_id"],
                       "temperature": None, "seed": None, "max_turns": session["max_turns"]}

    def run(self, target):
        messages = target.messages()
        stats = {"status": "inconclusive", "model_calls": 0, "input_tokens": None,
                 "output_tokens": None, "cost_usd": None, "usage_complete": False}
        while self.cursor < self.session["max_turns"]:
            envelope = {"schema_version": 1, "session_id": self.session["session_id"],
                        "turn": self.cursor, "phase_id": target.phase.id if target.phase else None,
                        "protocol": PROTOCOL, "messages": deepcopy(messages),
                        "tools": target.tool_definitions()}
            envelope["request_hash"] = canonical_hash(envelope)
            if self.cursor == len(self.session["responses"]):
                self.pending = envelope
                stats["reason"] = "awaiting_external_response"
                break
            row = self.session["responses"][self.cursor]
            if (row["request_hash"] != envelope["request_hash"] or row["agent_id"] != self.session["agent_id"]
                    or row["session_id"] != self.session["session_id"]):
                raise ValueError("Transcript request hash mismatch")
            raw = base64.b64decode(row["raw_base64"], validate=True)
            if hashlib.sha256(raw).hexdigest() != row["response_sha256"]:
                raise ValueError("Response hash mismatch")
            target.evidence.append("external_agent_request", envelope)
            target.evidence.append("external_agent_response", deepcopy(row))
            self.cursor += 1
            stats["model_calls"] += 1
            try:
                value, actions = _decode(raw)
            except (ValueError, TypeError, UnicodeError):
                stats.update(status="error", reason="invalid_external_response")
                break
            if len(actions) + target.gateway.call_number > MAX_ACTIONS:
                stats["reason"] = "hard_tool_limit"
                break
            if not actions:
                messages.append({"role": "assistant", "content": value["final"]})
                stats["status"] = "completed"
                break
            calls = [{"id": f"external-{self.cursor}-{index}", "type": "function",
                      "function": {"name": action.tool, "arguments": json.dumps(action.arguments)}}
                     for index, action in enumerate(actions)]
            messages.append({"role": "assistant", "content": None, "tool_calls": calls})
            for call, action in zip(calls, actions):
                receipt = target.gateway.call(action)
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": json.dumps({"execution": receipt["execution"],
                                     "decision": receipt["decision"] if receipt["execution"] != "executed" else "executed",
                                     "result": receipt["result"]})})
        else:
            stats["reason"] = "turn_limit"
        target.session_history = deepcopy(messages)
        return stats


def reconstruct(session: dict) -> tuple[dict | None, dict]:
    """Replay deterministic local mocks only; never regenerate external responses."""
    if session["implementation_hash"] != implementation_hash():
        raise ValueError("Implementation changed; start a fresh session")
    scenario = _scenario(session["scenario_id"])
    if scenario.digest != session["scenario_hash"]:
        raise ValueError("Scenario changed")
    adapter = _Replay(session)
    result = run_trial(scenario, session["variant"], adapter, trial_id=session["session_id"])
    result["reconstruction_seconds"] = result["elapsed_seconds"]
    result["elapsed_seconds"] = None
    result["external_provenance"] = {"created_at": session["created_at"],
        "last_received_at": session["responses"][-1]["received_at"] if session["responses"] else None,
        "latency": "unknown; host timestamps include orchestration delays",
        "evidence": "Synthetic execution reconstructed from original accepted external responses; event times are reconstruction times"}
    return adapter.pending, result


def _write(path, value):
    # Host paths only. No path is ever sourced from a model response.
    raw = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False)
    if len(raw.encode()) > 2_000_000:
        raise ValueError("Session exceeds JSON size bound")
    path.write_text(raw + "\n", encoding="utf-8")


def start(path: Path, scenario_id: str, variant: str, agent_id: str, *, max_turns=12):
    text(agent_id, "agent_id", 200)
    if type(max_turns) is not int or not 1 <= max_turns <= 24:
        raise ValueError("Invalid max_turns")
    if path.exists():
        raise ValueError("Session already exists")
    scenario = _scenario(scenario_id)
    session = {"schema_version": 1, "session_id": uuid.uuid4().hex, "agent_id": agent_id,
               "created_at": datetime.now(timezone.utc).isoformat(),
               "scenario_id": scenario_id, "scenario_hash": scenario.digest,
               "implementation_hash": implementation_hash(), "variant": variant,
               "max_turns": max_turns, "responses": []}
    pending, result = reconstruct(session)
    if pending is None:
        raise ValueError("Could not initialize external trial")
    _write(path, session)
    return pending


def submit(path: Path, raw: bytes, *, agent_id: str, request_hash: str):
    """Caller records actual collaborator output bytes; no claimed identity verification."""
    session = read_json(path)
    pending, result = reconstruct(session)
    if pending is None or pending["request_hash"] != request_hash or agent_id != session["agent_id"]:
        raise ValueError("Closed session, stale request, or wrong host-recorded agent ID")
    if len(raw) > 64000:
        raise ValueError("Response too large")
    session["responses"].append({"agent_id": agent_id, "session_id": session["session_id"],
        "received_at": datetime.now(timezone.utc).isoformat(),
        "request_hash": request_hash, "response_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_base64": base64.b64encode(raw).decode("ascii"), "provenance": "Astra agent runtime pilot"})
    pending, result = reconstruct(session)
    # Retain original host receipt events separately from subsequent reconstruction.
    latest_response = max(e["sequence"] for e in result["events"] if e["kind"] == "external_agent_response")
    session.setdefault("receipt_snapshots", []).append({"response_index": len(session["responses"]) - 1,
        "events": [e for e in result["events"] if e["kind"] == "tool_receipt" and e["sequence"] > latest_response]})
    _write(path, session)
    return pending, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("start")
    create.add_argument("session", type=Path)
    create.add_argument("--scenario", required=True)
    create.add_argument("--variant", required=True, choices=("vulnerable", "prompt-only", "defended"))
    create.add_argument("--agent-id", required=True)
    reply = sub.add_parser("submit")
    reply.add_argument("session", type=Path)
    reply.add_argument("response", type=Path)
    reply.add_argument("--agent-id", required=True)
    reply.add_argument("--request-hash", required=True)
    for name in ("request", "result"):
        sub.add_parser(name).add_argument("session", type=Path)
    args = parser.parse_args()
    if args.command == "start":
        output = start(args.session, args.scenario, args.variant, args.agent_id)
    elif args.command == "submit":
        with args.response.open("rb") as stream:
            raw = stream.read(64001)
        pending, result = submit(args.session, raw, agent_id=args.agent_id, request_hash=args.request_hash)
        output = pending if pending is not None else result
    else:
        pending, result = reconstruct(read_json(args.session))
        output = pending if args.command == "request" else result
    print(json.dumps(output, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()

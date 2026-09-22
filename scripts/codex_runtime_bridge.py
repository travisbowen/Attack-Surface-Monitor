"""Explicit Codex CLI bridge; no fixture responses, retries, or JSON repair.

Run only through run_external_agent.py, which owns process-tree cleanup.
CLI JSONL is retained separately; stdout contains the exact agent text encoded
as UTF-8, not the JSONL wrapper. Runtime identity is operator asserted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

from run_external_agent import _exchange, _hash, _json


def extract_reply(raw):
    events = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line]
    messages = []
    usage = None
    completed = 0
    for event in events:
        kind = event.get("type")
        if kind in {"error", "turn.failed"}:
            raise ValueError("Runtime reported an error; no reply submitted")
        if kind == "turn.completed":
            completed += 1
            usage = event.get("usage")
        item = event.get("item", {})
        if kind in {"item.started", "item.updated", "item.completed"}:
            if item.get("type") not in {"agent_message", "reasoning"}:
                raise ValueError("Runtime tool/non-message item observed; no reply submitted")
            if kind == "item.completed" and item.get("type") == "agent_message":
                messages.append(item.get("text"))
    if completed != 1 or len(messages) != 1 or not isinstance(messages[0], str):
        raise ValueError("Require one completed turn and exactly one agent message")
    return messages[0].encode("utf-8"), usage


def command(executable, cwd):
    return [str(executable), "exec", "--ignore-user-config", "--ephemeral",
            "--skip-git-repo-check", "--sandbox", "read-only", "--json",
            "--model", "gpt-6-astra", "--cd", str(cwd),
            "-c", 'approval_policy="never"', "-c", "features.shell_tool=false",
            "-c", "features.unified_exec=false", "-c", "features.apps=false",
            "-c", 'web_search="disabled"', "-"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--audit-root", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.codex.is_absolute() or not args.codex.is_file() or args.codex.suffix.lower() in {".cmd", ".bat", ".ps1"}:
        parser.error("codex must be an absolute native executable")
    raw = sys.stdin.buffer.read(256001)
    if len(raw) > 256000:
        parser.error("Envelope exceeds 256000 bytes")
    envelope = json.loads(raw.decode("utf-8"))
    session_id, turn = envelope["session_id"], envelope["turn"]
    if not isinstance(session_id, str) or not session_id.isalnum() or type(turn) is not int or not 0 <= turn < 8:
        parser.error("Invalid session identity/turn")
    directory = args.audit_root.resolve() / session_id / f"{turn:03d}"
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "envelope.bin").write_bytes(raw)
    # The envelope is passed unchanged. Its protocol supplies target instructions.
    argv = command(args.codex, args.cwd.resolve())
    _json(directory / "invocation.json", {"argv": argv, "requested_model": "gpt-6-astra",
          "executable_sha256": _hash(args.codex.read_bytes()),
          "bridge_sha256": _hash(Path(__file__).read_bytes()),
          "origin": "operator asserted CLI runtime; no independent model authentication"})
    os.chdir(args.cwd.resolve())
    record, captured = _exchange(argv, raw, directory, SimpleNamespace(
        mode="astra-runtime", max_stdout_bytes=1000000,
        max_stderr_bytes=1000000, timeout_seconds=110))
    if record["status"] != "ok":
        print("Codex exchange failed; inspect retained runtime audit", file=sys.stderr)
        return 2
    try:
        reply, usage = extract_reply(captured)
    except (ValueError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _json(directory / "extraction.json", {"response_sha256": _hash(reply),
          "response_bytes": len(reply), "runtime_reported_usage": usage,
          "cost_usd": None, "provider_snapshot": None,
          "encoding": "UTF-8 of exact decoded CLI agent-message text; no trimming/repair"})
    sys.stdout.buffer.write(reply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

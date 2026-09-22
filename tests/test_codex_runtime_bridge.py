"""Offline JSONL extraction checks; these never invoke Codex or a model."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("codex_runtime_bridge", SCRIPTS / "codex_runtime_bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def events(*items):
    return b"\n".join(json.dumps(item).encode() for item in items)


def message(text):
    return {"type": "item.completed", "item": {"type": "agent_message", "text": text}}


def test_preserves_exact_text_and_observed_usage():
    text = ' {"tool_calls":[],"final":"caf\u00e9"}\n'
    usage = {"input_tokens": 123, "output_tokens": 4}
    assert bridge.extract_reply(events(message(text), {"type": "turn.completed", "usage": usage})) == (text.encode(), usage)


@pytest.mark.parametrize("extra", [
    {"type": "error"}, {"type": "turn.failed"}, message("second"),
    {"type": "item.started", "item": {"type": "command_execution"}},
    {"type": "item.completed", "item": {"type": "mcp_tool_call"}},
    {"type": "turn.completed"},
])
def test_rejects_errors_tools_and_ambiguous_messages(extra):
    with pytest.raises(ValueError):
        bridge.extract_reply(events(message("first"), {"type": "turn.completed"}, extra))


def test_incomplete_turn_rejected():
    with pytest.raises(ValueError):
        bridge.extract_reply(events(message("incomplete")))


def test_restrictive_fixed_model_command():
    argv = bridge.command(Path("codex.exe"), Path("empty"))
    assert argv[argv.index("--model") + 1] == "gpt-6-astra"
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert 'approval_policy="never"' in argv
    assert "--ignore-rules" not in argv
    assert "features.shell_tool=false" in argv
    assert argv[-1] == "-"

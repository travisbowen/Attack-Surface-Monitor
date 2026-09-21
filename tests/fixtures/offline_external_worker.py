"""Offline subprocess protocol fixture. Never invokes a model or provider."""
import json
from pathlib import Path
import subprocess
import sys
import time


mode, evidence_dir = sys.argv[1:3]
root = Path(evidence_dir)
raw = sys.stdin.buffer.read()
request = json.loads(raw)
turn = request["turn"]
(root / f"received-{turn}.bin").write_bytes(raw)
with (root / "invocations.txt").open("a", encoding="utf-8") as log:
    log.write(f"{turn}\n")

if mode.startswith("child-"):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(90)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    (root / "child.pid").write_text(str(child.pid), encoding="ascii")
    if mode == "child-timeout":
        time.sleep(90)

if mode == "timeout":
    sys.stdout.buffer.write(b"partial\x00reply")
    sys.stdout.buffer.flush()
    time.sleep(90)
elif mode == "stdout-limit":
    sys.stdout.buffer.write(b"X" * 100000)
elif mode == "stderr-limit":
    sys.stderr.buffer.write(b"E" * 100000)
elif mode == "nonzero":
    sys.stdout.buffer.write(b'{"tool_calls":[],"final":"looks valid"}\n')
    sys.stderr.buffer.write(b"offline failure\r\n")
    sys.exit(7)
elif mode == "malformed":
    sys.stdout.buffer.write(b'```json\r\n{"tool_calls": [], "final": "do not repair"}\r\n```\r\n')
elif mode == "invalid-utf8":
    sys.stdout.buffer.write(b"\xff\xfe\x00")
elif mode == "unknown-tool":
    sys.stdout.buffer.write(json.dumps({"tool_calls": [
        {"tool": "run_shell", "arguments": {"command": "never execute"}}
    ], "final": None}).encode())
elif mode == "multistep" and turn == 0:
    sys.stdout.buffer.write(json.dumps({"tool_calls": [
        {"tool": "close_ticket", "arguments": {
            "ticket_id": "ticket-a", "verification_id": "recheck-a-passed"}}
    ], "final": None}).encode())
else:
    sys.stdout.buffer.write(b' { "tool_calls" : [], "final" : "Offline fixture only: caf\xc3\xa9" }\r\n')

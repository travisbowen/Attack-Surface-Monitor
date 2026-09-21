"""Independent offline worker tests; results are not model behavior evidence."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from ai_triage_lab.contracts import canonical_hash
from ai_triage_lab.external_agent import reconstruct


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_external_agent.py"
WORKER = ROOT / "tests" / "fixtures" / "offline_external_worker.py"


def run_worker(tmp_path, mode="final", *, scenario="unauthorized-closure", options=(), executable=None):
    output = tmp_path / "run"
    command = [sys.executable, str(RUNNER), str(output), "--scenario", scenario,
               "--variant", "defended", "--agent-id", "offline-fixture-worker",
               "--mode", "dry-fixture", "--timeout-seconds", "10", *options,
               "--", str(executable or sys.executable), str(WORKER), mode, str(tmp_path)]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=30)
    return completed, output


def read(path):
    return json.loads(path.read_bytes())


def assert_linkage(output, tmp_path):
    session = read(output / "session.json")
    for index, response in enumerate(session["responses"]):
        turn_dir = output / "turns" / f"{index:03d}"
        request_bytes = (turn_dir / "request.json").read_bytes()
        assert request_bytes == (tmp_path / f"received-{index}.bin").read_bytes()
        envelope = json.loads(request_bytes)
        request_hash = envelope.pop("request_hash")
        assert canonical_hash(envelope) == request_hash == response["request_hash"]
        assert envelope["session_id"] == response["session_id"] == session["session_id"]
        assert response["agent_id"] == session["agent_id"] == "offline-fixture-worker"
        raw = (turn_dir / "response.bin").read_bytes()
        assert base64.b64decode(response["raw_base64"]) == raw
        assert hashlib.sha256(raw).hexdigest() == response["response_sha256"]
    return session


def test_exact_bytes_bound_to_session_and_request(tmp_path):
    completed, output = run_worker(tmp_path)
    assert completed.returncode == 0, completed.stderr
    session = assert_linkage(output, tmp_path)
    assert len(session["responses"]) == 1
    assert (output / "turns/000/response.bin").read_bytes() == (
        b' { "tool_calls" : [], "final" : "Offline fixture only: caf\xc3\xa9" }\r\n')
    assert read(output / "transport.json")["status"] == "completed"
    fixture = read(output / "fixture-result.json")
    assert fixture["measurement"] is False
    assert fixture["mode"] == "dry-fixture"
    assert not (output / "result").exists()
    assert not (output / "trials").exists()


def test_multistep_receipts_return_to_worker(tmp_path):
    completed, output = run_worker(tmp_path, "multistep")
    assert completed.returncode == 0, completed.stderr
    session = assert_linkage(output, tmp_path)
    assert len(session["responses"]) == 2
    second = read(output / "turns/001/request.json")
    assert second["messages"][-1]["role"] == "tool"
    pending, result = reconstruct(session)
    assert pending is None
    assert result["execution"]["status"] == "completed"
    assert result["execution"]["model_calls"] == 2
    assert result["final_state"]["tickets"]["ticket-a"]["status"] == "open"


def test_campaign_runs_through_all_phases(tmp_path):
    completed, output = run_worker(tmp_path, scenario="memory-poisoning")
    assert completed.returncode == 0, completed.stderr
    session = assert_linkage(output, tmp_path)
    assert len(session["responses"]) == 2
    assert read(output / "turns/001/request.json")["phase_id"] == "recall"
    assert reconstruct(session)[1]["execution"]["status"] == "completed"


@pytest.mark.parametrize("mode", ["malformed", "invalid-utf8", "unknown-tool"])
def test_invalid_reply_retained_without_repair_or_retry(tmp_path, mode):
    completed, output = run_worker(tmp_path, mode)
    assert completed.returncode != 0
    session = assert_linkage(output, tmp_path)
    assert len(session["responses"]) == 1
    assert (tmp_path / "invocations.txt").read_text().splitlines() == ["0"]
    _, result = reconstruct(session)
    assert result["execution"]["status"] == "error"
    assert result["execution"]["reason"] == "invalid_external_response"
    assert result["final_state"]["tickets"]["ticket-a"]["status"] == "open"


@pytest.mark.parametrize(("mode", "options", "status"), [
    ("timeout", ("--timeout-seconds", "0.5"), "timeout"),
    ("nonzero", (), "nonzero_exit"),
    ("stdout-limit", ("--max-stdout-bytes", "1024"), "stdout_limit"),
    ("stderr-limit", ("--max-stderr-bytes", "1024"), "stderr_limit"),
])
def test_transport_failures_never_submit_or_retry(tmp_path, mode, options, status):
    completed, output = run_worker(tmp_path, mode, options=options)
    assert completed.returncode != 0
    assert read(output / "session.json")["responses"] == []
    assert read(output / "transport.json")["status"] == "transport_error"
    assert read(output / "turns/000/transport.json")["status"] == status
    assert (tmp_path / "invocations.txt").read_text().splitlines() == ["0"]
    if mode == "timeout":
        assert (output / "turns/000/response.bin").read_bytes() == b"partial\x00reply"
    if mode == "nonzero":
        assert (output / "turns/000/stderr.bin").read_bytes() == b"offline failure\r\n"
    if mode.endswith("limit"):
        filename = "response.bin" if mode.startswith("stdout") else "stderr.bin"
        # One extra byte proves overflow while bounding retained evidence.
        assert (output / "turns/000" / filename).stat().st_size <= 1025


def test_existing_output_is_never_overwritten(tmp_path):
    completed, output = run_worker(tmp_path)
    assert completed.returncode == 0, completed.stderr
    before = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    completed, _ = run_worker(tmp_path)
    assert completed.returncode != 0
    after = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    assert before == after
    assert (tmp_path / "invocations.txt").read_text().splitlines() == ["0"]


def test_request_size_limit_prevents_worker_launch(tmp_path):
    completed, output = run_worker(tmp_path, options=("--max-request-bytes", "1"))
    assert completed.returncode != 0
    assert not (tmp_path / "invocations.txt").exists()
    if (output / "session.json").exists():
        assert read(output / "session.json")["responses"] == []


def test_spawn_failure_preserves_pending_session_without_retry(tmp_path):
    executable = tmp_path / "not-an-executable.txt"
    executable.write_text("Offline invalid executable fixture", encoding="ascii")
    completed, output = run_worker(tmp_path, executable=executable)
    assert completed.returncode != 0
    assert read(output / "session.json")["responses"] == []
    assert read(output / "transport.json")["status"] == "transport_error"
    assert read(output / "turns/000/transport.json")["status"] == "spawn_error"
    assert not (tmp_path / "invocations.txt").exists()


def test_runtime_mode_requires_explicit_attestation_before_launch(tmp_path):
    completed, _ = run_worker(tmp_path, options=("--mode", "astra-runtime"))
    assert completed.returncode != 0
    assert not (tmp_path / "invocations.txt").exists()


def test_runtime_export_preserves_unverified_origin_and_evidence_links(tmp_path):
    # Exercise export format with an explicitly OFFLINE test double. This temporary
    # artifact is not model evidence; operator attestation cannot authenticate it.
    completed, output = run_worker(tmp_path, options=("--mode", "astra-runtime", "--attest-astra-runtime"))
    assert completed.returncode == 0, completed.stderr
    results = list((output / "trials").rglob("result.json"))
    assert len(results) == 1
    result = read(results[0])
    provenance = result["transport_provenance"]
    assert provenance["identity_verified"] is False
    assert provenance["runtime_attestation"] is True
    assert "operator assertion only" in provenance["origin_basis"]
    assert provenance["session_sha256"] == hashlib.sha256((output / "session.json").read_bytes()).hexdigest()
    for turn in provenance["turn_evidence"]:
        record = output / turn["directory"] / "transport.json"
        assert turn["transport_record_sha256"] == hashlib.sha256(record.read_bytes()).hexdigest()
    assert not (output / "fixture-result.json").exists()


def test_operator_argv_is_passed_literally_without_shell(tmp_path):
    # This shell metacharacter string is a worker argument, never executable code.
    completed, _ = run_worker(tmp_path, "final & definitely-not-an-executable")
    assert completed.returncode == 0, completed.stderr
    assert (tmp_path / "invocations.txt").read_text().splitlines() == ["0"]


def test_turn_budget_stops_campaign_without_extra_attempt(tmp_path):
    completed, output = run_worker(tmp_path, scenario="memory-poisoning", options=("--max-turns", "1"))
    assert completed.returncode != 0
    assert (tmp_path / "invocations.txt").read_text().splitlines() == ["0"]
    assert read(output / "transport.json")["status"] == "inconclusive"


def process_alive(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                raise ctypes.WinError(ctypes.get_last_error())
            return code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A terminated orphan can remain a zombie briefly on Linux.
    stat = Path(f"/proc/{pid}/stat")
    return not (stat.exists() and stat.read_text().split(")", 1)[1].split()[0] == "Z")


@pytest.mark.parametrize("mode", ["child-timeout", "child-final"])
def test_worker_descendants_reaped_on_timeout_and_normal_exit(tmp_path, mode):
    try:
        completed, output = run_worker(tmp_path, mode, options=("--timeout-seconds", "1"))
        pid = int((tmp_path / "child.pid").read_text())
        deadline = time.monotonic() + 3
        while process_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not process_alive(pid), f"Task-owned worker descendant {pid} survived"
        assert completed.returncode == (0 if mode == "child-final" else 1), completed.stderr
    finally:
        # Only this fixture's exact child; prevents leaks even if transport regresses.
        pid_path = tmp_path / "child.pid"
        if pid_path.exists():
            pid = int(pid_path.read_text())
            if process_alive(pid):
                os.kill(pid, signal.SIGTERM)


def test_keyboard_interrupt_cleans_worker_tree_and_retains_cancel_record(tmp_path, monkeypatch):
    import _thread

    spec = importlib.util.spec_from_file_location("offline_transport_under_test", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "cancelled-run"
    monkeypatch.setattr(sys, "argv", [str(RUNNER), str(output), "--scenario", "unauthorized-closure",
        "--variant", "defended", "--agent-id", "offline-fixture-worker", "--mode", "dry-fixture",
        "--timeout-seconds", "10", "--", sys.executable, str(WORKER), "child-timeout", str(tmp_path)])
    stop = threading.Event()
    interrupted = threading.Event()

    def interrupt_after_child_starts():
        deadline = time.monotonic() + 5
        while not stop.wait(0.02) and time.monotonic() < deadline:
            if (tmp_path / "child.pid").exists():
                interrupted.set()
                _thread.interrupt_main()
                return

    interrupter = threading.Thread(target=interrupt_after_child_starts)
    interrupter.start()
    try:
        assert module.main() == 1
        assert interrupted.is_set()
        assert read(output / "turns/000/transport.json")["status"] == "cancelled"
        assert read(output / "session.json")["responses"] == []
        pid = int((tmp_path / "child.pid").read_text())
        deadline = time.monotonic() + 3
        while process_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_alive(pid)
    finally:
        stop.set()
        interrupter.join(timeout=6)
        pid_path = tmp_path / "child.pid"
        if pid_path.exists():
            pid = int(pid_path.read_text())
            if process_alive(pid):
                os.kill(pid, signal.SIGTERM)

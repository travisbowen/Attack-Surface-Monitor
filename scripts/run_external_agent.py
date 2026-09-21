"""Bounded, explicit subprocess transport for the frozen external-agent host.

Bridge contract: read one exact UTF-8 host envelope from stdin through EOF;
return one strict protocol reply on stdout, logs only on stderr, then exit zero.
One process is launched per envelope. Bridge must preserve the supplied session
identity and arrange a fresh authorized Astra target per trial in runtime mode.
This is transport, not a sandbox or a model-identity authentication mechanism.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_triage_lab import external_agent as host  # noqa: E402
from ai_triage_lab.runner import save_trial  # noqa: E402


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(path, value):
    path.write_bytes((json.dumps(value, indent=2, ensure_ascii=True,
                                allow_nan=False) + "\n").encode("utf-8"))


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


class _WindowsJob:
    """Kill-on-close job; assigned before any request bytes reach the bridge."""

    def __init__(self):
        from ctypes import wintypes as w

        class BASIC(ctypes.Structure):
            _fields_ = [("per_process", ctypes.c_int64), ("per_job", ctypes.c_int64),
                        ("flags", w.DWORD), ("min_ws", ctypes.c_size_t),
                        ("max_ws", ctypes.c_size_t), ("active", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
                        ("scheduling", w.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ("read_ops", "write_ops", "other_ops", "read", "write", "other")]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("basic", BASIC), ("io", IO),
                        ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t),
                        ("peak_process", ctypes.c_size_t),
                        ("peak_job", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            "SetInformationJobObject": ([w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
            "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
            "CloseHandle": ([w.HANDLE], w.BOOL),
        }
        for name, (args, result) in signatures.items():
            getattr(self.api, name).argtypes = args
            getattr(self.api, name).restype = result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = EXTENDED()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise error

    def assign(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self, errors):
        if self.handle:
            if not self.api.TerminateJobObject(self.handle, 1):
                errors.append("TerminateJobObject: " + str(ctypes.WinError(ctypes.get_last_error())))
            if not self.api.CloseHandle(self.handle):
                errors.append("CloseHandle(job): " + str(ctypes.WinError(ctypes.get_last_error())))
            self.handle = None


def _exchange(argv, request, directory, args):
    """Capture bounded byte prefixes. Never retry an ambiguous invocation."""
    started = time.monotonic()
    record = {"status": "spawn_error", "mode": args.mode, "measurement": False,
              "evidence_scope": "transport capture only; dry fixtures are unmeasured",
              "started_at": _now(), "pid": None,
              "returncode": None, "request_sha256": _hash(request),
              "request_bytes": len(request), "stdin_bytes_written": 0,
              "stdout_truncated": False, "stderr_truncated": False,
              "cleanup_errors": [], "timing_scope": "transport wall time, not model latency"}
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": args.max_stdout_bytes, "stderr": args.max_stderr_bytes}
    exceeded = threading.Event()
    io_errors = []
    threads = []
    process = None
    job = None

    def reader(name, pipe):
        try:
            while True:
                chunk = pipe.read(min(8192, limits[name] + 1 - len(outputs[name])))
                if not chunk:
                    break
                outputs[name].extend(chunk)
                if len(outputs[name]) > limits[name]:
                    record[name + "_truncated"] = True
                    exceeded.set()
                    break
        except (OSError, ValueError) as exc:
            io_errors.append(f"{name}: {exc}")
        finally:
            pipe.close()

    def writer():
        try:
            offset = 0
            while offset < len(request):
                count = process.stdin.write(request[offset:])
                if not count:
                    raise OSError("stdin write made no progress")
                offset += count
                record["stdin_bytes_written"] = offset
        except (OSError, ValueError) as exc:
            io_errors.append(f"stdin: {exc}")
        finally:
            process.stdin.close()

    try:
        if os.name == "nt":
            job = _WindowsJob()
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, bufsize=0,
                                   start_new_session=os.name != "nt",
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        record["pid"] = process.pid
        if job:
            job.assign(process)
        threads = [threading.Thread(target=reader, args=(name, getattr(process, name)), daemon=True)
                   for name in outputs]
        threads.append(threading.Thread(target=writer, daemon=True))
        for thread in threads:
            thread.start()
        while True:
            if exceeded.is_set():
                record["status"] = "stdout_limit" if record["stdout_truncated"] else "stderr_limit"
                break
            code = process.poll()
            if code is not None and not any(t.is_alive() for t in threads):
                record["status"] = "nonzero_exit" if code else ("io_error" if io_errors else "ok")
                break
            if time.monotonic() - started >= args.timeout_seconds:
                record["status"] = "timeout"
                break
            time.sleep(0.01)
    except KeyboardInterrupt:
        record["status"] = "cancelled"
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        errors = record["cleanup_errors"]
        if job:
            job.close(errors)
        elif process is not None and os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                errors.append(f"killpg({process.pid}): {exc}")
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"process {process.pid}: {exc}")
            deadline = time.monotonic() + 3
            for thread in threads:
                thread.join(timeout=max(0, deadline - time.monotonic()))
            if any(t.is_alive() for t in threads):
                errors.append("Bridge pipe threads still alive; inherited pipes may remain open")
            for name in ("stdin", "stdout", "stderr"):
                pipe = getattr(process, name)
                if pipe is not None and not pipe.closed:
                    try:
                        pipe.close()
                    except OSError as exc:
                        errors.append(f"close {name}: {exc}")
            record["returncode"] = process.returncode
        if errors and record["status"] == "ok":
            record["status"] = "cleanup_error"
        record["io_errors"] = list(io_errors)
        record["finished_at"] = _now()
        record["elapsed_seconds"] = time.monotonic() - started
        captured = {name: bytes(raw) for name, raw in outputs.items()}
        for name, raw in captured.items():
            record[name + "_captured_bytes"] = len(raw)
            record[name + "_sha256"] = _hash(raw)
        (directory / "response.bin").write_bytes(captured["stdout"])
        (directory / "stderr.bin").write_bytes(captured["stderr"])
        _json(directory / "transport.json", record)
    return record, captured["stdout"]


def _parser():
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Example (offline fixture): python scripts/run_external_agent.py out/fixture "
        "--scenario unauthorized-closure --variant defended --agent-id fixture-1 "
        "--mode dry-fixture -- C:/Python/python.exe C:/trusted/fixture_bridge.py. "
        "Fixture bridge: import sys; sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(b'{\"tool_calls\":[],\"final\":\"Fixture only.\"}'). "
        "Only trusted bridge executables: inherited permissions/environment are not sandboxed. "
        "Do not put credentials in argv: it is persisted as evidence."
    ))
    parser.add_argument("output", type=Path, help="exclusive NEW output directory; no resume/overwrite")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--variant", choices=("vulnerable", "prompt-only", "defended"), required=True)
    parser.add_argument("--agent-id", required=True, help="host-recorded target identity; not authentication")
    parser.add_argument("--mode", choices=("dry-fixture", "astra-runtime"), required=True)
    parser.add_argument("--attest-astra-runtime", action="store_true", help=(
        "operator asserts bridge returns actual authorized Astra runtime bytes; no identity proof"))
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=float, default=60)
    parser.add_argument("--max-request-bytes", type=int, default=256000)
    parser.add_argument("--max-stdout-bytes", type=int, default=64000)
    parser.add_argument("--max-stderr-bytes", type=int, default=64000)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if "--" not in argv:
        if "--help" in argv or "-h" in argv:
            parser.parse_args(argv)
        parser.error("required bridge argv after -- (absolute executable path)")
    split = argv.index("--")
    args = parser.parse_args(argv[:split])
    bridge = argv[split + 1:]
    if not bridge or not Path(bridge[0]).is_absolute() or not Path(bridge[0]).is_file():
        parser.error("bridge executable must be an existing absolute file path")
    if os.name == "nt" and Path(bridge[0]).suffix.lower() in {".cmd", ".bat"}:
        parser.error("Windows batch files invoke a shell; configure an executable instead")
    if not 1 <= args.max_turns <= 24:
        parser.error("max-turns must be 1..24")
    if not math.isfinite(args.timeout_seconds) or not 0 < args.timeout_seconds <= 3600:
        parser.error("timeout-seconds must be finite and in (0, 3600]")
    for name, maximum in (("max_request_bytes", 2000000), ("max_stdout_bytes", 64000),
                          ("max_stderr_bytes", 2000000)):
        if not 1 <= getattr(args, name) <= maximum:
            parser.error(f"{name.replace('_', '-')} must be 1..{maximum}")
    if args.mode == "astra-runtime" and not args.attest_astra_runtime:
        parser.error("astra-runtime requires --attest-astra-runtime")
    if args.mode == "dry-fixture" and args.attest_astra_runtime:
        parser.error("runtime attestation conflicts with dry-fixture mode")
    bridge[0] = str(Path(bridge[0]).resolve())
    try:
        # Fingerprint executable before creating outputs. Interpreter script argv is
        # recorded verbatim, but executable hash does not authenticate script/model.
        with open(bridge[0], "rb") as stream:
            executable_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        args.output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        parser.error(str(exc))
    manifest = {"schema_version": 1, "mode": args.mode, "measurement": False,
                "runtime_attestation": args.attest_astra_runtime,
                "identity_verified": False, "status": "running", "created_at": _now(),
                "bridge_argv": bridge, "bridge_executable_sha256": executable_hash,
                "transport_sha256": _hash(Path(__file__).read_bytes()),
                "timing_scope": "transport wall time only; not model latency",
                "limitations": ("Trusted bridge inherits environment and permissions; no sandbox. "
                                "Operator attestation is not model authentication. No retry/resume. "
                                "Dry fixtures are unmeasured; legacy host identity labels are not proof."),
                "bounds": {key: getattr(args, key) for key in
                           ("max_turns", "timeout_seconds", "max_request_bytes", "max_stdout_bytes", "max_stderr_bytes")},
                "turns": []}
    _json(args.output / "transport.json", manifest)
    session = args.output / "session.json"
    result = None

    def cancel(signum, frame):
        raise KeyboardInterrupt

    # Graceful SIGTERM (and Windows Ctrl+Break) uses the same cleanup path as
    # Ctrl+C. Forced process termination cannot promise durable evidence.
    previous_signals = {}
    for signum in (signal.SIGTERM, getattr(signal, "SIGBREAK", signal.SIGTERM)):
        if signum not in previous_signals:
            previous_signals[signum] = signal.signal(signum, cancel)
    try:
        pending = host.start(session, args.scenario, args.variant, args.agent_id,
                             max_turns=args.max_turns)
        manifest["session_id"] = pending["session_id"]
        for index in range(args.max_turns):
            turn = args.output / "turns" / f"{index:03d}"
            turn.mkdir(parents=True, exist_ok=False)
            raw = (json.dumps(pending, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
            (turn / "request.json").write_bytes(raw)
            row = {"index": index, "request_hash": pending["request_hash"],
                   "request_sha256": _hash(raw), "directory": f"turns/{index:03d}",
                   "status": "prepared", "submitted_to_host": False}
            manifest["turns"].append(row)
            _json(args.output / "transport.json", manifest)
            if len(raw) > args.max_request_bytes:
                row["status"] = "request_limit"
                manifest["status"] = "transport_error"
                break
            record, response = _exchange(bridge, raw, turn, args)
            row.update(status=record["status"], response_sha256=_hash(response))
            if record["status"] != "ok":
                manifest["status"] = "transport_error"
                break
            # Host performs strict UTF-8/schema validation and retains malformed
            # replies unchanged. Never pre-parse, strip fences, repair, or retry.
            pending, result = host.submit(session, response, agent_id=args.agent_id,
                                          request_hash=row["request_hash"])
            row["submitted_to_host"] = True
            _json(args.output / "transport.json", manifest)
            if pending is None:
                status = result["execution"]["status"]
                manifest["status"] = "completed" if status == "completed" else (
                    "host_error" if status == "error" else "inconclusive")
                break
        else:
            manifest["status"] = "inconclusive"
        if manifest["status"] in {"completed", "host_error", "inconclusive"} and result is not None:
            if args.mode == "dry-fixture":
                _json(args.output / "fixture-result.json", {
                    "measurement": False, "mode": args.mode,
                    "warning": "Unmeasured offline fixture; host identity labels do not establish runtime origin.",
                    "host_result": result})
            else:
                result["transport_provenance"] = {
                    "mode": args.mode,
                    "origin_basis": "operator assertion only; no independent model authentication",
                    "runtime_attestation": True,
                    "identity_verified": False,
                    "bridge_argv": bridge,
                    "bridge_executable_sha256": executable_hash,
                    "transport_sha256": manifest["transport_sha256"],
                    "session_sha256": _hash(session.read_bytes()),
                    "timing_scope": manifest["timing_scope"],
                    "limitations": manifest["limitations"],
                    "turn_evidence": [
                        {"directory": row["directory"],
                         "transport_record_sha256": _hash(
                             (args.output / row["directory"] / "transport.json").read_bytes())}
                        for row in manifest["turns"]
                    ],
                }
                save_trial(args.output / "trials", result)
                manifest["measurement"] = True
                manifest["measurement_basis"] = "operator-attested runtime origin, not independently authenticated"
    except KeyboardInterrupt:
        manifest["status"] = "cancelled"
    except Exception as exc:
        manifest["status"] = "host_error"
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        manifest["finished_at"] = _now()
        _json(args.output / "transport.json", manifest)
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
    print(json.dumps({"status": manifest["status"], "mode": args.mode,
                      "output": str(args.output.resolve()), "measurement": manifest["measurement"]}))
    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

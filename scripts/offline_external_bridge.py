"""Deterministic transport fixture, never a model or runtime measurement.

Consumes one host envelope unchanged and returns a fixed harmless final reply.
Use ONLY with run_external_agent.py --mode dry-fixture.
"""
import sys


def main():
    if len(sys.stdin.buffer.read(2_000_001)) > 2_000_000:
        return 1
    sys.stdout.buffer.write(
        b'{"tool_calls":[],"final":"Offline transport fixture only; no model inference."}'
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

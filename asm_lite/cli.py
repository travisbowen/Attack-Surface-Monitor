from __future__ import annotations

"""
CLI entrypoint for the Attack Surface Monitor project.
This module orchestrates the following components:
- the pipeline controller
- the contract between user input and internal modules
"""

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from asm_lite.discover import discover_subdomains
from asm_lite.resolve import resolve_hosts
from asm_lite.probe import probe_http


def utc_now_iso() -> str:
    """
    Return the current UTC timestamp in ISO-8601 format.

    - Ensures all timestamps are timezone-safe
    - Makes outputs consistent for diffing / historical tracking
    - Avoids local-time ambiguity later when I add drift detection
    """
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    """
    Define and parse CLI arguments.

    This function is intentionally isolated so:
    - argument logic is not mixed with scanning logic
    """
    p = argparse.ArgumentParser(
        prog="attack-surface-monitor",
        description="ASM-lite: discover subdomains, resolve DNS, " "probe HTTP(S), and emit structured JSON outputs.",
    )
    # Root domain to scan (required)
    p.add_argument("--domain", required=True, help="Root domain to scan (e.g., example.com)")
    # Output directory (default: out/)
    p.add_argument("--out", default="out", help="Output directory (default: out)")
    # Max subdomains to discover (default: 200)
    p.add_argument("--max-subdomains", type=int, default=200, help="Cap discovery results")
    # HTTP timeout seconds (default: 8.0)
    p.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout seconds")
    return p.parse_args()


def main() -> int:
    """
    Main execution pipeline.

    Order of operations:
    1. Parse & validate input
    2. Discover potential assets
    3. Resolve them to IPs
    4. Probe exposed HTTP(S) services
    5. Persist results to disk
    """
    args = parse_args()

    domain = args.domain.strip().lower()
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise SystemExit(f"Invalid domain: {args.domain}")

    # Prepare output directory
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------
    # 1) Subdomain discovery
    # -----------------------------
    # Uses certificate transparency to enumerate likely subdomains.
    # This is passive, low-risk, and fast.
    subs = discover_subdomains(domain, limit=args.max_subdomains)

    # -----------------------------
    # 2) DNS resolution
    # -----------------------------
    # Resolve each discovered hostname to A/AAAA records.
    # Output remains hostname-centric to preserve intent.
    assets = resolve_hosts(subs)

    # -----------------------------
    # 3) HTTP(S) probing
    # -----------------------------
    # Actively probe standard web endpoints to understand exposure.
    # No exploitation — metadata only.
    http_findings = probe_http(assets, timeout=args.timeout)

    # -----------------------------
    # 4) Persist outputs
    # -----------------------------
    # Meta file exists so future scans can be compared chronologically.
    (out_dir / "meta.json").write_text(json.dumps({"domain": domain, "generated_at": utc_now_iso()}, indent=2))

    # Raw asset inventory
    (out_dir / "assets.json").write_text(json.dumps(assets, indent=2))

    # HTTP exposure results
    (out_dir / "http.json").write_text(json.dumps(http_findings, indent=2))

    print(f"[OK] Wrote outputs to: {out_dir}")
    print(f" - assets.json: {len(assets)} hosts")
    print(f" - http.json:   {len(http_findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

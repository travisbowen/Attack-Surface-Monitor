from __future__ import annotations

"""
CLI entrypoint for the Attack Surface Monitor project.
This module orchestrates the following components:
- the pipeline controller
- the contract between user input and internal modules
"""

import argparse
import json
import ipaddress
import math
from importlib.resources import files
from pathlib import Path
from datetime import datetime, timezone

from asm_lite.discover import discover_subdomains
from asm_lite.resolve import resolve_hosts
from asm_lite.probe import probe_http
from asm_lite.report import write_html_report
from asm_lite.score import score_http_findings
from asm_lite.intent import annotate_http_findings
from asm_lite.scope import normalize_domain


# Resolved from this file's location, not the current working directory, so the
# CLI works when invoked from anywhere. A relative Path("templates") only
# resolved correctly when the process happened to start in the repo root.
_TEMPLATE_DIR = Path(str(files("asm_lite").joinpath("templates")))


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
    p.add_argument("--allow-cidr", action="append", default=[], help="Explicitly authorize non-global addresses within this CIDR")
    p.add_argument("--max-requests", type=int, default=400)
    p.add_argument("--max-redirects", type=int, default=3)
    p.add_argument("--max-response-bytes", type=int, default=262144)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--requests-per-second", type=float, default=5.0)
    p.add_argument("--max-duration", type=float, default=120.0, help="HTTP probe phase wall-time budget; excludes discovery and system DNS")
    p.add_argument("--vantage", default="operator-network", help="Operator-provided network location label; not proof of public reachability")
    args = p.parse_args()
    try:
        args.domain = normalize_domain(args.domain)
        for cidr in args.allow_cidr:
            ipaddress.ip_network(cidr, strict=True)
        for label, low, high in (("max_subdomains", 1, 1000), ("max_requests", 1, 10000),
                                 ("max_redirects", 0, 10), ("max_response_bytes", 1, 2097152),
                                 ("concurrency", 1, 50)):
            if not low <= getattr(args, label) <= high:
                raise ValueError(f"{label} must be in [{low}, {high}]")
        for label, high in (("timeout", 120), ("requests_per_second", 100), ("max_duration", 3600)):
            value = getattr(args, label)
            if not math.isfinite(value) or not 0 < value <= high:
                raise ValueError(f"{label} must be positive and at most {high}")
    except ValueError as exc:
        p.error(str(exc))
    return args


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

    domain = args.domain

    # Prepare output directory
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------
    # 1) Subdomain discovery
    # -----------------------------
    # Uses certificate transparency to enumerate likely subdomains.
    # This is passive, low-risk, and fast.
    discovery = {}
    subs = discover_subdomains(domain, limit=args.max_subdomains, metadata=discovery)

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
    http_findings = probe_http(
        assets, timeout=args.timeout, domain=domain, allowed_cidrs=args.allow_cidr,
        max_requests=args.max_requests, max_redirects=args.max_redirects,
        max_response_bytes=args.max_response_bytes, concurrency=args.concurrency,
        requests_per_second=args.requests_per_second, max_duration=args.max_duration,
        vantage=args.vantage,
    )

    # Intent inference: classify surfaces + flag potential exposure mismatches
    http_findings = annotate_http_findings(http_findings)

    # Risk scoring: numeric prioritization + reasons (sorted highest first)
    http_findings = score_http_findings(http_findings)

    # -----------------------------
    # 4) Persist outputs
    # -----------------------------
    # Meta file exists so future scans can be compared chronologically.
    (out_dir / "meta.json").write_text(json.dumps({
        "schema_version": "asm-observation-v2", "domain": domain, "generated_at": utc_now_iso(),
        "vantage": {"label": args.vantage, "source": "operator-provided", "public_reachability_verified": False},
        "discovery": discovery, "dns_complete": all(a["dns_complete"] for a in assets),
        "probe_complete": all(f["complete"] for f in http_findings),
        "completeness": {
            "complete": bool(discovery.get("complete")) and all(a["dns_complete"] for a in assets) and all(f["complete"] for f in http_findings),
            "discovery_complete": discovery.get("complete", False),
            "dns_complete": all(a["dns_complete"] for a in assets),
            "probe_complete": all(f["complete"] for f in http_findings),
            "dns_failure_count": sum(not a["dns_complete"] for a in assets),
            "probe_incomplete_count": sum(not f["complete"] for f in http_findings),
            "exhaustive": False,
        },
        "exhaustive": False, "address_sampling": "first-approved-IP-per-host",
        "limits": {key: getattr(args, key) for key in
                   ("max_subdomains", "timeout", "max_requests", "max_redirects", "max_response_bytes",
                    "concurrency", "requests_per_second", "max_duration", "allow_cidr")},
        "limitations": ["CT inventory is not exhaustive", "System DNS uses OS resolver timeouts",
                        "Probe wall-time excludes discovery and DNS", "Scores are uncalibrated review heuristics"],
    }, indent=2))

    # Raw asset inventory
    (out_dir / "assets.json").write_text(json.dumps(assets, indent=2))

    # HTTP exposure results
    (out_dir / "http.json").write_text(json.dumps(http_findings, indent=2))

    report_path = write_html_report(
        out_dir=out_dir,
        domain=domain,
        assets=assets,
        http_findings=http_findings,
        template_dir=_TEMPLATE_DIR,
    )

    print(f"[OK] Wrote outputs to: {out_dir}")
    print(f" - assets.json: {len(assets)} hosts")
    print(f" - http.json:   {len(http_findings)} findings")
    print(f" - report.html: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

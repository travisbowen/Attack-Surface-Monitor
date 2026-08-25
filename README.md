# Attack Surface Monitor

Intent-aware attack surface discovery and HTTP exposure monitoring.

This project passively discovers subdomains via certificate transparency,
resolves them to IPs, probes exposed HTTP(S) services, and emits structured
outputs for analysis and future drift detection.

The tool focuses on visibility and prioritization, not exploitation.

## Usage & Scope

This tool is intended for use **only** on systems and domains that you own
or have **explicit authorization** to test.

It performs passive discovery and non-intrusive HTTP probing, but it should
still be operated within a clearly defined and approved scope.

### Quick Start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m asm_lite.cli --domain example.com --out out
```

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--domain` | required | Root domain to scan |
| `--out` | `out` | Output directory |
| `--max-subdomains` | `200` | Cap on discovery results |
| `--timeout` | `8.0` | Per-request HTTP timeout, seconds |

### Outputs

A run writes four files into the output directory:

| File | Contents |
| --- | --- |
| `meta.json` | Domain and UTC timestamp, so runs can be diffed chronologically |
| `assets.json` | Hostname inventory, each with its resolved IPs |
| `http.json` | One record per attempted URL, annotated with intent and risk score, sorted highest risk first |
| `report.html` | Human-readable report: top risks, asset inventory, per-finding detail |

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite is fully offline. Certificate transparency lookups, HTTP probing, and
TLS certificate reads are all stubbed, so no test sends traffic to any host.

Layout:

| Module | Responsibility |
| --- | --- |
| `asm_lite/discover.py` | Certificate transparency enumeration and scope enforcement |
| `asm_lite/resolve.py` | Hostname to IP resolution |
| `asm_lite/probe.py` | HTTP(S) metadata probing |
| `asm_lite/intent.py` | Surface classification and exposure mismatch flagging |
| `asm_lite/score.py` | Explainable risk scoring |
| `asm_lite/report.py` | HTML rendering |
| `asm_lite/cli.py` | Pipeline orchestration |

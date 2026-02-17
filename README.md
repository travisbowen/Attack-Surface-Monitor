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

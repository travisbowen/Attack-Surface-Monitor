# Attack Surface Monitor + AI Triage Lab

Current source version: **0.3.0**. Earlier 0.2.0 verification remains historical;
release artifacts and empirical evidence are recorded separately.

A Python portfolio project connecting bounded HTTP exposure observations to a
synthetic GenAI security evaluation lab. The scanner collects evidence; the lab
tests what happens when an AI analyst consumes attacker-controlled evidence and
chooses tools with more authority than the content should have.

**Evidence level:** offline scripted experiments demonstrate harness behavior
and application controls. A separate [external-agent runtime pilot](docs/astra-runtime-pilot.md)
records actual GPT-6 Astra agent behavior on synthetic tasks, with inherited runtime
instructions/tools and limited coverage. It is not a direct API benchmark or evidence
of broad injection resistance. Eight planned exposures yielded seven evaluable trials
and one invalid relay: 7/7 legitimate tasks succeeded; 0/4 attack objectives achieved.
Repeated direct-provider comparison tooling is implemented;
that benchmark remains pending provider configuration.

## Install and demonstrate

Requires Python 3.11 or later; local release verified with Python 3.12 on Windows.
From a clone:

```bash
python -m venv .venv
# Activate: source .venv/bin/activate (POSIX), .venv\Scripts\Activate.ps1 (PowerShell)
python -m pip install ".[dev]"
ai-triage-lab run --suite all --out out/demo
python -m pytest -q
```

Open the printed run directory's `report.html`. Sixteen scenarios across three
variants produce 48 trials: eight basic cases and eight advanced campaigns,
including six benign controls. Every trial starts with fresh synthetic state.
Campaign phases share a bounded session. No model service or live scan is needed.
Installed commands also work outside the checkout; fixtures, scenarios, scanner
templates, and self-contained dashboard assets are included in the wheel.

| Component | Demonstrates |
| --- | --- |
| `asm-lite` | Scoped discovery, approved connection/redirect addresses, bounded HTTP collection, explicit errors and vantage/completeness metadata |
| `ai-triage-lab` | Vulnerable, prompt-only, and application-enforced tool gateways; deterministic receipt/state evaluation; offline evidence dashboard |
| Advanced campaigns | Trial-local memory, poisoned retrieval and tool descriptions, staged multi-turn manipulation, matched controls |
| `ai-triage-experiment` | No-network preflight, repeated randomized model comparisons, usage/budget tracking and incomplete-trial denominators |
| Optional PyRIT 1.1 | Single-prompt `PromptSendingAttack` bridge with the lab's business-effect evaluator |

The vulnerable variant is deliberate. Prompt-only equals vulnerable under the
scripted adapter because scripted actions do not interpret prompts. Defended
results establish the tested host policy, not universal prompt-injection immunity.

## Scanner usage and boundaries

Only scan domains and systems you own or are explicitly authorized to test.
The command below is a placeholder: replace it with your authorized domain.

```bash
asm-lite --domain YOUR-AUTHORIZED-DOMAIN --out out/scan --vantage operator-network
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--domain` | required | Root domain and subdomain scope |
| `--out` | `out` | Output directory |
| `--max-subdomains` | `200` | Discovery cap |
| `--timeout` | `8` | HTTP request timeout, seconds |
| `--allow-cidr` | none | Repeat to explicitly authorize non-global address ranges |
| `--max-requests` | `400` | HTTP request budget |
| `--max-redirects` | `3` | Redirect limit |
| `--max-response-bytes` | `262144` | Response body cap |
| `--concurrency` | `10` | Concurrent probe limit |
| `--requests-per-second` | `5` | Request rate limit |
| `--max-duration` | `120` | HTTP phase seconds; excludes discovery and system DNS |
| `--vantage` | `operator-network` | Operator label; does not prove public reachability |

Outputs: `meta.json` (`asm-observation-v2`, limits and completeness), `assets.json`
(DNS inventory), `http.json` (observations, explicit errors, heuristic scores),
and escaped `report.html`. Discovery is not exhaustive; one approved IP per host
is sampled. OS DNS timeouts are outside the HTTP phase deadline. Scores prioritize
review and are not verified vulnerabilities. Importing saved JSON never scans.

## Portfolio and research

- [Demo walkthrough](docs/portfolio-demo.md): attacks, controls, evidence, and dashboard.
- [Lab guide](docs/ai-triage-lab.md), [advanced campaigns](docs/advanced-campaigns.md), [threat model](docs/threat-model.md).
- [Results dashboard](docs/results-dashboard.md): offline filtering and cross-run comparison.
- [Unauthorized closure case study](docs/case-studies/unauthorized-closure.md) and [memory poisoning case study](docs/case-studies/memory-poisoning.md).
- [External-agent runtime pilot](docs/astra-runtime-pilot.md): actual agent replies, synthetic tool effects, invalid-trial accounting, and research limitations.
- [Model experiment protocol](docs/model-experiments.md): direct-provider configuration and spending boundaries.
- [Local release guide](docs/local-release.md), [verification record](docs/lab-verification.md), [implementation plan](docs/implementation-plan.md).

Default tests and demos are offline. Dependency installation requires access to
your package source. Optional PyRIT setup is separate; CI includes core tests,
wheel installation outside the checkout, and optional integration coverage.
No package publication, hosted deployment, or hosted multi-user service is included.

# Portfolio demonstration

This is an offline, synthetic application-security demonstration. No live model
findings, real vulnerabilities, external tickets, or production permissions are
claimed. Allow about ten minutes after installation. Use Python 3.11+ and install
with `python -m pip install ".[dev]"` from a clone.

## 1. Generate the comparison

```bash
ai-triage-lab run --suite all --out out/portfolio
```

The command prints a new run directory. Open its `report.html` locally. It contains
48 scripted trials: sixteen scenarios, three variants, one repeat. Six scenarios
are controls; ten are attacks. Explain why prompt-only and vulnerable results
match: the scripted adapter executes predefined actions and does not read prompts.

## 2. Show an authorization failure and its fix

Filter to `unauthorized-closure`. Open evidence details for vulnerable and defended
trials. Compare the same task and payload. The vulnerable receipt records an
unauthorized execution and the final ticket is closed. Defended execution is
blocked and the ticket remains open while the report is published. Then inspect
`normal-workflow`: authorized closure with a trusted passing recheck still works.
See the [closure case study](case-studies/unauthorized-closure.md).

## 3. Show a stateful attack and its control

Filter to `memory-poisoning`. Inspect the `plant` and `recall` phases, stored memory
provenance, actual tool receipts, and final ticket state. Compare
`memory-poisoning-control`: a permitted analyst note must be read back in a later
phase. Read the [memory case study](case-studies/memory-poisoning.md) for the narrow
claim established by this experiment. Retrieval, metadata and multi-turn cases
use the same unauthorized-closure objective with different lower-trust surfaces.

## 4. Inspect evidence and compare runs

Each trial directory has `result.json` and `events.jsonl`. Results include initial
and final state, scenario/configuration hashes, phase evidence, actual actions,
and separate attack/task/completion outcomes. Hash chains detect modifications
relative to a trusted saved head; they are not signed audit logs.

Generate another run, then substitute the two printed directory paths below:

```bash
ai-triage-lab compare RUN_DIRECTORY_A RUN_DIRECTORY_B --out out/comparison
```

The output directory must be new. The [dashboard guide](results-dashboard.md)
explains filters and comparison groups. Inspect errors, unknown outcomes and
denominators alongside success rates; absence of completed evidence is not a
successful defense. Filters narrow the trial/matrix view; headline totals retain
their documented scope. No external assets or telemetry are required.

## 5. Explain what remains unmeasured

Use [model experiment preflight](model-experiments.md) to prepare repeated trials
without network calls. Actual execution requires explicit compatible endpoint,
model/version, configuration, and authorized spending limits. Neither mocked
transport tests nor scripted results establish susceptibility of a real LLM.
Real scanning is separate, requires authorization, and is not part of this demo.

The portfolio demonstrates trust-boundary design, negative controls, safe tool
gateways, reproducible evidence, deployment packaging, and measured limitations.
It does not establish production readiness of an autonomous security analyst.

# Portfolio demonstration

This walkthrough generates offline synthetic application-security evidence and
then inspects an archived live-agent pilot without making model calls. No real
vulnerabilities, external tickets, or production permissions are claimed. Allow
about ten minutes after installation. Use Python 3.11+ and install with
`python -m pip install ".[dev]"` from a clone.

Start with the engineering question: can an AI analyst consume hostile findings
without treating their instructions as authority? Show one unauthorized action,
the host control that blocks it, and a benign task that still succeeds. Then
separate what scripted tests prove from what the small live pilot observed.

## Short recorded terminal demo

From the source checkout, use the standard-library recorder with the installed
project's Python interpreter:

```bash
python scripts/record_portfolio_demo.py --out out/public-demo
```

Choose a new output directory each time. The recorder executes three actual
offline CLI trials: unauthorized closure against vulnerable and defended hosts,
then normal authorized workflow against the defended host. It displays actual
tool receipts, ticket state, and outcomes from the newly saved results, then
executes the archived pilot verifier. No provider or browser is used.

`portfolio-demo.cast` is an asciicast v2 terminal recording, captured from timed
process stdout/stderr pipes. It is **not browser video or a PTY screen capture**.
Recorder labels identify command headings and exit codes; the displayed `python`
alias means the interpreter running the recorder. Worker output summarizes saved
CLI artifacts; complete underlying CLI stdout is retained in `*-cli.txt` files.
Raw captured worker/verifier output is retained in `command-*-stdout.bin`.
Newlines alone are normalized to CRLF for terminal playback. Eight-second reading
pauses are real elapsed time, not altered timestamps; `--pause 0` removes them.

Play the recording with an existing asciinema-compatible player, for example
`asciinema play out/public-demo/portfolio-demo.cast`, or read `transcript.txt`
without installing anything. `recording.json` retains command exit codes and
measured timings. The output also contains each generated report and independent
trial evidence. The recording is normally under one minute with default pauses.
No renderer, player, or browser is installed or started by the recorder.

The September 22, 2026 recording and its transcript are preserved locally under
`out/public-demo-20260922/` for release attachment. It demonstrates scripted host
behavior and verifies existing pilot evidence; it creates no new model research
and does not resolve the outstanding browser-verification limitation.

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

## 5. Inspect archived live-agent evidence

Open the [Astra runtime pilot](astra-runtime-pilot.md) and its
[evidence bundle](../research/astra-runtime-pilot/README.md). These are actual
external-agent replies on synthetic tasks, separate from the 48 scripted trials.
Eight exposures yielded seven evaluable trials and one invalid relay, retained
without retry. Legitimate tasks succeeded in 7/7 evaluable trials; attack
objectives succeeded in 0/4 valid attack trials. Inspect invalid trial 04 to show
why an orchestration error cannot count as a successful defense.

From repository root, verify the archive without calling a model:

```bash
python research/astra-runtime-pilot/verify_bundle.py
```

The verifier checks all 31 preserved replies and seven valid reconstructions,
including event chains and final state. Verified path-format equivalence allows
replay without rewriting the archived evidence. Actual Linux and Windows hosted
CI also passed archived reconstruction and installed-wheel verification.

The pilot inherited runtime instructions/tools and lacks provider snapshot,
sampling, usage, cost, and inference-latency data. Four unsuccessful attack
trials do not establish robustness or incremental defense benefit when both
variants avoid the attack.

## 6. Optionally demonstrate automatic transport

The [source-only transport guide](external-agent-transport.md) includes a
PowerShell offline command using an absolute Python executable path. Run it from
the checkout with a new output directory, then inspect `transport.json`, captured
request/response bytes, and `fixture-result.json` with `measurement: false`.
The fixture demonstrates protocol completion, not successful security analysis.

Explain the controls: bounded input/output and time, exact reply submission,
process-tree cleanup, preserved failures, and no automatic retries. The runner
requires a trusted operator-supplied executable; it is not a sandbox. The bundled
Codex CLI bridge has a separately recorded launch failure; operator attestation
does not authenticate a model.
This optional fixture creates no new live measurement.

## 7. Explain what remains unmeasured

Use [model experiment preflight](model-experiments.md) to prepare repeated trials
without network calls. Actual execution requires explicit compatible endpoint,
model/version, configuration, and authorized spending limits. Neither mocked
transport tests nor scripted results establish susceptibility of a real LLM.
Real scanning is separate, requires authorization, and is not part of this demo.
The [verification record](lab-verification.md) separates historical full-suite
and wheel checks from later focused transport and portability checks. Actual
browser rendering remains unverified. Hosted Linux/Windows CI passed; see the
dated record for exact commits. Inspect the separately preregistered
[native repeats](../research/native-runtime-repeats/README.md) without pooling
their file-worker method with the original pilot or blocked CLI attempt.

The portfolio demonstrates trust-boundary design, negative controls, safe tool
gateways, reproducible evidence, deployment packaging, and measured limitations.
It does not establish production readiness of an autonomous security analyst.

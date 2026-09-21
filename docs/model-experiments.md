# Model comparison protocol

No live model results have been collected for this release. Mock HTTP tests verify
transport and evidence handling only. Provider endpoint, model/version and hosted
spending authorization remain required before collecting empirical findings.

Create explicit configurations under ignored `out/`, one per model/version or
sampling configuration. Example for an operator-managed local service:

```json
{
  "endpoint": "http://localhost:8000/v1/chat/completions",
  "model": "REPLACE-WITH-EXACT-MODEL-VERSION",
  "max_requests": 400,
  "max_turns": 8,
  "max_completion_tokens": 800,
  "max_total_tokens": 600000,
  "timeout_seconds": 30,
  "trial_timeout_seconds": 120,
  "temperature": 0,
  "seed": 42
}
```

Use a Chat Completions compatible endpoint supporting function tools and usage
counts. Sampling fields are optional; omit unsupported parameters. Hosted HTTPS
endpoints read credentials from `ASM_LAB_API_KEY` or configured `api_key_env`;
never put credential values in files or chat. Record an immutable model version
when available. Response model names and system fingerprints are captured in
evidence but do not guarantee immutable provider behavior.

Prepare a manifest without credentials or network calls:

```bash
python -m ai_triage_lab.experiment --model-config out/model-a.json --model-config out/model-b.json --suite all --repeats 3 --seed 20260921
```

Inspect configuration, request budgets, scenario hashes and randomized schedule.
Run the same command with `--execute` only after configuring an approved provider.
An identical seed reproduces the schedule; it does not guarantee identical model
outputs. The experiment creates a fresh manifest and output directory each time.
For a small initial run, select both an attack and its control using repeated
`--scenario` options. Example: `--scenario memory-poisoning --scenario memory-poisoning-control`.

Each configuration owns one adapter-wide request/token budget. Every trial gets
fresh target state; campaign phases retain conversation, tool results, final
assistant responses, memory and cumulative tool budget. Trial deadline spans
all phases. Validated calls execute sequentially, and later model turns receive
actual tool receipts. Untrusted tool descriptions are presented as configured.
Malformed multi-call messages are validated before any of their actions execute.

The output includes `experiment-plan.json`, per-trial evidence, an incrementally
updated `experiment-summary.json`, and the offline comparison dashboard. Pair IDs
associate scenario/repetition across variants/configurations. Request order is
randomized to reduce systematic ordering bias; no claim of statistical power is
made from the default three repeats. Per-scenario denominators remain available
alongside pooled summaries. Compare successful controls and legitimate task
completion as well as attack objectives. Failure of a control is not automatically
a model refusal. Scenarios cover fixed synthetic objectives, not adaptive search.

Only completed attack trials enter attack-rate denominators. Error/inconclusive
trials remain visible; observed side effects in incomplete trials are retained.
Missing provider usage stops subsequent requests across the configuration.
Saved trial artifacts and the last complete summary survive interrupted runs;
the summary explicitly counts unrecorded trials and marks an incomplete schedule.
An interruption during the current trial can lose that trial's in-memory evidence;
reconcile provider usage externally before restarting. Absent trials must never
be interpreted as successes. Model claims alone do not establish tool effects.

`max_total_tokens` is a post-response stopping threshold and can overshoot by one
request. Optional `max_cost_usd` requires both `input_usd_per_million` and
`output_usd_per_million`; the adapter reserves an estimated next-request cost
using request bytes and completion allowance before sending. This conservative
estimate is **not a strict provider billing cap**: hidden tokens, billing rules
and incorrect supplied prices can differ. Set provider-side spending controls.
Request counts and requested output limits remain bounded independently. No
automatic retries or redirects occur. Underbudgeted configurations can produce
many inconclusive trials; inspect planned size before execution.

PyRIT 1.1 remains a single-prompt injection bridge. Native experiment execution
provides the multi-phase campaign protocol; the bridge does not claim persistent
PyRIT conversation support or adaptive attack optimization.

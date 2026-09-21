# ASM AI Triage Lab

Python 3.12. Run commands from the repository root. The default lab needs only
Python's standard library; the model adapter uses the existing `httpx` dependency.

## Offline demonstration

```bash
python -m ai_triage_lab.cli run
python -m ai_triage_lab.cli run --scenario unauthorized-closure --variant all
python -m pytest -q
```

Each run creates a new timestamped directory under `out/ai-triage-lab` containing:

- `report.html`: escaped, static comparison with no external resources.
- `summary.json`: outcomes and denominators by target variant.
- `<trial-id>/result.json`: scenario, configuration, implementation/prompt/tool
  hashes, execution statistics, evaluation, initial/final state, and events.
- `<trial-id>/events.jsonl`: ordered evidence chain with tool receipts.

Exit code 0 means all requested trials completed. It does **not** mean every
attack failed: the vulnerable baseline is supposed to fail. Exit code 2 means
invalid CLI input or at least one error/inconclusive trial. A completed trial can
still have a failed legitimate task.

The scripted adapter replays scenario actions. It does not infer actions from
payload text, and cannot evaluate new payload effectiveness. The prompt-only
variant therefore intentionally matches the vulnerable variant in scripted runs.

## Existing scanner observations

```bash
python -m ai_triage_lab.cli import-asm fixtures/asm-example --out out/imported-example.json
python -m ai_triage_lab.cli run --scan-dir fixtures/asm-example --finding-index 0
```

Replace `fixtures/asm-example` with a saved scan directory containing `meta.json`,
`assets.json`, and `http.json`. Import validates bounded JSON and preserves raw
observations, source hashes, and heuristic scores. Missing completeness/vantage
metadata remains `unknown`. The importer does not overwrite an existing output.

`--scan-dir` uses the selected observation as background for lab `finding-a`.
Tenant identity and ticket data remain synthetic. Scenario payloads overlay their
declared title/header field; the original imported row and overlay are retained
separately in evidence. This is an attack experiment, not automatic vulnerability
classification of the imported asset. Files are never fetched as URLs.

## Real-model experiments

Copy `fixtures/model-config.example.json` to your own configuration file. Set an
explicit tool-capable model and full Chat Completions endpoint. Loopback HTTP is
allowed for local servers; remote endpoints require HTTPS. For authenticated
services set the credential environment variable named by `api_key_env` in your
own shell. Never put credentials in the JSON, endpoint URL, or scenario.

```bash
python -m ai_triage_lab.cli run --adapter model --model-config path/to/model-config.json --scenario unauthorized-closure
```

Selecting the model adapter initiates model requests. No provider/model is chosen
automatically. The lab implements the
[Chat Completions tool-call contract](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
to support compatible hosted and local services. It does not claim all providers
or models accept every field. `token_parameter` can be `max_completion_tokens`
(default) or `max_tokens` for compatible servers requiring the older name.

Boundaries:

- `max_requests` applies across the entire command, not separately to each trial.
- `max_turns`, `max_completion_tokens`, request-body byte limit, timeout, trial
  deadline, and 24-tool hard ceiling constrain execution.
- `max_total_tokens` is a **post-response stop threshold** based on provider usage,
  not a prepaid token ceiling. One request can cross it. Provider billing and
  tokenizer behavior remain outside this application's control.
- Missing usage or transport errors stop further requests through that adapter.
  No automatic retry or redirect following occurs.
- Cost is reported only when both token rates are supplied and usage is known;
  it is an estimate using your rates, not a provider invoice or spending cap.

Trials create fresh sessions and state. For a preliminary model experiment, use
`--trials 10` and size the shared request budget accordingly. Compare model,
prompt, tools, scenario, framework and implementation versions. Report incomplete
trials separately. Hosted outputs can vary despite fixed settings.

When combining `--scan-dir` with a remote model, selected stored observations are
sent to that explicitly configured service. Use synthetic or approved data.

## Optional PyRIT integration

The bridge targets **PyRIT 1.1.0**, currently maintained at
[Microsoft/PyRIT](https://github.com/microsoft/PyRIT). Use a separate virtual
environment to keep its large dependency set separate from the small scanner setup.

```bash
python -m venv .venv-pyrit
# Activate .venv-pyrit using your shell's activation command.
python -m pip install -r requirements-pyrit.txt
python -m pytest tests/ai_triage_lab/test_pyrit.py -q
python -m ai_triage_lab.pyrit_demo
```

The demo uses PyRIT's `PromptSendingAttack`, with retries disabled, against both
target variants. Default adapter remains scripted. Add `--model-config` to use
real model calls. PyRIT orchestrates delivery; the lab evaluates actual business
effects. Without an objective scorer PyRIT's own outcome can be undetermined;
the returned lab evaluation and saved receipts are the authoritative lab result.

`TriagePyRITTarget` accepts single-turn text attacks. Each incoming prompt becomes
the scenario's untrusted title/header, never a trusted operator message. Titles
over 200 characters are rejected rather than silently truncated. Calls serialize
to preserve shared model budgets. Every attack starts a fresh target session.

PyRIT's installed package creates its own data directories during import. In a
restricted Windows environment those default AppData paths may be unavailable.
A supported source checkout keeps PyRIT data inside that checkout. This workspace
was verified with tag `v1.1.0` in `out/pyrit-src` and an isolated environment in
`out/pyrit-venv`. Automated cleanup of those disposable setup directories was
blocked by execution policy. They remain until manual cleanup. While present,
the PowerShell demo command is:

```powershell
.\out\pyrit-venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'out/pyrit-src'); from ai_triage_lab.pyrit_demo import main; raise SystemExit(main())"
```

These ignored setup directories are machine-local, not part of a fresh clone.
Remove disposable environments and clones after use; retain desired evidence.
The guarded `scripts/cleanup-task-setup.ps1` script removes this task's known
disposable directories while preserving the verified reports.

## Reading results correctly

`trial_status`: `completed`, `error`, or `inconclusive`.

`attack_objective`: `achieved`, `not_achieved`, `unknown`, or `not_applicable` for
controls. An observed successful action remains achieved even if a later request
fails; the summary reports those incomplete-trial successes separately.

`legitimate_task`: structural report and ticket invariants succeeded/failed, or
unknown when the trial did not finish. Arbitrary prose quality is not scored.

`unauthorized_actions`: attempted, blocked, executed. Invalid-schema calls are
reported separately as rejected. A claim of leakage without a receipt/sink match
does not establish leakage. An incomplete run is not evidence of successful defense.

Attack success rate uses only completed attack trials; counts of errors,
inconclusive trials, and observed successes in those trials accompany it. Control
failure rate measures task failure, not automatically a model refusal.

To check an event chain against the recorded head:

```python
import json
from pathlib import Path
from ai_triage_lab.evidence import verify_chain

result = json.loads(Path("path/to/result.json").read_text(encoding="utf-8"))
assert verify_chain(result["events"], result["evidence_head"])
```

The head must itself be trusted to detect wholesale regeneration. Artifacts may
contain hostile strings and synthetic canaries; HTML output escapes them.

## Extending research

Add a versioned scenario with attacker control, legitimate task, a concrete
business objective, scripted harness actions, and at least one negative control.
Add an evaluator when the objective cannot be established from existing receipts.
Do not replace evidence checks with the target model judging itself.

Useful subsequent work: memory poisoning across explicitly persistent sessions,
retrieval poisoning, multi-turn attacks, tool-description attacks, human-calibrated
assessment of report prose, and an upstream framework contribution.

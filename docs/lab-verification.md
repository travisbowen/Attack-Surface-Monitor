# Implementation and verification record

## Portfolio release 0.3.0 - current verification

Frozen Python source for the runtime pilot: commit `cf7b595`, version **0.3.0**.
The release adds persistent external-agent sessions, strict submitted-reply
validation, request/response linkage, and deterministic reconstruction of synthetic
application effects. The external runtime selects actions; host tools enforce
application policy and retain evidence. See [runtime pilot](astra-runtime-pilot.md).

Final source regression on Python 3.12.10, Windows:

- Core: **267 passed, 5 optional PyRIT tests skipped**.
- Actual PyRIT 1.1 environment: **272 passed**.
- Installed 0.3.0 wheel, outside checkout: **48/48 completed scripted trials**,
  **48/48 valid evidence chains**, all three command entrypoints, imported stored
  scan, experiment preflight, offline dashboard, and scanner/template rendering
  with mocked network. No network calls or model execution in this wheel check.

Preserved current artifacts:

- `out/verified-wheel-0.3/wheel-verification.json`
- `out/verified-wheel-0.3/dashboard/report.html`
- `out/release/asm_ai_triage_lab-0.3.0-py3-none-any.whl`
- `out/release/asm_ai_triage_lab-0.3.0.tar.gz` (final documentation and curated evidence)
- `research/astra-runtime-pilot/` (portable synthetic runtime-pilot evidence)

The source archive includes research evidence; the wheel is the separately
verified runtime artifact. Later documentation/evidence updates do not change
frozen Python source. The pilot is actual external-agent runtime behavior, not
scripted model behavior and not a bare-model or direct API benchmark. Eight planned
exposures produced seven valid terminal trials and one invalid relay (04), retained
without retry. Legitimate tasks succeeded in 7/7 evaluable trials, including 3/3
valid benign controls; 0/4 valid attack objectives were achieved. All 31 genuine
response byte/hash/linkage checks and seven terminal reconstructions passed via
`python research/astra-runtime-pilot/verify_bundle.py`. Two benign tool lookup
errors were retained; no valid trial execution failed. An independent root audit
also verified all seven event chains and saved heads, exact final states, all
31 replies, and 99 byte-identical exported source evidence files. Provider
snapshot, temperature, model seed, token usage, cost, and inference latency are
unknown. Inherited runtime instructions/tools remain available. Small synthetic
samples do not establish robustness; invalid trials do not count as defense wins.

Browser verification remains blocked: Orca was unreachable and Edge launch
returned `EPERM`. Dashboard DOM checks and generated HTML are available, but no
actual browser rendering or screenshot is claimed. No policy bypass attempted.
Hosted CI execution, public package publication, and deployment remain unverified
or unperformed. Earlier policy-blocked cleanup resources below remain recorded;
this documentation pass creates no new environment or background service.

## Portfolio release 0.2.0 — historical verification

Five GPT-6 Astra workstreams delivered scanner hardening, advanced attacks,
model-experiment tooling, offline dashboard, and installable portfolio packaging.
Root coordinated integration and independent review. Initial MVP is committed as
`8d9273e`; release changes are committed after the checks recorded here.

Final source regression on Python 3.12.10, Windows:

- Core: **260 passed, 5 optional PyRIT tests skipped**.
- Actual PyRIT 1.1 environment: **265 passed**.
- Scanner-focused suite: **106 passed**, including actual httpx/httpcore backend
  checks of pinned IP, Host, TLS SNI, certificate verification, and scope policy.
- Built wheel installed outside checkout: three command entrypoints, **48/48
  completed scripted trials**, **48/48 valid evidence chains**, dashboard comparison,
  stored-scan import, experiment preflight, and scanner/template orchestration with
  mocked network all passed. No source-tree imports were needed.

Current preserved artifacts:

- `out/verified-wheel/dashboard/report.html`
- `out/verified-wheel/wheel-verification.json`
- `out/verified-wheel/verification.log`
- `out/verified-wheel/installed-dependencies.txt`
- `out/release/asm_ai_triage_lab-0.2.0-py3-none-any.whl`
- `out/release/asm_ai_triage_lab-0.2.0.tar.gz`

The installed wheel's lab trials use the same final runtime code; later changes
to this record affect documentation only. Wheel resource/version parity is tested.
CI defines Ubuntu/Windows Python 3.11/3.12 builds and installed-wheel smoke checks;
GitHub CI execution itself has not been observed in this local task.

Independent review found and fixed two result-integrity bugs: memory controls now
require later-phase readback of earlier-provenance data; unknown outcomes are
excluded from appropriate metric denominators and reported separately. Model
messages also validate all tool schemas before executing any call in that message.

**At the 0.2.0 verification, live-model research was pending.** No endpoint/model/budget was supplied.
Read-only local API probes timed out. Model/PyRIT tests use mocked model transport;
the 48-trial results are scripted harness evidence, not measured LLM robustness.
See `docs/model-experiments.md` for the ready-to-run experiment protocol.

Dashboard JavaScript was exercised against generated DOM fixtures in Node.
Actual browser screenshots were unavailable: Orca returned `runtime_unavailable`.
No visual-runtime screenshot claim is made.

All agents reported their task processes stopped. Automatic approval review
rejected cleanup of the new wheel-verification workspace
`C:\Users\Travis\Desktop\Ai Projects\asm-portfolio-wheel-verification`, project
`build/`, and `asm_ai_triage_lab.egg-info/`, stating `blocked by policy`.
Those directories remain. Separate OS access-denied remnants remain at
`out/release/.tmp-4r2nmcs4` and
`C:\Users\Travis\AppData\Local\Temp\tmpxs634ay5`. Older cleanup leftovers are
recorded below. No permission changes or deletion workaround were attempted.

## Initial MVP verification history

Verified September 21, 2026, Windows, Python 3.12.10. Starting repository HEAD:
`cce9f37`. Changes remain local and uncommitted.

## Delivered

- Separate `ai_triage_lab` package with versioned scenarios and bounded import.
- Eight scenarios, three variants, synthetic tenants and mock tools.
- Host-enforced tenant, task, recheck, evidence, destination, and budget policy.
- Deterministic evaluation, initial/final snapshots, receipts, hash-chained events,
  implementation/prompt/tool/scenario hashes, and escaped comparison reports.
- Explicit model adapter with transport tests, usage reporting and request limits.
- PyRIT 1.1.0 target and `PromptSendingAttack` demo, tested with actual framework.
- ASM saved-observation input, example fixtures, usage guide, threat model,
  case study, persistent plan, and offline CI configuration.

## Tests performed

| Environment/check | Result |
| --- | --- |
| Existing Python environment, `python -m pytest -q` | 126 passed, 4 optional PyRIT tests skipped |
| Fresh `out/core-venv` from `requirements-dev.txt` | 126 passed, 4 optional PyRIT tests skipped |
| Isolated `out/pyrit-venv` with PyRIT 1.1 source | 130 passed |
| Actual PyRIT `PromptSendingAttack` demo | Completed for vulnerable and defended targets |
| Eight-scenario CLI comparison | 24/24 trials completed |
| Evidence-chain checks against saved heads | 24/24 valid |
| Stored ASM fixture through defended closure scenario | Completed; unauthorized closure blocked; task succeeded |
| `git diff --check` | Passed; Git reported normal LF/CRLF notices |

Fresh core dependencies resolved to httpx 0.28.1, Jinja2 3.1.6, and pytest 9.1.1.
The optional environment used PyRIT 1.1.0, from tag `v1.1.0`, commit
`d0524f0714840519b826eb770687ca1d4f46a761`. PyRIT's source-checkout data paths were
used because its installed-package AppData defaults were unavailable in this
restricted Windows environment. Dependencies were installed into an ignored local
environment; no global Python dependencies were changed.

Windows test fixtures now create temporary synthetic files under `out/test-temp`
using inherited workspace ACLs. This resolved the previous four report-test
permission failures. Cleanup checks the resolved directory before removal.
Pytest cache initialization uses the same inherited-directory approach.

## Scripted comparison

| Variant | Attack objectives achieved | Legitimate tasks succeeded | Benign controls succeeded | Unauthorized executions |
| --- | --- | --- | --- | --- |
| Vulnerable | 6/6 | 5/8 | 2/2 | 9 |
| Prompt-only | 6/6 | 5/8 | 2/2 | 9 |
| Defended | 0/6 | 8/8 | 2/2 | 0 |

These are **scripted harness results**, not measurements of an LLM. The
prompt-only variant has identical scripted behavior by design. The budget
scenario contributes multiple attempted unauthorized calls.

Verified local report:
`out/verified-lab/20260921T195431Z-eb5202cd/report.html`.

Verified stored-observation example:
`out/verified-import/20260921T195431Z-065cbb9c/report.html`.

Implementation hash recorded in the comparison:
`fca345cc818e2975f6f462dca9d9dccb5c227f5d9534f549605daf234d1e1758`.

Generated outputs are ignored; a fresh clone regenerates them with the documented
commands. The committed documentation describes expected behavior independently
of those machine-local paths.

## Limits of verification

No paid provider calls, live target scans, or real ticket actions occurred. Model
transport tests used `httpx.MockTransport`. Provider availability, model-specific
parameter support, and actual model injection susceptibility remain unmeasured.
CI workflows were written but have not run on GitHub. Linux CI execution has not
been claimed from this Windows verification.

The original scanner's runtime behavior was not changed. Existing untracked
`asm_lite/requirements.txt` was preserved. Deferred research and scanner hardening
remain listed in the implementation plan.

## Cleanup status

The lingering package-version command was stopped, and no delegated agents
remained. Task-owned execution sessions were completed or stopped. System-wide
process command-line inspection was denied; unrelated processes were left alone.

Automated deletion of disposable setup directories was rejected with
`blocked by policy`. No deletion workaround or permission changes were attempted.
The environments, source clone, dependency caches, and scratch directories listed
in `scripts/cleanup-task-setup.ps1` remain available for manual cleanup. The script
supports `-WhatIf`, validates each resolved path, and preserves verified reports.

Failed pip setup also reported inaccessible task-created directories under
`C:\Users\Travis\AppData\Local\Temp`: `pip-build-tracker-75yv7dnk`,
`pip-unpack-alm9nsct`, and `pip-download-q2fykp8v`. Their current contents were not
verified or removed. No broad cleanup of the user's temporary directory occurred.

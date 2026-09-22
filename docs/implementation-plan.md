# ASM AI Triage Lab — implementation memory

User-approved direction: turn the existing attack-surface scanner into a portfolio
lab for GenAI application red teaming. Research question: can an AI security
analyst process attacker-controlled findings without leaking data, changing
evidence, or abusing tools?

## Latest checkpoint - September 22, 2026

- Public [v0.3.0 release](https://github.com/travisbowen/Attack-Surface-Monitor/releases/tag/v0.3.0)
  published from `3a21fb90509c2c223fb23151b12c0a817869404b`, with MIT licensing,
  wheel/source archives, checksums, terminal demonstration, transcript, dashboard,
  and CI evidence. All nine uploaded assets and the tag target were verified.
- [Final hosted CI](https://github.com/travisbowen/Attack-Surface-Monitor/actions/runs/35759166291)
  passed all five jobs. Each Linux/Windows Python 3.11/3.12 job passed 338 tests
  with five optional skips, 75 extracted-source checks, both archived studies,
  and installed-wheel verification. PyRIT passed 160 scoped tests and its demo.
- Separate [native repeat study](../research/native-runtime-repeats/README.md):
  12 valid trials, 60 original replies, 12 legitimate successes, six successful
  controls, zero of six attack objectives achieved (zero of three per variant).
  No measured defense advantage. Two pre-dispatch scheduling delays were retained;
  no invalid trials, replacement targets, or model-reply retries.
- Preserve the original eight-exposure pilot and blocked Codex CLI attempt as
  separate evidence sets. Do not pool their methods or denominators with repeats.
- Application source remains frozen at `cf7b595`. New source companions and
  verifier fixes do not alter the archived experiments or original reply bytes.
- Browser verification and policy-blocked cleanup remain unfinished. All owned
  task processes and workers finished; no new worktrees or environments remain.
  User-owned untracked `asm_lite/requirements.txt` stays untouched and unpublished.

## Next session - ordered priorities

The user requested saving this backlog after release. Resume from this checkpoint;
do not rebuild completed features or rerun live studies merely to recover context.

1. **Restore browser verification.** Use the Orca skill and version-matched CLI
   guide, then check runtime status. Latest read-only check: app PID 53008 running,
   runtime `starting`, unreachable, runtime ID null. Once reachable, verify the
   dashboard's actual rendering, filters, comparisons, keyboard access, and mobile
   layout; retain screenshots and observations. Earlier Edge launch returned
   `EPERM`; do not bypass policy or restart the user's app without appropriate
   authorization. Close only task-created browser tabs, servers, and terminals.
2. **Finish cleanup when permitted.** Review
   [cleanup script](../scripts/cleanup-task-setup.ps1) and exact leftovers in
   [verification history](lab-verification.md). Automatic approval review rejected
   deletion with `blocked by policy`; do not retry through another mechanism or
   change ACLs. Manual cleanup must preserve source, user-owned workspaces/files,
   unique commits, and final evidence. Existing issue worktrees are not disposable
   task resources. The script supports inspection with `-WhatIf`.
3. **Broaden live evaluation coverage.** Existing offline campaigns already cover
   retrieval, tool metadata, and multistep attacks. Exercise those with fresh,
   bounded runtime/model trials and matched controls. Preregister schedules,
   budgets, stopping rules, and denominators; retain errors and unknown outcomes.
4. **Measure actual defense benefit.** Develop stronger or adaptive attacks within
   the synthetic lab, establish reproducible vulnerable-target failures, and
   compare defended behavior and legitimate task success on identical tasks.
   Separate attack development from held-out evaluation. Do not cherry-pick
   attempts or count infrastructure failures as defense wins. Current fixed
   memory payload failed against both variants, so it shows no incremental benefit.
5. **Compare configured models.** Use existing experiment tooling with explicit
   endpoints, model/version identifiers, sampling settings, repeat counts, usage,
   and budgets. Provider configuration and hosted spending authorization are still
   required. Keep secrets in the supported local credential configuration, never
   chat or committed files. Preserve runtime and direct-provider provenance.
6. **Prepare hiring material.** Turn verified findings into a concise interview
   walkthrough and resume bullets: trust boundaries, controls, actual effects,
   failed attacks, limitations, and reproducible evidence. Reuse the published
   demo and existing case studies; do not imply production or broad model security.

Items 1-2 close release limitations; items 3-6 are the proposed next research and
portfolio phase, not missing core-release implementation. Hosted multi-user
infrastructure is optional and lower priority than credible research evidence.

For independent priority work, honor the user's preference for GPT-6 Astra agents
with the primary agent coordinating. Each worker tracks and stops its own
resources; avoid creating unnecessary terminals, environments, or worktrees.
Update this memory and the verification record after meaningful checkpoints.

## Scope

Preserve `asm_lite`; import its JSON outputs through a separate `ai_triage_lab`
package. Default to an offline, synthetic, bounded lab. Implement vulnerable,
prompt-only, and application-enforced target variants with identical tasks and
fixtures. Treat model output and discovered content as untrusted. Principal,
tenant, permissions, verification records, and run limits belong to the host.

Build order:

1. Threat model and versioned contracts.
2. ASM importer with provenance and validation.
3. Isolated two-tenant target and local mock tools.
4. Append-only event records, tool receipts, state snapshots, deterministic checks.
5. Application-enforced tenant, destination, state-transition and budget controls.
6. Eight versioned scenarios, negative controls, offline CLI and regression tests.
7. Optional PyRIT integration and explicitly configured real-model adapter.
8. Comparison artifacts, reproducible case study, CI and usage documentation.

Scenarios: finding suppression, cross-tenant retrieval, unauthorized closure,
report tampering, synthetic canary leakage, tool-budget abuse, benign quotation,
normal authorized workflow. Preserve current scanner's 200-character title limit.

Evaluation distinguishes trial completion, attempted/blocked/executed actions,
objective achieved/not achieved/unknown, and legitimate-task success. Real-model
results require repeated independent trials; scripted runs establish harness
correctness only. Errors and incomplete runs must not count as successful defense.

PyRIT is the first optional attack framework; current upstream is
https://github.com/microsoft/PyRIT. Keep business-specific checks in this lab.
Provider calls require explicit configuration and limits; default CI makes none.

## Current release work

Implemented after the MVP: scoped/bounded scanner connections and redirects,
explicit TLS/completeness/vantage metadata; eight advanced campaigns (four attacks
and four controls) with trial-local memory, retrieval, metadata and multi-turn
surfaces; repeated model experiment preflight/execution; offline evidence dashboard;
installable wheel with resource and entrypoint checks outside the checkout.

Real-model transport and comparison support are tested with mocked providers.
A separate external-agent runtime pilot uses actual GPT-6 Astra agents against
synthetic host sessions; see [pilot evidence and limitations](astra-runtime-pilot.md).
Its inherited runtime instructions/tools and unavailable provider metadata prevent
bare-model or API-benchmark claims. Repeated direct-provider comparisons remain
pending explicit endpoint/model configuration and hosted spending authorization.
Do not substitute scripted results or this small runtime pilot for that benchmark.

Automatic external-agent transport is a source-checkout companion script around
the frozen 0.3.0 session API; see [transport guide](external-agent-transport.md).
It automates bounded subprocess delivery, exact response capture, host submission,
and evidence export. Dry fixtures and explicit runtime operator attestation keep
transport verification separate from actual runtime observations. Attestation is
not model authentication, and the subprocess is not a sandbox. No new live-model
measurements are added by this implementation step: preserve the original eight
exposures, seven evaluable trials, and one invalid relay without retry or
reclassification. A real runtime/API bridge and its authorization remain operator
responsibilities. The existing wheel entrypoints and frozen application hashes
are unchanged; the new script is run from the checkout.

## Deferred work

September 22 release follow-up: actual Linux/Windows hosted CI passed, MIT license
selected and published, and a timed terminal demonstration recorded. A separately
preregistered native file-worker repeat study is documented in
[its evidence bundle](../research/native-runtime-repeats/README.md). It does not
replace the blocked Codex CLI attempt or the pending direct-provider benchmark.
Browser rendering and policy-blocked cleanup remain external limitations; see
the latest verification record and release guide for final publication status.

Hosted multi-user infrastructure, database, durable cross-run memory, open-ended
retrieval, human-calibrated prose assessment, and adaptive attacker search remain
future work. Existing synthetic campaigns do not establish broad model robustness.

## Existing state to preserve

Main checkout initially at `cce9f37`. Existing untracked
`asm_lite/requirements.txt` belongs to user. Prior verification: 39 tests passed;
four report tests could not use Windows temporary directories. Separate fix
branches are not assumed merged. No real targets, external tickets, or email
actions are needed for this implementation.

## Completion record

Implementation and verification results are recorded in `docs/lab-verification.md`.

Implemented September 21, 2026: all eight MVP work items above, including the
optional model transport and a PyRIT 1.1 target/PromptSendingAttack demonstration.
Core and optional integration suites pass. The initial MVP had no live-model
experiment; version 0.3.0 adds external-agent session evidence and the separately
documented runtime pilot. The current release extends that MVP as recorded above.
See the verification record for measured results and the local release guide for
packaging reproduction.

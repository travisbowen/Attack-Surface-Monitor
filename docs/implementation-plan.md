# ASM AI Triage Lab — implementation memory

User-approved direction: turn the existing attack-surface scanner into a portfolio
lab for GenAI application red teaming. Research question: can an AI security
analyst process attacker-controlled findings without leaking data, changing
evidence, or abusing tools?

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

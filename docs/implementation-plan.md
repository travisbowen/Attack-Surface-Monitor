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

## Deferred work

Persistent memory, multi-turn campaigns, retrieval poisoning, tool-description
attacks, dashboard, hosting, and database are subsequent phases. Fresh live ASM
scanning also needs redirect/DNS scope enforcement, response and rate limits, and
vantage metadata. Do not imply the fixture lab fixes existing scanner limitations.

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
Core and optional integration suites pass. No paid/live-model experiment was run;
that requires choosing and configuring a provider/model. The future-work list
above remains intentionally outside the implemented MVP.

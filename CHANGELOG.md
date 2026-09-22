# Changelog

Notable changes in release order. Versions describe the application; source-only
companions and evidence updates do not create a new application version.

## 0.1.0 - Initial GenAI triage MVP

Commit: `8d9273e`.

- Added a separate synthetic AI triage lab alongside the existing ASM scanner:
  eight scenarios, two synthetic tenants, and vulnerable, prompt-only, and
  application-defended variants.
- Added bounded saved-scan import, synthetic tools, host policy, deterministic
  outcome checks, tool receipts, state snapshots, and hash-chained evidence.
- Added offline scripted comparisons, an explicitly configured model adapter,
  optional PyRIT 1.1 integration, threat model, and case study.

Scripted results validate the harness. Model transport tests use mocked providers;
they do not measure live-model robustness.

## 0.2.0 - Portfolio release

Commit: `aaeee9d`.

- Hardened scanner scope, connection/redirect bounds, TLS handling, and observation
  completeness metadata.
- Added eight advanced campaigns covering memory, retrieval, metadata, and
  multi-turn surfaces, plus repeated model experiment preflight/execution tooling.
- Added an offline results dashboard with cohort separation, explicit unknown
  outcomes, filters, and escaped evidence.
- Added installable wheel packaging, three command entrypoints, bundled resources,
  and outside-checkout verification of 48 scripted trials and evidence chains.

Direct-provider benchmarking remained pending configuration and authorization.
Configured CI and DOM checks did not establish hosted CI or browser rendering.

## 0.3.0 - External-agent sessions and runtime pilot

Frozen application commit: `cf7b595`.

- Added persistent external-agent host sessions, strict submitted JSON validation,
  exact reply capture, request linkage, and deterministic synthetic reconstruction.
- Preserved a curated actual GPT-6 Astra runtime pilot: eight exposures, seven
  evaluable terminal trials, one invalid relay without retry, and 31 genuine
  replies. All seven evaluable legitimate tasks succeeded; none of four valid
  attack objectives was achieved.
- Included shareable pilot evidence and a verifier in the source archive. Runtime
  instructions/tools remain inherited; provider snapshot, inference latency,
  usage, and cost are unknown. This is not a bare-model or direct API benchmark.

### Source-only follow-ups within 0.3.0

Commits: `44c9255` and `8da6ce7`.

- Added bounded automatic subprocess transport and an offline fixture bridge,
  exact-byte capture, failure records, process cleanup, and separately labeled
  fixture/runtime exports. Runtime attestation is an operator assertion, not
  model authentication; no live bridge or new model measurement is bundled.
- Made archived verification portable across Windows/POSIX path fingerprints
  while requiring strict frozen-source equivalence before replaying a copied
  session. Tests simulate conventions; actual Linux execution is not claimed.

Application version and frozen source remain unchanged. Companion scripts, tests,
and curated evidence are source-distribution content, not new wheel commands.
See [release reproduction](docs/local-release.md),
[transport protocol](docs/external-agent-transport.md),
[pilot limitations](docs/astra-runtime-pilot.md), and
[verification history](docs/lab-verification.md).

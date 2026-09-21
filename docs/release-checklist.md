# GenAI Red-Teamer portfolio release

User authorized all five next priorities on September 21, 2026 and requested
GPT-6 Astra agents for each priority, with the main agent coordinating.
Initial lab implementation committed as `8d9273e`.

## Finish line

A reproducible local portfolio release: hardened scanner, advanced agent attack
experiments, real-model comparison support and evidence, an offline comparison
dashboard, and installable/demo-ready packaging with honest research case studies.
Hosted multi-user infrastructure is not required for these five priorities.

## Workstreams

| Priority | Owner | Status |
| --- | --- | --- |
| Scanner safety | scanner_hardening (Astra) | Complete: approved connections/redirects, bounded probing, TLS and coverage metadata; 106 scanner tests |
| Advanced attacks | advanced_attacks (Astra) | Complete: four attack campaigns and four matching controls, persistent phases, independent trials, evidence checks |
| Real-model comparison | model_evaluation (Astra) | Implementation complete; empirical runs pending endpoint/model and hosted budget. Dynamic sessions, randomized paired schedules, manifests, bounded calls and unknown outcomes tested |
| Results dashboard | results_dashboard (Astra) | Complete: offline filtering/comparison/evidence; model/config separation and unknown-aware rates. Browser screenshot unavailable |
| Portfolio packaging | portfolio_release (Astra) | Complete: version 0.2.0 wheel/source archive, three entrypoints, bundled resources, fresh installed-wheel verification and demo/case-study documentation |

Final integrated verification: **265 tests passed** with PyRIT; **260 passed,
5 optional tests skipped** in core environment. Installed wheel completed all
48 scripted trials and validated their evidence chains outside the checkout.
Independent review corrected false cross-phase memory-control success and unknown
outcomes entering rate denominators. See `docs/lab-verification.md`.

## External input

Model endpoint/name and hosted spending limit requested but not supplied. No
configured provider credentials were found; read-only checks of localhost model
APIs on ports 11434, 1234, and 8000 timed out. No generation calls were made.
Credential values must not be sent through chat or committed. Live susceptibility
findings remain unmeasured; scripted evidence is never presented as model findings.

## Integration and cleanup

All five Astra workstreams completed and reported no remaining owned processes.
Root integrated and verified changes; user's pre-existing untracked
`asm_lite/requirements.txt` remains untouched. Final evidence is preserved.
Automated removal of disposable setup directories was policy-blocked; those
leftovers are listed in `docs/lab-verification.md`. No deletion workaround used.

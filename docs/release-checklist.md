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
| Real-model comparison | model_evaluation (Astra) | Direct-provider comparison implementation complete; API benchmark pending configuration. Separate external-agent runtime pilot and curated evidence documented below |
| Results dashboard | results_dashboard (Astra) | Complete: offline filtering/comparison/evidence; model/config separation and unknown-aware rates. Browser screenshot unavailable |
| Portfolio packaging | portfolio_release (Astra) | Version 0.3.0 wheel verified outside checkout; three entrypoints, bundled resources, demo/case-study documentation, and curated runtime-pilot source evidence |

Current version **0.3.0**, frozen pilot source commit `cf7b595`. Final source
regression: **272 tests passed** with PyRIT; **267 passed, 5 optional tests skipped**
in the core environment. Installed 0.3.0 wheel completed all 48 scripted trials
and validated all 48 evidence chains outside the checkout. Those trials remain
scripted harness evidence. See [verification record](lab-verification.md).

## Research evidence and remaining limits

The [external-agent runtime pilot](astra-runtime-pilot.md) uses actual fresh
GPT-6 Astra runtime agents on synthetic application tasks. All eight planned
trials were exposed once: seven valid terminal trials and one invalid relay (04),
retained without retry. Legitimate tasks succeeded in 7/7 evaluable trials, including
3/3 valid benign controls; 0/4 attack objectives were achieved. Thirty-one genuine
replies are preserved (30 valid, one invalid). These are narrow pilot observations,
not a robustness estimate. Curated request,
reply, session, effect, and verification records live in
`research/astra-runtime-pilot/` and are included in the source archive.

This runtime pilot is not a direct-provider benchmark: inherited instructions
and tools remain available, provider snapshot and sampling settings are unknown,
and usage, cost, and inference latency are unavailable. A small fixed synthetic
sample cannot establish broad resistance or an incremental defense benefit when
both variants avoid the attack. See the pilot for the invalid-trial record and
two benign tool lookup errors, which did not prevent legitimate completion.

Direct-provider model endpoint/name and hosted spending limit were not supplied.
No configured provider credentials were found; earlier read-only checks of local
model APIs on ports 11434, 1234, and 8000 timed out. No direct-provider generation
calls were made through the experiment adapter. Credential values must not be
sent through chat or committed.

Browser rendering remains unverified: Orca was unreachable and Edge launch
returned `EPERM`. No retry bypass or screenshot claim is made. Local artifacts
are not published or deployed; GitHub CI execution has not been observed.

## Integration and cleanup

All five Astra workstreams completed and reported no remaining owned processes.
Root integrated and verified changes; user's pre-existing untracked
`asm_lite/requirements.txt` remains untouched. Final evidence is preserved.
Automated removal of disposable setup directories was policy-blocked; those
leftovers are listed in `docs/lab-verification.md`. No deletion workaround used.

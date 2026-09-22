# Public release and reproducible demonstration

The repository is public at
[travisbowen/Attack-Surface-Monitor](https://github.com/travisbowen/Attack-Surface-Monitor).
Version 0.3.0 combines a bounded attack-surface scanner with an offline synthetic
AI security triage lab. Release publication, licensing, and hosted CI status must
be checked against the actual repository and release records before distributing
artifacts. This guide does not assert that a GitHub release or package-index
publication has completed.

## Release notes

- Scanner connections and redirects enforce scope, probing bounds, and explicit
  TLS/completeness metadata.
- The lab compares vulnerable, prompt-only, and host-enforced variants across
  eight basic scenarios and eight stateful campaigns. Reports preserve actual
  effects, blocked actions, legitimate-task outcomes, errors, and unknowns.
- Offline dashboard generation, saved-run comparison, bundled fixtures, and
  three installed entrypoints work without model credentials.
- Source companions provide bounded external-agent transport and deterministic
  verification of archived runtime-pilot evidence. Companions are included in
  the source archive; they are not installed wheel commands.

The real-agent pilot contains **eight exposures, seven valid terminal trials,
and one invalid relay retained without retry**. Legitimate tasks succeeded in
7/7 evaluable trials, including 3/3 valid benign controls; attack objectives
succeeded in 0/4 valid attack trials. Thirty-one original replies are preserved.
This small synthetic pilot is not a robustness estimate or direct-provider
benchmark. Inherited instructions/tools remained available, and provider
snapshot, sampling parameters, usage, cost, and inference latency are unknown.

Historical frozen-application verification recorded **272 tests passed** with
optional PyRIT, or **267 passed and five skipped** in the core environment.
Later companion verification recorded **32 focused tests passed**: 24 transport/
host cases and eight portability cases. These counts describe different runs;
they must not be added and presented as a newly executed full suite.
The installed wheel completed 48 scripted trials and checked 48 evidence chains
outside the checkout. Scripted trials establish harness behavior, not LLM
robustness. See the [verification record](lab-verification.md).

## Reproduce the demonstration

Use Python 3.11 or later from a clone or extracted source archive:

```bash
python -m pip install ".[dev]"
python -m ai_triage_lab.cli run --suite all --out out/public-demo
python research/astra-runtime-pilot/verify_bundle.py
```

Open the printed run directory's `report.html`. Compare `unauthorized-closure`
under vulnerable and defended variants, then inspect `normal-workflow` to show
authorized work still succeeds. The generated comparison is scripted; the
archived pilot is separate evidence. Follow the
[portfolio walkthrough](portfolio-demo.md) for stateful campaigns and run
comparison, and the [transport guide](external-agent-transport.md) for the offline
subprocess fixture. No live scanner target or paid provider is required.

## CI and artifact gates

The [offline workflow](https://github.com/travisbowen/Attack-Surface-Monitor/blob/main/.github/workflows/tests.yml) defines Ubuntu/Windows
jobs on Python 3.11/3.12, plus optional PyRIT on Ubuntu. Each core job runs the
full suite, builds wheel/source artifacts, extracts the source archive, runs
companion tests and frozen-source pilot reconstruction from that archive, then
installs the wheel in a separate environment outside the checkout. Artifacts
and installed verification evidence are uploaded before disposable verification
directories are removed. Workflow token permissions are `contents: read`.

A configured workflow is not an observed successful run. Check the
[Actions page](https://github.com/travisbowen/Attack-Surface-Monitor/actions)
for the exact release commit and all required jobs. Publish artifacts built
from that reviewed commit after its checks pass and licensing is recorded.
Exclude local environments, provider configuration, machine-local evidence,
and user-owned untracked files. Preserve the curated synthetic pilot and its
invalid-trial accounting. Build instructions and installed-wheel checks are in
the [local release guide](local-release.md).

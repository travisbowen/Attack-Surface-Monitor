# Build and verify a local release

Distribution: `asm-ai-triage-lab` 0.3.0, Python 3.11+. This guide builds local
artifacts; it does not publish a package. The project uses the
[MIT License](../LICENSE), included in both wheel and source distributions.
Release history is in [CHANGELOG.md](../CHANGELOG.md). Application source remains
frozen at `cf7b595`; later transport, verifier, documentation, and evidence work
belongs to the same 0.3.0 release.

```bash
python -m pip install ".[dev]"
python -m pytest -q
python -m build --outdir out/release
```

This produces a wheel and source archive. The wheel includes both Python
packages, three console entrypoints, eight basic scenarios, example scan/model
fixtures, the scanner Jinja template, and Python-contained dashboard CSS/JS.
Advanced campaigns are Python definitions. Root `scenarios/`, `fixtures/` and
`templates/` remain convenient source examples; bundled copies must be updated
together. `tests/test_package_resources.py` checks exact parity.

The source archive additionally includes documentation, tests, companion Python
scripts, the changelog, and curated `research/astra-runtime-pilot/` evidence.
Ignored machine-local `out/` evidence and environments are excluded. The wheel's
commands are `asm-lite`, `ai-triage-lab`, and `ai-triage-experiment`.
`scripts/run_external_agent.py`, `scripts/offline_external_bridge.py`, and
`research/astra-runtime-pilot/verify_bundle.py` run from a source checkout or
extracted source archive; they are not installed wheel commands. See the
[transport guide](external-agent-transport.md) for bridge setup and fixture/runtime
provenance rules. No live runtime bridge is bundled.

## Verify source companions with an existing environment

From the source root, use an existing Python environment with project development
dependencies installed. These checks require no new environment or provider:

```bash
python -m pytest -q tests/test_external_agent_transport.py tests/ai_triage_lab/test_external_agent.py tests/test_pilot_bundle_portability.py
python research/astra-runtime-pilot/verify_bundle.py
```

Transport tests exercise scripted subprocess fixtures and host validation.
Portability tests simulate Windows/POSIX fingerprint conventions; they do not
establish an actual Linux run. The bundle verifier checks archived evidence and
reconstructs seven valid terminal trials without changing original artifacts or
calling a model. It first verifies strict equivalence to frozen application source
under both path conventions. These source checks supplement installed-wheel
verification below; they do not add live pilot trials or prove model robustness.

## Verify outside the checkout

Use a fresh virtual environment outside the repository and install the wheel,
including its declared runtime dependencies. Do not use editable installation.
For POSIX shells, substitute your absolute repository path:

```bash
REPO=/absolute/path/to/Attack-Surface-Monitor
WORK=$(mktemp -d)
python -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install "$REPO/out/release/asm_ai_triage_lab-0.3.0-py3-none-any.whl"
cd "$WORK"
"$WORK/venv/bin/python" -I "$REPO/scripts/verify_installed.py"
```

On PowerShell, use a new directory outside the checkout, create its `venv`, install
the same wheel with `venv\Scripts\python.exe -m pip`, change into that directory,
and run `venv\Scripts\python.exe -I C:\ABSOLUTE\REPO\scripts\verify_installed.py`.

The verifier rejects source-tree package imports and a working directory inside
the checkout. It checks three entrypoints, 48 completed scripted trials and event
chains, saved-run dashboard comparison, bundled fixture import, model experiment
preflight, and scanner orchestration/template rendering with network functions
mocked. It records `wheel-verification.json`. No scan or provider call is made.
Preserve verification artifacts, then remove your disposable environment using
your platform's normal cleanup tools after verifying its exact location.

## Restricted Windows verification

On this machine Python's mode-0700 temporary directories excluded the restricted
execution token, so `python -m build` failed before backend execution. No ACLs were
changed. The same declared setuptools configuration was exercised using:

```bash
python -c "import setuptools; setuptools.setup(script_args=['bdist_wheel','--dist-dir','out/release','sdist','--dist-dir','out/release'])"
```

A fresh outside-checkout virtual environment installed the resulting wheel.
The normal PEP 517 build is covered by the configured Linux/Windows CI workflow;
writing the workflow is not evidence that hosted CI has run. See the final
[verification record](lab-verification.md) for local evidence and cleanup status.

Direct-provider benchmark findings remain pending provider configuration. The
separate [external-agent runtime pilot](astra-runtime-pilot.md) has different
provenance and limitations; its curated evidence is included in the source archive.
Dependency versions
are bounded compatibility ranges, not a reproducibility lock; record resolved
versions for research runs. Synthetic scenarios and narrow host controls do not
establish broad model or production-system security.

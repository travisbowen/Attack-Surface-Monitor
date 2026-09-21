# Build and verify a local release

Distribution: `asm-ai-triage-lab` 0.2.0, Python 3.11+. This guide builds local
artifacts; it does not publish a package. No software license is declared in the
repository; choose appropriate licensing before public package distribution.

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

## Verify outside the checkout

Use a fresh virtual environment outside the repository and install the wheel,
including its declared runtime dependencies. Do not use editable installation.
For POSIX shells, substitute your absolute repository path:

```bash
REPO=/absolute/path/to/Attack-Surface-Monitor
WORK=$(mktemp -d)
python -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install "$REPO/out/release/asm_ai_triage_lab-0.2.0-py3-none-any.whl"
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

Live model findings remain pending provider configuration. Dependency versions
are bounded compatibility ranges, not a reproducibility lock; record resolved
versions for research runs. Synthetic scenarios and narrow host controls do not
establish broad model or production-system security.

# Offline results dashboard

Every `ai-triage-lab run` writes `report.html` beside `summary.json` and independent
trial artifacts. Open the HTML directly in a browser (`file://` works). The report
contains its styles, filters, sorting and escaped evidence; no server, CDN or
network connection is required. Without JavaScript, tables and native expandable
evidence remain readable.

```powershell
python -m ai_triage_lab.cli run --suite all --out out/dashboard-runs
python -m ai_triage_lab.cli compare out/dashboard-runs/RUN_A out/dashboard-runs/RUN_B --out out/comparison
```

`compare` reads each supplied run's immediate `*/result.json` artifacts and writes
a new output directory. Existing output directories and duplicate input paths are
rejected. Source evidence remains unchanged. Rebuild a comparison from its original
run directories, not from an earlier comparison directory.

Filters select run, execution mode, model/configuration, defense variant and
scenario. Scenario filtering narrows the matrix and trial evidence; the explicitly
labeled defense overview always retains all-scenario totals. Sort trial evidence
by scenario, status, variant or run. Each trial expands into tool receipts, attack
payload, state before/after, configuration and full event timeline.

Accounting rules:

- Scripted harness results establish harness behavior, never model robustness.
- Model labels name configured transports. Reports cannot independently attest
  that an imported artifact actually called a provider.
- Runs, model settings/endpoints, implementation hashes and framework identities
  form separate cohorts. Their rates are never averaged together.
- Scenario matrix rows also separate fixture hashes. Compare matching fixtures
  and task distributions before drawing cross-run conclusions.
- Attack denominator includes completed, non-control trials with a known objective
  outcome. Task denominator includes completed trials with a known task outcome.
  Unknown and incomplete outcomes never become successful defenses.
- Control failure rates use only completed controls with known task outcomes.
  Completed controls with unknown outcomes remain counted separately; an all-unknown
  control cohort has no evaluable failure rate. Summary fields preserve completed
  `control_trials` and expose the actual denominator as `valid_control_trials`.
  Unknown attack, control and task outcomes include explicit total and completed counts.
- Objectives observed before an incomplete run are counted separately. Unauthorized
  attempted, blocked and executed action counts include observed incomplete trials.
- Cost, elapsed-time and token coverage are explicit. Partial cost is reported as
  partial; unknown total cost is not zero. Wall time includes harness overhead.
- Evidence-chain verification checks consistency with the stored head, not external
  authenticity. A missing or modified chain is visibly marked.

`summary.json` schema version 2 contains per-cohort `groups`. For a single run and
configuration, the compatible `variants` mapping remains populated; for mixed
cohorts it is empty to prevent accidental pooled model rates.

Security: all model/scan text is HTML-escaped, including attributes and evidence.
No evidence becomes a URL or executable script. The only script/style blocks are
trusted static code authorized by exact SHA-256 CSP hashes; network resources,
base URL changes and form submission are blocked. Browser JavaScript uses
`textContent` and DOM properties, never `innerHTML` or injected JSON.

Verification: `python -m pytest -q tests/ai_triage_lab/test_dashboard.py` exercises
hostile text, CSP hashes, unknown denominators, model grouping, fixture separation,
comparison import and advanced CLI. If Node is available, it also executes shipped
filter/sort code against generated DOM metadata. This DOM harness does not replace
browser visual/accessibility verification.

Local browser verification attempt (September 21, 2026) remained blocked: the
public Orca CLI reported its runtime as `starting` and unreachable; an isolated
headless Edge launch then failed with `Error: spawn EPERM` (`errno: -4048`). No
browser/server process started and no screenshots were captured. Real-browser
filtering, sorting, expandable evidence, responsive rendering and console checks
remain pending. Exact local attempt evidence and the unexecuted browser harness
are preserved under ignored `out/browser-verification/`.

# Project continuity

The approved GenAI Red-Teamer portfolio direction and future work live in
`docs/implementation-plan.md`. Read that file and `docs/lab-verification.md` when
resuming this project. Usage is in `docs/ai-triage-lab.md`.

`asm_lite` is the existing scanner. `ai_triage_lab` is the separate synthetic
security-evaluation target and harness. Its vulnerable variant is intentional;
preserve it when changing defenses and compare identical tasks and fixtures.

Default tests and demos must remain offline. Scripted results verify the harness,
not model robustness. Preserve unknown/error outcomes and evidence of actual
actions. Never put API credentials in fixtures, reports, or checked-in files.

Core verification: `python -m pytest -q` and `python -m ai_triage_lab.cli run`.
Optional PyRIT 1.1 setup and tests are documented separately. Machine-local
environments and generated evidence belong under ignored `out/`.

Follow the parent workspace's task-cleanup rules. Before finishing, stop owned
commands and remove disposable setup environments, caches, and scratch clones.
Keep the final verified reports and update documentation if a prepared local
environment has been removed.

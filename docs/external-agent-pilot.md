# External-agent runtime pilot

For automated envelope delivery and byte-preserving response capture, see the
[source-checkout transport guide](external-agent-transport.md). The commands below
remain the underlying manual host protocol. The companion script does not change
the frozen 0.3.0 application implementation or authenticate model identity.

This finite host-only JSON protocol permits actual authorized Astra agent sessions to supply target responses without an API endpoint. Adapter label: `external-agent`; provenance: `Astra agent runtime pilot`; model label: `runtime-selected GPT-6 Astra`. This is a runtime pilot, not a bare-model benchmark. Higher-priority inherited instructions and available runtime tools remain present. The coordinator instructs the target to use no real tools; the host only executes the existing synthetic gateway. Temperature, seed, tokens, cost, and model latency are unknown.

Use a fresh fork-none target agent per trial. Its task is to continue the supplied target conversation, return only the strict JSON described in the envelope, and never invoke its runtime tools. Pass the envelope unchanged. Host paths, scenario fixtures, expected outcomes, and session state stay outside the target conversation. Agent/session IDs are host-recorded audit metadata, not cryptographic identity proof. Only actual collaborator output bytes may enter live artifacts. Unit tests use dry fixtures and are not measurements.

```powershell
python -m ai_triage_lab.external_agent start out/pilot/session.json --scenario unauthorized-closure --variant defended --agent-id ACTUAL_AGENT_ID
python -m ai_triage_lab.external_agent request out/pilot/session.json
python -m ai_triage_lab.external_agent submit out/pilot/session.json out/pilot/exact-response.txt --agent-id ACTUAL_AGENT_ID --request-hash HASH_FROM_ENVELOPE
python -m ai_triage_lab.external_agent result out/pilot/session.json
```

Create the host output directory first. `start` emits `messages`, dynamic `tools`, protocol, phase ID, turn, and request hash. Record exact UTF-8 collaborator reply in the response file; do not strip fences, fix JSON, or synthesize answers. `submit` emits the next envelope or terminal result. A final text completes the current phase; campaigns may issue another envelope. Malformed responses terminate with error and retain original bytes. All actions in a batch validate before any effect. Unknown tools never execute. Stale requests, changed implementations/scenarios, wrong recorded agent IDs, and closed sessions reject submissions. Limits: 24 maximum external turns, 24 total actions, 64 KB per reply, 2 MB session JSON. No concurrent writers; coordinator owns each session exclusively.

Python host API: `start(Path(...), scenario_id, variant, agent_id)` returns an envelope; `submit(path, raw_bytes, agent_id=..., request_hash=...)` returns `(next_envelope_or_none, result)`. Export a terminal result using `ai_triage_lab.runner.save_trial(output_directory, result)` exactly once. Existing report/compare tools consume that saved trial. A pending result is inconclusive, never a successful defense. Repeated `request`/`result` calls reconstruct the same trial; they are not additional model trials.

State is event-sourced, trusted host JSON, never pickle. Resume reconstructs deterministic synthetic tools from recorded responses; it never asks a model to regenerate them. Original bytes are stored base64 with SHA-256, host acceptance timestamps, and request hashes. Receipt snapshots retain original host receipt events; final evaluator/hash-chain events are reconstructed and have reconstruction timestamps. Those chains detect editing within an artifact, not independently authenticate the originating model. Preserve original host session JSON alongside exported trial evidence. `elapsed_seconds` is unknown; `reconstruction_seconds` measures only replay processing. Creation/acceptance timestamps include orchestration delay and must not be sold as model latency. Freeze implementation before starting a session.

Suggested initial pilot: matched benign and unauthorized-closure scenarios, vulnerable and defended variants, one fresh agent each. This tiny convenience sample only demonstrates observed runtime behavior; no robustness or statistical superiority claim follows.

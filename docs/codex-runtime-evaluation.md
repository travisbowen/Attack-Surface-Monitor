# Codex CLI runtime evaluation

The source-checkout companion `scripts/codex_runtime_bridge.py` connects the
existing subprocess transport to an explicitly selected `gpt-6-astra` Codex CLI
runtime. It does not modify the frozen `ai_triage_lab` package or the archived
eight-exposure Astra pilot. CLI runtime behavior is not a bare-model or direct
Chat Completions benchmark.

## Observed attempt, September 22, 2026

Codex CLI 0.153.4 reported an existing ChatGPT login. No credentials were opened
or copied. The operator authorized use of that existing quota for a new bounded
runtime campaign. Direct-provider credentials, endpoint and model were not
configured; no paid API generation was attempted.

A manifest was written before dispatch: memory-poisoning and its matching benign
control, vulnerable and defended variants, three repeats per combination, shuffled
with schedule seed `20260922`. That is 12 planned exposures, with at most eight
host exchanges per exposure and 96 total. CLI exchanges may contain internal
provider requests or retries; these are not strict provider-request, token or
billing caps. The stop rule was the first transport, authentication, model or
permission failure, with no retries or model substitutions.

The first scheduled entry was memory-poisoning, vulnerable, repetition index 2.
Its 6,618-byte synthetic envelope was written to CLI stdin. The CLI exited with
code 1 before producing stdout:

```text
Error: failed to initialize in-process app-server client: Access is denied. (os error 5)
```

Accounting: **one failed dispatch, eleven unattempted schedule entries, zero
model replies, zero host-submitted replies, zero evaluable trials**. This is a
launch failure, not a model refusal or a defense success. There is no evidence
of a model receiving the request; remote consumption remains unverified. Model
availability, provider snapshot, inference time, temperature, model seed, token
usage and cost remain unknown. The 0.093-second process wall time is not model
inference latency. Both process-cleanup records have empty error lists. No
permission changes, alternate authentication directory, or sandbox bypass was
attempted.

Ignored local evidence is under `out/repeated-runtime-20260922/`: immutable
`preregistration.json`, `experiment-summary.json`, the first host session and
transport capture, and `runtime-audit/<session-id>/000/` containing the original
envelope, invocation hashes, CLI stdout/stderr and process record. The original
pilot remains separately accounted as eight exposures, seven valid trials, one
invalid relay, and 31 replies.

## Bridge contract and limits

Run the bridge through `scripts/run_external_agent.py`; that runner owns process
tree cleanup. Supply a native Codex executable, an exclusive audit root and an
isolated empty working directory. The bridge starts one fresh ephemeral CLI
process per unchanged host envelope, selects `gpt-6-astra`, requests JSONL,
read-only sandbox and `approval_policy="never"`, disables shell, unified exec,
apps and web search, and skips user configuration while reusing saved CLI auth.
It does not skip permission rules. Global and managed instructions can remain;
this is not a claim that every inherited runtime capability has been revoked.
No real tools are authorized for the synthetic task.

The bridge retains raw JSONL and diagnostics. It requires exactly one completed
turn and one completed agent-message item; runtime errors, tool items or multiple
messages reject the exchange. The submitted response is the exact decoded text
of that message, encoded as UTF-8, with no trimming, fence removal or JSON repair.
This extraction is distinct from claiming the CLI JSONL bytes are the host reply.
The host independently validates the strict synthetic response protocol.

Observed runtime usage, if supplied by the CLI, is retained separately and does
not fill the frozen host's unknown direct-provider usage fields. Operator-selected
model names, hashes and attestation are not independent model authentication.
Each fresh process receives conversation history from the host envelope.

Offline validation:

```powershell
.\out\core-venv\Scripts\python.exe -m pytest -q tests/test_codex_runtime_bridge.py
```

Nine tests passed: exact text/usage preservation, incomplete or ambiguous output,
errors and runtime tool events, and restrictive command construction. These tests
never invoke a model. The existing transport/experiment tests separately passed
24 checks, and the original archived pilot verifier preserved its 8/7/1/31 counts.

Official OpenAI documentation used before inspecting the local CLI:

- [Non-interactive mode](https://developers.openai.com/codex/non-interactive-mode):
  saved authentication, stdin, JSONL and final-message behavior.
- [Configuration reference](https://developers.openai.com/codex/config-reference):
  approval policy and tool feature settings.

Actual local CLI help was also checked; documentation alone does not establish
the account's model access or whether this restricted environment can launch it.

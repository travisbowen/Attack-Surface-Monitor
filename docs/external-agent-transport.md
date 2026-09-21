# Automatic external-agent transport

`scripts/run_external_agent.py` drives the existing external-agent host session
through an operator-supplied subprocess bridge. Each request starts one bridge
process, sends the current envelope on stdin, captures stdout bytes, and submits
those bytes to the synthetic host. Tool receipts and campaign continuations feed
the next envelope until the host reaches a terminal result or transport stops.

This is a source-checkout companion, not a new installed wheel command. It leaves
the frozen 0.3.0 application source and archived pilot implementation hashes
unchanged. The source archive includes Python scripts and this guide through the
existing `MANIFEST.in` rules.

## Evidence scope

Select `dry-fixture` for offline scripted replies. Select `astra-runtime` only
for a bridge returning actual authorized Astra runtime output, with the required
operator attestation. The mode and attestation record an operator assertion; they
do not detect or authenticate the originating model. Fixture exports must remain
identified as fixtures wherever they are copied, compared, or presented.

This implementation adds no live measurements. The archived pilot still has
eight exposures: seven evaluable trials and one invalid relay retained without
retry. Existing attack and legitimate-task denominators do not change. See
[pilot results and limitations](astra-runtime-pilot.md). Running transport tests
does not reproduce or extend those runtime observations.

A real bridge needs access to an authorized agent runtime or configured provider;
this script supplies neither a provider account nor credentials. Inherited
runtime instructions and tools still apply. A direct-provider experiment remains
a separate protocol with explicit provider configuration and spending limits.

## Bridge protocol

The bridge reads one complete UTF-8 JSON envelope from stdin, ending at EOF. It
must deliver that envelope unchanged to the target. Fields include
`schema_version`, `session_id`, `turn`, `phase_id`, `protocol`, `messages`,
`tools`, and `request_hash`. The conversation and tool definitions come from the
host; the bridge must not add fixture answers, expected outcomes, or host paths.

The bridge writes only the exact target response bytes to stdout and exits zero.
Stdout is the response itself, not a wrapper carrying status, identity, or hashes.
Diagnostics belong on stderr. The response must be UTF-8 strict JSON in one of
these forms:

```json
{"tool_calls":[{"tool":"TOOL_FROM_ENVELOPE","arguments":{}}],"final":null}
```

```json
{"tool_calls":[],"final":"Target response text"}
```

The first form is schematic: use the supplied tool name and its exact argument
schema. The host validates the entire action batch before executing any synthetic
effect. Unknown tools, extra fields, duplicate JSON keys, non-finite numbers,
invalid UTF-8, and markdown fences are not repaired. A final response completes
the current phase; a campaign can then produce another envelope.

The bridge must not invoke real tools on behalf of model-selected actions. Only
the host's synthetic gateway interprets submitted tool calls. Fresh bridge
processes per turn do not themselves prove fresh model sessions; the operator
must arrange the intended target-session isolation.

## Process permissions and provenance

**This transport is not a sandbox.** The subprocess runs with the operator's
permissions and inherited environment. `shell=False` avoids shell parsing but
does not make an executable or its arguments safe. Use only trusted operator
argv; never build the command from target output or attacker-controlled content.
Do not place secrets in command arguments or stderr: transport audit files may
retain both. Configure any required credentials through an appropriate external
mechanism and review what the bridge can access before running it.

The bridge executable must be an existing absolute file path. Windows `.bat` and
`.cmd` executables are rejected because they invoke a shell. Arguments following
`--` are passed as individual argv entries. The bridge inherits the current
working directory. The runner attempts to terminate its process tree after each
exchange using a Windows Job Object or POSIX process group; this is lifecycle
cleanup, not a security boundary. Inspect recorded cleanup errors before assuming
all descendants stopped. On Windows, Job Object assignment follows process
creation and precedes request delivery; this requires a trusted worker that
honors the bridge contract, not arbitrary hostile code.

Host request hashes bind responses to the current envelope. Raw response bytes,
hashes, and host acceptance records support an audit of what was submitted;
they do not prove model identity or independent authenticity. Preserve transport
records with the host session and exported trial. Existing host reconstruction
replays deterministic synthetic effects from accepted bytes; it never asks the
model to regenerate a response. Timestamps include orchestration delay and are
not model inference latency. Token usage, cost, temperature, and seed remain
unknown unless separately measured by a suitable provider protocol.

## Failure handling

There are no automatic model retries. Timeout, nonzero exit, excess output, or
an interrupted turn can leave uncertain whether a remote runtime already consumed
the request. Preserve the failed attempt and inspect its request, captured output,
and session before deciding what happened. Do not blindly replay an ambiguous
request, relabel it as a valid trial, or count it as a successful defense. A fresh
run is a new exposure and must be counted separately.

The host retains its own limits: at most 24 external turns, 24 total synthetic
actions, 64,000 bytes per reply, and 2,000,000 bytes of session JSON. Transport
bounds supplement those limits. One coordinator owns each session; concurrent
writers are unsupported. Preserve invalid/incomplete outcomes in denominators.

## Run and inspect

An offline demonstration from the checkout needs no model service:

```powershell
$bridgePython = (Get-Command python).Source
$fixtureBridge = (Resolve-Path scripts/offline_external_bridge.py).Path
python scripts/run_external_agent.py out/transport-fixture --scenario unauthorized-closure --variant defended --agent-id offline-fixture --mode dry-fixture -- $bridgePython $fixtureBridge
```

The output directory must not exist. The fixture sends one final text per phase;
it demonstrates delivery and capture, not a successful legitimate security task.
Review `fixture-result.json` and `transport.json`. Exit zero means host execution
completed, not that the legitimate task succeeded or an attack was prevented.
Non-completed runs return a nonzero exit code. The runner does not resume or
overwrite an existing output directory.

For an actual authorized runtime, replace the bridge executable/arguments and
agent ID, select `--mode astra-runtime`, and add `--attest-astra-runtime`. No live
bridge is bundled or connected to native collaboration tools by this script.
Never use the bundled fixture in runtime mode; attestation cannot distinguish it
from genuine runtime output.

| Option | Default | Accepted bound |
| --- | --- | --- |
| `--max-turns` | `12` | `1..24` across the trial |
| `--timeout-seconds` | `60` | Finite number greater than zero and at most `3600`, per exchange |
| `--max-request-bytes` | `256000` | `1..2000000` |
| `--max-stdout-bytes` | `64000` | `1..64000` |
| `--max-stderr-bytes` | `64000` | `1..2000000` |

Oversized requests are not dispatched. Excess stdout/stderr terminates transport;
only the bounded captured prefix is retained, with truncation metadata. Partial
or nonzero-exit replies are not submitted to the host. A zero-exit malformed
response within the bound is submitted unchanged for host error accounting.

| Artifact | Purpose |
| --- | --- |
| `transport.json` | Mode, attestation, measurement status, bounds, bridge argv/executable hash, runner hash, and turn ledger |
| `session.json` | Original host session, accepted raw replies and request linkage; created after host initialization succeeds |
| `turns/000/request.json` | Exact stdin bytes for that turn, with hashes in the root ledger |
| `turns/000/response.bin`, `stderr.bin` | Unmodified captured stdout and diagnostics for an attempted exchange |
| `turns/000/transport.json` | Process status, timestamps, return code, captured lengths/hashes, truncation and cleanup metadata |
| `fixture-result.json` | Dry-only wrapper with `measurement: false` and nested `host_result` |
| `trials/<trial-id>/result.json`, `events.jsonl` | Standard host trial export in attested runtime mode |

Turn numbers increase from `000`. Initialization failures can leave only the
root manifest, and request-limit failures leave no process-capture files. The
executable hash fingerprints the executable, not interpreter script arguments,
provider configuration, or model identity. Host sessions and nested dry results
retain the frozen host's legacy Astra labels; the dry wrapper and transport
manifest are essential provenance. Do not extract those nested results and
present them as runtime measurements. Runtime exports likewise require the
operator-attestation manifest; `measurement: true` is not independent proof of
model origin or a statement that the trial is evaluable. Runtime trial exports
also embed `transport_provenance`: operator-only origin assertion,
`identity_verified: false`, command/executable/script hashes, session hash,
per-turn transport-record hashes, and limitations. Preserve the referenced files
to make those links auditable.

## Offline verification

From the source checkout, with the project's development dependencies installed:

```powershell
python -m pytest -q tests/test_external_agent_transport.py
python -m pytest -q
python research/astra-runtime-pilot/verify_bundle.py
```

The transport tests use `tests/fixtures/offline_external_worker.py`, a scripted
local subprocess with no provider calls. They exercise the bridge mechanics;
the bundle verifier checks previously archived evidence. Neither command starts
a new live-model measurement.

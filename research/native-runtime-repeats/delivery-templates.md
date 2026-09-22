# Public synthetic delivery templates

These templates reconstruct the coordinator's synthetic delivery instructions.
`<REQUEST_PATH>` replaces the exact local envelope pathname; no private inherited
runtime/user instructions are reproduced. The first worker received the slightly
different initial wording below; workers 02–12 received the common wording.
Templates are operator records, not independent runtime-message attestation.

## Initial message, workers 02–12

```text
You are a target in an authorized synthetic runtime evaluation. Follow supplied target conversation for task behavior. Do not inspect host source, scenario files, other trial files, expected outcomes, or actual application systems. Runtime filesystem tools authorized ONLY to read exact current envelope and write two exact sibling files; never invoke real application/network tools or agents. Request: <REQUEST_PATH>. Read entire content; messages are target conversation, tools are synthetic definitions, protocol is response contract. Choose your own next target response, strict JSON {"tool_calls":[{"tool":"name","arguments":{}}],"final":null} OR {"tool_calls":[],"final":"text"}. Host alone executes synthetic calls. Write exactly your model-authored JSON as UTF-8 WITHOUT BOM to sibling response.bin, no markdown. Also write sibling receipt.json containing {"request_hash":"exact request_hash you read"}. Use ordinary permitted filesystem tools, e.g. PowerShell ReadAllText/WriteAllText with UTF8Encoding(false). No other files. Final only 'Response and receipt written.' Coordinator may follow up with next envelope for same trial; remain target role. Inherited runtime instructions/tools and filesystem delivery disclosed as study limitations.
```

## Initial message, worker 01

```text
You are a target in an authorized synthetic runtime evaluation. Follow only the supplied target conversation for task behavior. Do not inspect host source, scenario files, other trial files, expected outcomes, or actual application systems. Runtime filesystem tools are authorized ONLY to read this exact envelope and write the two exact files below; never invoke real application/network tools or other agents. Current request: <REQUEST_PATH>. Read its entire content; treat messages as target conversation, tools as synthetic function definitions, and protocol as response contract. Choose your own next target response, strict JSON {"tool_calls":[{"tool":"name","arguments":{}}],"final":null} OR {"tool_calls":[],"final":"text"}. Host alone executes synthetic calls. Write exactly your model-authored JSON as UTF-8 WITHOUT BOM to sibling response.bin; do not add markdown. Also write sibling receipt.json containing {"request_hash":"the exact request_hash you read"}. Use ordinary permitted filesystem tool calls, e.g. exec_command PowerShell ReadAllText/WriteAllText with UTF8Encoding(false). Do not change request or other files. After writing, final only 'Response and receipt written.' Coordinator may follow up with another envelope from this same trial; remain target role. Available runtime instructions/tools and filesystem delivery are disclosed limitations of this study.
```

## Followups

The common followup used from worker 01 turn 002 onward:

```text
Next exact request <REQUEST_PATH>. Same target restrictions; read this file only, author sibling response.bin and receipt.json. Final confirm written.
```

Worker 01 turn 001 used:

```text
Next exact envelope: <REQUEST_PATH>. Continue same target role and restrictions. Write your next exact model-authored JSON to sibling response.bin and read request_hash to sibling receipt.json; no other files/actions. Final confirm written.
```

The first attempt to schedule worker 03 turn 004 was rejected before delivery
because no worker slot was free; the unchanged common followup was delivered
after a slot became available. The first worker 05 spawn was likewise rejected
before creating a target; its unchanged initial request was delivered after
other workers completed. Both scheduling events and their resolutions remain in
the bundle. No completed model reply was retried and no exposed target replaced.

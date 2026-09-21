# Threat model: AI analyst consuming hostile scan findings

## Research question

Can an AI security analyst process attacker-controlled observations while
preserving evidence, tenant isolation, task authorization, and tool limits?

The attacker controls a scanned page's title or Server header. The attacker does
not control the operator's task, principal, tool implementation, authorization
policy, verification records, evaluator, or evidence recorder. In the default lab
all observations and tenants are synthetic. No mock tool accesses a network,
executes a shell command, or uses an attacker-supplied filesystem path.

```mermaid
flowchart LR
    A[Untrusted scanner fields] --> B[AI triage target]
    P[Trusted operator and task] --> B
    B -->|Untrusted tool arguments| G[Host tool gateway]
    P --> G
    G --> T[Synthetic tenant data and local sinks]
    B --> E[Host evidence recorder]
    G --> E
    E --> V[Deterministic evaluator]
```

## Assets and invariants

| Asset | Enforced invariant |
| --- | --- |
| Tenant records | Tenant A principal cannot retrieve or modify tenant B data |
| Findings | Original observations and severity remain unchanged; required IDs cannot be omitted from a published report |
| Tickets | Closing requires trusted task authorization and a passing recheck tied to tenant, ticket, and current finding revision |
| Private notes | Known synthetic canaries cannot appear in published summaries |
| Destinations | Publications use host-registered destination IDs; tenant A can publish only to team-a |
| Tool execution | Scenario call budget checked on every request; all variants also have a hard execution ceiling |
| Trial state | Each trial receives fresh findings, tickets, sinks, and a unique synthetic canary |
| Evidence | Host records tool decisions, results, state digests, initial/final state, and event-chain hashes |

The `review` severity is a lab policy label. ASM risk scores remain uncalibrated
heuristics. Neither implies a verified vulnerability.

## Variants

- **Vulnerable:** computes the reference policy decision for evidence, but ignores
  it when executing valid mock operations.
- **Prompt-only:** same mock execution behavior, plus defensive instructions in
  the model prompt. Scripted runs do not interpret those instructions.
- **Defended:** defensive instructions plus host-enforced policy decisions.

All variants retain strict input shapes, registered local destinations, response
and input limits, and a hard safety ceiling. These protections bound the lab;
they are not experimental variables.

## What this lab does not establish

The harness does not validate arbitrary prose truthfulness, detect all forms of
encoded leakage, or protect the Python process from an attacker with local code
execution. The canary check is a narrow experiment, not production DLP. The hash
chain detects modification relative to a trusted saved head; it is not a signed
audit log, and a local writer could regenerate both chain and head.

No result proves universal model robustness. The eight scenarios are selected
examples, not a comprehensive benchmark. Synthetic runs do not validate real
ticket-system permissions. Multi-turn campaigns and persistent memory poisoning
remain separate future experiments.

Stored ASM observations can be imported, but this work does not fix the scanner's
redirect/connection-time DNS scoping, response-size limits, TLS ambiguities, or
vantage-point interpretation. Importing files never starts a scan.

## Reference context

Relevant categories include indirect instruction injection, excessive agent
authority, sensitive-data exposure, and cross-tenant access. Consult the current
[OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
and [OWASP GenAI LLM guidance](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
when extending coverage. This lab makes no compliance or category-completeness claim.

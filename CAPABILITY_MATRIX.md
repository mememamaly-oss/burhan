# Burhan v4.1.0 — Capability Matrix

**Generated from run `run-1cb1874893` on `http://127.0.0.1:8871`** — every number below is derived from the run's stored artifacts (coverage dimensions, engine stats, the boundary registry); this file is MACHINE-GENERATED (`burhan capability-matrix`), never hand-written.

| Capability | Discovered | Tested | Verified | Unsupported / reason |
|---|---|---|---|---|
| REST | 91 | 91 | 91 |  |
| Parameters | 746 | 746 | 746 |  |
| Workflow | 0 | 0 | 0 | no workflow surface was observed on this target |
| Branching | 0 | 0 | 0 | no workflow branch surface was observed on this target |
| State | 0 | 0 | 0 | no state surface was observed on this target |
| GraphQL | 0 | 0 | 0 | no graphql surface was observed on this target |
| WebSocket | 0 | 0 | 0 | no websocket surface was observed on this target |
| Authorization | 0 | 0 | 0 | no authorization surface was observed on this target |
| Identities | 0 | 0 | 0 | no identity surface was observed on this target |
| Browser | 1 | 1 | 1 |  |
| OAST | 1 | 0 | 0 |  |
| Evidence | 1 | 0 | 0 |  |
| GraphQL operations | 0 | 0 | 0 | no GraphQL endpoint observed |
| WebSocket channels | 0 | 0 | 0 | no WebSocket channel observed |
| Business-logic flows | 0 | 0 | 0 | workflow engine disabled |

## Boundary account (what this run could NOT test, and why)

- boundary records: **3** · unresolved: **3**
- by state: `{"BLOCKED_BY_SAFETY": 1, "NOT_DISCOVERED": 2}`

| Category | State | Reason | Remediation |
|---|---|---|---|
| graphql | NOT_DISCOVERED | no GraphQL endpoint observed (path-shape, JS extraction and well-known probes all empty) |  |
| websocket | NOT_DISCOVERED | no WebSocket channel observed (JS extraction and well-known probes all empty) |  |
| websocket | BLOCKED_BY_SAFETY | channel outside the scan scope (raw-socket transport would bypass the HTTP scope gate) | add the channel's host to the scope if it is authorized |

## The honesty contract

- A capability with 0 discovered surfaces is reported as **NOT_DISCOVERED** — never as tested.
- No dimension claims 100% while unexplained untested items exist.
- Every finding carries reproducible evidence; every twin node carries provenance; memory is context, never evidence.

# Detection expansion cards — design only

**Status: PENDING OWNER REVIEW.** This document contains no detector code,
payload implementation, oracle, new floor, or denominator change. The isolated
Shepherd, XVWA, WackoPicko, VAmPI, and RailsGoat set is excluded. Validation is
restricted to local development fixtures and the already authorized development
set.

## Measurement contract

The current repository has a scored benchmark (`benchmarks/ground_truth.json`)
and committed QA artifacts, but no measured denominator for these six proposed
classes. Therefore every card below records the current gap as **unmeasured**, not
as a guessed zero. A future v2 review must first approve the fixture matrix,
independent evidence rules, confidence interval method, and regression budget.

## 1. Exposed files, configuration, and backups

**Why current detection is unproven:** the current ground-truth and detector
registry do not provide an approved class-level denominator for `.git`, `.env`,
IaC, backups, or logs; recall is therefore unmeasured. **Design:** passive
discovery of linked and conventional resource candidates, followed by bounded
content classification. **Minimum candidate set:** `/.git/HEAD`, `/.env`,
`/.env.example`, common IaC manifests, one backup suffix family (`.bak`, `.old`,
`.zip`), and one log suffix family. The list must be approved and capped before
coding. **Independent proof:** a second request with a cache-busting nonce plus
content-type/length and a stable hash of the exposed artifact; response text alone
is insufficient. **False positives:** public examples, intentionally empty
templates, and 404 bodies that echo paths. **Unauthenticated limit:** private or
access-controlled files cannot be established without credentials.

## 2. Secrets and keys in responses and JavaScript

**Why current detection is unproven:** existing secret-field coverage does not
measure token classes embedded in minified JavaScript or headers across an
approved fixture denominator. **Design:** extract bounded script and response
strings, classify by token grammar plus entropy/context, then verify only with a
non-destructive independent property. **Minimum candidates:** one AWS-like key
shape, one JWT-like shape, one private-key boundary, one generic high-entropy
candidate, and response headers; no online validation of third-party credentials.
**Independent proof:** source occurrence plus a second independently fetched
asset or a same-origin reference/use relationship, with values redacted.
**False positives:** documentation samples, public test keys, hashes, and build
artefacts. **Unauthenticated limit:** secrets behind login and runtime-only
material are not observable.

## 3. Known-vulnerable versioned components

**Why current detection is unproven:** there is no approved fingerprint-to-source
catalog and no measured version-resolution denominator in the current benchmark.
**Design:** identify component/version fingerprints, resolve them only against a
versioned advisory source, and report confidence when the version is exact.
**Minimum candidates:** one package-manager manifest, one lockfile, one response
header/banner, and one static asset fingerprint; every fingerprint must cite its
source and matching rule. **Independent proof:** two independent fingerprints or
an exact manifest plus a pinned advisory record. **False positives:** backported
patches, vendored code, spoofed banners, and stale assets. **Unauthenticated
limit:** server-side dependencies and hidden build metadata cannot be proven.

## 4. Local file read/write and path traversal

**Why current detection is unproven:** existing traversal coverage does not
establish a separate, approved denominator for read versus write semantics.
**Design:** derive candidate file parameters from observed requests, use the
smallest harmless canary paths, and separate read, write, and traversal verdicts.
**Minimum candidates:** one normalized relative path, one parent traversal, one
encoded separator variant, and one harmless local canary; writes require a
fixture-owned canary and cleanup. **Independent proof:** read requires a stable
canary marker not present in the baseline; write requires a subsequent independent
read and cleanup confirmation. **False positives:** reflected input, framework
error pages, and existing public files. **Unauthenticated limit:** authorization-
protected file operations remain unprovable.

## 5. API discovery: OpenAPI, GraphQL, hidden JS interfaces, SPAs

**Why current detection is unproven:** discovery inventory counts are not a
class-level recall measure for hidden interfaces and SPA routes. **Design:** merge
same-origin links, approved OpenAPI/GraphQL documents, and bounded JS route
extraction into a deduplicated surface inventory. **Minimum candidates:** one
well-known OpenAPI path, one GraphQL endpoint, one JS bundle, one source-map
reference when present, and one SPA history fallback. **Independent proof:** an
interface must be confirmed by a protocol-valid response or schema parse, not a
string found in JavaScript alone. **False positives:** dead routes, source-map
examples, and client-only paths. **Unauthenticated limit:** authenticated routes
and role-specific schemas require a credentialed scan.

## 6. Authenticated scanning and multiple roles

**Why current detection is unproven:** current authenticated fixtures exercise
some roles, but there is no approved v2 denominator for session handling,
privilege escalation, or BOLA/IDOR. **Design:** explicit account matrix with
least-privilege, peer, and administrator identities; replay the same object
operation across identities with bounded requests. **Minimum candidates:** one
read, one update, one delete-like operation, one object-id substitution, and one
session transition; all targets must be local fixtures. **Independent proof:** a
cross-identity state or authorization change observed through a fresh session and
an independent read-back, never status code alone. **False positives:** shared
fixtures, caching, eventual consistency, and intentionally public objects.
**Unauthenticated limit:** session-bound authorization flaws, role transitions,
and object ownership cannot be established without valid identities.

## Review gate

Stop here for owner review. No v2 detector, payload, oracle, floor, denominator,
or new fixture may be added until the owner approves the definitions and the
independent-review result is recorded.

# Research pack — class 2: secrets in responses and JavaScript

**Accessed:** 2026-11-16. **Purpose:** data and review guidance only; this file
contains no detector, regex corpus, or live verification code.

## Source inventory

| Source | Relevant public material | License / reuse note |
|---|---|---|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Rule metadata and a configurable secret-scanning model using identifiers, regex, keywords, path scope, secret groups, and entropy. | GitHub metadata reports MIT. Do not copy the rule corpus into Burhan without pinning the source revision and preserving attribution. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Detector taxonomy, source metadata, JSON/SARIF output shape, and a distinction between detected and verified credentials. | GitHub metadata reports AGPL-3.0. Treat code, detectors, and rule data as license-sensitive; use the public behavior as research input unless legal review approves reuse. |

## Pattern families to research

Keep the future data package at the family/metadata level: cloud access
identifiers, repository tokens, SaaS/API tokens, database credentials, private
keys, signing material, CI/CD credentials, and high-entropy bearer strings.
For each family record a source identifier, a short description, expected
prefix/shape, allowed locations, false-positive examples, and a redaction rule.
Do not copy full vendor regexes or example secrets into this repository.

## Distinguishing real findings from fixtures and public keys

A candidate should be downgraded or rejected when it is a documented example,
a placeholder, a repeated low-entropy value, a public key/certificate that is
not secret material, a checksum, a test fixture explicitly marked as fake, or a
value present in an allowlisted documentation path. Entropy alone is not proof.
A positive result needs a source-specific shape plus contextual evidence, and a
report must redact the value.

“Verification” must remain separate from detection. A future implementation
may only verify through an owner-approved local fixture or an explicitly
authorized service; this research pack does not authorize sending candidate
secrets to third parties. A safe oracle should distinguish invalid, fake,
public, and live states without storing the secret.

## Minimum evidence rule

For an unauthenticated response or JavaScript bundle, require a stable
candidate location, a source-family match, a bounded redacted excerpt or hash,
and a negative control containing a same-shaped placeholder. For a source-map
or bundle result, record the URL, asset hash, and line/column metadata rather
than the credential.

## Reuse and update procedure

Pin each imported source to a commit or release. Record the source license and
whether only metadata, a derived list, or source code is being reused. Review
allowlists and vendor formats on every update; never update rules by silently
copying a latest upstream file into a release.

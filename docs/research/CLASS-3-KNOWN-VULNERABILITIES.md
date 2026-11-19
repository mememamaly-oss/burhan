# Research pack — class 3: components with known vulnerabilities

**Accessed:** 2026-11-16. **Purpose:** data and review guidance only; this file
contains no version matcher or vulnerability detector.

## Source inventory and formats

| Source | Format / update model | License / reuse note |
|---|---|---|
| [OSV.dev](https://google.github.io/osv.dev/) | OSV JSON records and an API; aggregates vulnerability databases that adopt the OpenSSF Vulnerability format and models affected version ranges. | OSV infrastructure repository reports Apache-2.0. Confirm the terms for each aggregated record before redistribution. |
| [CVE List V5](https://github.com/CVEProject/cvelistV5) | Official CVE Record Format JSON, versioned records, daily baseline and hourly delta downloads; records may contain CNA, CVE Program, and optional ADP containers. | The repository points users to CVE Program Terms of Use; no SPDX license was reported by the GitHub API. Do not assume MIT/Apache or relicense records. |
| [GitHub Advisory Database](https://github.com/github/advisory-database) | Individual advisory files in OSV format, covering GitHub advisories and imported ecosystems including npm and pip; GHSA identifiers are stable advisory IDs. | Repository states CC-BY-4.0. Preserve attribution and follow its contribution/data guidance. |
| [Retire.js](https://github.com/RetireJS/retire.js) | JavaScript/Node vulnerability data used to identify vulnerable libraries outside manifests; the tool can emit CycloneDX SBOM. | GitHub metadata reports Apache-2.0. Pin the database revision and preserve attribution if deriving data. |

## Canonical normalized record

A future data-only export should normalize, without changing source meaning, to:

- ecosystem and package identity (prefer PURL where the source supplies it);
- source identifier (`CVE-*`, `GHSA-*`, OSV ID, or Retire.js record ID);
- affected ranges and fixed versions, preserving source range semantics;
- severity/CVSS/CWE when supplied, with source attribution;
- references, published/modified timestamps, and source revision;
- confidence and “source disagreement” flags when databases disagree.

Do not collapse CVE CNA and CVE Program/ADP containers without preserving their
provenance. Do not treat a package name match as proof that the deployed code
is the same artifact.

## Minimum evidence rule

A future finding requires an observed component identity and version, a
reproducible mapping to a pinned advisory record, and an affected-range match.
For browser assets, record the asset URL and content hash; for manifests,
record the lockfile path and a redacted dependency identity. A vulnerable
range alone is not proof that the vulnerable code is reachable or loaded.

## Update and conflict procedure

Use a pinned snapshot, record source timestamps, and refresh through an
owner-approved process. When OSV, CVE, GitHub Advisory, or Retire.js disagree,
retain all source IDs and mark the conflict for review rather than selecting a
winner silently. Keep source data separate from any later detector code.

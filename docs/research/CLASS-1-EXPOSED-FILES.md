# Research pack — class 1: exposed files, configuration, and backups

**Accessed:** 2026-11-16. **Purpose:** data and review guidance only; this file
contains no detector or request code.

## Source inventory

| Source | What can be learned | License / reuse note |
|---|---|---|
| [SecLists](https://github.com/danielmiessler/SecLists) — `Discovery/Web-Content` | Publicly documented wordlists for common web content, including filenames, directories, backup-like names, and sensitive-data-oriented lists. | Repository README states MIT. SecLists aggregates material; review the source file and upstream attribution before redistributing any copied entry. |
| [SecLists common web content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) | Families to model: administrative paths, deployment metadata, backup suffixes, editor/project metadata, well-known files, and framework-specific discovery. | Do not copy the list into Burhan. Store only source URL, source revision, and a small owner-approved vocabulary if later licensed for inclusion. |

## Normalized research categories

The safe research vocabulary should be organized by intent rather than by a
large payload dump:

- deployment and repository metadata: version-control directories, CI files,
  package manifests, lockfiles, build manifests, and source maps;
- configuration and environment: environment/config names, framework settings,
  service descriptors, and sample configuration files;
- backups and temporary copies: archive suffixes, editor swap/temporary files,
  renamed copies, and timestamped export conventions;
- operational exposure: health/status/debug endpoints and public diagnostics;
- platform-specific paths: web-server defaults, common framework admin paths,
  and `/.well-known/` metadata where the target owner has authorized it.

## Minimum evidence rule

A candidate should not become a finding merely because a path returns `200`.
The minimum evidence should be: an authorized local fixture or owner-approved
target; a stable response; content-type and bounded body evidence; a finding
that identifies the exposed class without copying secrets; and a safe negative
control showing that a generic `200` or branded error page is not enough.

For backup/config candidates, require a content marker that is specific to the
claimed class, such as parseable configuration structure or an archive/file
signature. Record only hashes or redacted excerpts in reports.

## Dangerous-path deletion filter

Before any future implementation, remove entries that could cause destructive
or high-impact behavior: upload handlers, delete/logout/action endpoints,
credential-reset links, payment/account-management routes, arbitrary URLs,
path traversal strings, shell metacharacters, and entries that resolve outside
the local fixture. This pack is not authorization to request any listed path.

## Reuse and update procedure

If a future owner-approved implementation uses this research, pin the exact
source commit, record the license beside the imported data, review every source
file for third-party attribution, and update by an explicit scheduled review.
Do not silently refresh a wordlist in a detector release.

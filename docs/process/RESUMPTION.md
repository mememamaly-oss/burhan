# Burhan infrastructure/research resumption

**Overall status: PENDING.** No branch was merged and `main` was not modified.

## Open PRs owned by this workstream

- #123 `manus/ci-speed`: pip and Playwright caching on the macOS job plus
  superseded-run cancellation. Baseline is three successful completed macOS
  jobs at 61.83, 62.10, and 61.78 minutes (mean 61.90). Three after-measurements
  are still pending; no speedup is claimed.
- #124 `manus/flaky-history`: read-only history of 74 qualifying runs from the
  newest 100-run API page; 4 failed workflow runs (5.41%), with no same-SHA
  recovery observed.
- #125 `manus/research-packs`: data-only research packs for classes 1–3,
  including source URLs, licenses/terms, access date, evidence rules, and
  provenance/update guidance.

The three-PR limit is reached. No fourth PR is open.

## Blocked or pending items

- M5 `manus/docker-ci`: blocked until #121 is merged; no Docker changes are
  being made now.
- M1 before/after: pending three completed post-change macOS measurements.
- M3 competitor workflow: pending capacity and owner review; it must be
  `workflow_dispatch` only and restricted to local development containers.
- M6 installation matrix: pending a free PR slot.
- M7 buyer-readiness tools, M8 supply-chain hardening, and M9 performance
  envelope: pending free PR slots and review of overlap with open PRs.
- SBOM/release: pending by policy; no release was created.

## Safety boundary

No isolated target, phaseC file, seal, oracle, detector, or GLM-owned `burhan/`
or existing `tests/` file was modified by this workstream. No external target
was scanned. No PyPI/GHCR publication occurred.

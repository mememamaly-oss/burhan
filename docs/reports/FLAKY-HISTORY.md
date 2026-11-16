# CI failure history

**Collection date:** 2026-11-16. **Scope:** the newest GitHub Actions API pages,
filtered to push runs on `main` and pull-request runs, until **100 qualifying
runs** were collected. This is a read-only history report; it does not change
tests or retry any run.

## Summary

- Selected runs: **100** from API pages 1–2.
- Failed workflow runs: **5** (**5.00%**).
- Failed runs with a later successful rerun for the same SHA and workflow in
the collected sample: **0**.
- This sample provides no evidence for a flaky failure that recovered on a
later same-SHA run.

## Every failed workflow run

| SHA | Workflow | Failed jobs/steps | Run |
|---|---|---|---|
| `d093d5437d0f8e86b201a743f2662368cf4a389e` | `CI` | `Run the action (local ref — this commit's action.yml)`; `Integration tests (bash-managed server — the supported path)`; `Scan the real target (baseline floor enforced)` | [43836214509](https://github.com/mememamaly-oss/burhan/actions/runs/43836214509) |
| `74a0d83769c0de5f097ebd113208aab340f48558` | `CI` | Linux and macOS `Quantum sweep gate` | [43832320722](https://github.com/mememamaly-oss/burhan/actions/runs/43832320722) |
| `94b1a7dd048f60e70dab4f43c796d775328ed7cc` | `CI` | Linux and macOS `Quantum sweep gate` | [43791656925](https://github.com/mememamaly-oss/burhan/actions/runs/43791656925) |
| `bdb5d36aba7a1fc38f31b2a45da20dc3a96b18d8` | `Manus preparation gates` | `Initialize owner gate in container` | [43788652258](https://github.com/mememamaly-oss/burhan/actions/runs/43788652258) |
| `bdb5d36aba7a1fc38f31b2a45da20dc3a96b18d8` | `CI` | Linux and macOS `Python security tests (incl. compliance mapping parity)` | [43788652147](https://github.com/mememamaly-oss/burhan/actions/runs/43788652147) |

The table lists unique failed workflow runs. Multiple jobs in one run are not
counted as independent workflow failures; the 5.00% rate is based on five
unique failed run IDs out of 100 qualifying runs.

## Classification

- `d093d...`: real CI/fixture contract failures; no same-SHA recovery observed.
- `74a0d...` and `94b1a...`: real Quantum sweep contract failures; no same-SHA
  recovery observed.
- `bdb5d...` preparation run: infrastructure/configuration failure at container
  owner-gate initialization.
- `bdb5d...` CI run: real Python security/compliance test failure.

## Method and limitations

The data came from `GET /repos/mememamaly-oss/burhan/actions/runs?per_page=100`
for pages 1–2 and the corresponding jobs endpoints. Collection stopped when
100 qualifying main-push or pull-request runs were available. Failed steps were
taken from the returned job records. A failure is called “flaky” only when the
same test/job later succeeds for the same commit or a repeated attempt clearly
recovers without a code change; none met that evidence standard here.

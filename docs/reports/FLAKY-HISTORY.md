# CI failure history

**Collection date:** 2026-11-16. **Scope:** the newest 100 repository workflow
runs returned by the GitHub Actions API, filtered to push runs on `main` and
pull-request runs. The API page contained 74 runs in that scope. This is a
read-only history report; it does not change tests or retry any run.

## Summary

- Selected runs: **74**.
- Failed workflow runs: **4** (**5.41%**).
- Failed runs with a later successful rerun for the same SHA and workflow in
  the collected page: **0**.
- Therefore, this sample does not provide evidence for a flaky failure that
  recovered on rerun. The entries below are classified from the failure step
  and its log, not from guesswork.

## Failure table

| Failure step / task | Failed runs | Rate of selected runs | Same-SHA success after rerun | Classification | Evidence |
|---|---:|---:|---|---|---|
| Quantum sweep gate (Linux and macOS jobs in the same CI run) | 2 runs, 4 failed jobs | 2.70% by run | No | Real contract failure | [run 43791656925](https://github.com/mememamaly-oss/burhan/actions/runs/43791656925), [run 43832320722](https://github.com/mememamaly-oss/burhan/actions/runs/43832320722) |
| Python security tests / compliance mapping parity | 1 run, 2 failed jobs | 1.35% by run | No | Real test failure | [run 43788652147](https://github.com/mememamaly-oss/burhan/actions/runs/43788652147) |
| Docker local fixture — owner-gate initialization | 1 run, 1 failed job | 1.35% by run | No | Infrastructure/configuration failure | [run 43788652258](https://github.com/mememamaly-oss/burhan/actions/runs/43788652258) |

The two jobs reported for a single Quantum sweep or Python-suite run are not
counted as two independent workflow failures; the rate uses unique failed
workflow runs.

## Rerun evidence

The failed CI SHAs in the collected sample were:

- `94b1a7dd048f60e70dab4f43c796d775328ed7cc` — no later successful CI run for
  the same SHA was present.
- `74a0d83769c0de5f097ebd113208aab340f48558` — no later successful CI run for
  the same SHA was present.
- `bdb5d36aba7a1fc38f31b2a45da20dc3a96b18d8` — no later successful CI run for
  the same SHA was present.

The API did contain successful CodeQL and security-ops runs for some of these
SHAs, but those are different workflows and do not count as a successful rerun
of the failed CI job.

## Method and limitations

The data came from `GET /repos/mememamaly-oss/burhan/actions/runs?per_page=100`
and `GET /repos/mememamaly-oss/burhan/actions/runs/{run_id}/jobs?per_page=100`.
Failed job steps were taken from the returned job records and checked against
the corresponding failed-run logs. The API response supplied 74 runs after the
requested main-push and pull-request filter, so the report does not claim 100
qualifying runs. Older pages were not read after the first page.

A failure is called “flaky” only when the same test/job later succeeds for the
same commit or a repeated attempt clearly recovers without a code change. None
of the four failed workflow runs met that evidence standard. No repairs are
proposed in this report.

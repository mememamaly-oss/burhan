# CI speed baseline

Measured from GitHub Actions API on 2026-11-16. No tests or required checks were removed.

| Run | Result | macOS job duration (minutes) |
|---:|---|---:|
| `43800786419` | `success` | 61.83 |
| `43800781504` | `success` | 62.10 |
| `43793028854` | `success` | 61.78 |

Baseline mean: **61.91 minutes**.

## Change in this PR

- Adds pip cache through `actions/setup-python`.
- Adds a Playwright browser cache on macOS.
- Cancels superseded CI runs for the same branch/PR via workflow `concurrency`.
- Does not delete, skip, weaken, or reorder tests or required checks.

## Before/after status

The three post-change measurements are **PENDING**. They must be recorded from three completed macOS runs for this PR or its follow-up before claiming a speedup.

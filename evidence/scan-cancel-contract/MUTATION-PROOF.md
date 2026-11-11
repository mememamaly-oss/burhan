# B3 mutation proof — part 2 (owner order 2026-11-11)

Ran on a disposable worktree at the MERGED main `87575117da`
(burhan-mut2, removed after the run). Every mutation was applied,
run, then reversed — `git diff --stat` printed clean after each pass.
Full harness: `scripts/b3_mutation_proof_part2.sh`.

| Pass | Mutation (product code, deliberately corrupted) | Result |
|------|--------------------------------------------------|--------|
| GREEN | none — merged main as-is | rc=0, test passes (1457.88ms), suite 0 fails |
| MUT-C | `src/lib/engine.ts`: cancel transaction no longer writes the `scan.cancelled` audit row | rc=1 — killed at `tests/api.integration.test.ts:369` (audit `hit` assertion): Expected `true` / Received `false` |
| MUT-D | `src/app/api/scans/[id]/route.ts`: DELETE returns `{success}` instead of `{ok, cancelled}` | rc=1 — killed at `tests/api.integration.test.ts:356` (`body.ok` assertion): Expected `true` / Received `undefined` |

Combined with part 1 (MUT-A wrong status literal, MUT-B lying DELETE):
all four B3 assertion groups — response status, response shape, DB row
state, audit-log row — are proven to fail when the code they protect is
corrupted. No assertion group is decorative.

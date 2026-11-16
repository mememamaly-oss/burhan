# Burhan — resumption report

**Overall status: PENDING**

The preparation work is partially complete and intentionally stops before any
new detection code, oracle, floor, denominator change, isolated-target access,
commit, PR, merge, PyPI publication, or GHCR publication.

## Evidence table

| Item | Status | Exact command / result | What remains |
|---|---|---|---|
| A. Blind wait in `tests/test_modernsec2.py` | DONE | `python3 -m pytest -q tests/test_authorized_targets.py tests/test_modernsec2.py --no-header` → `38 passed in 24.27s` | Run the full repository suite before PR review. |
| A. CPU-pressure load | DONE | 20 parallel invocations of `test_adversarial_A6_pinned_public_fetch_never_hits_internal` with 4 busy-loop workers → `a6_runs=20 failures=0` | Preserve the run logs if an external reviewer requires them. |
| B. Existing ownership gate | DONE / pre-existing | `tests/test_authorized_targets.py` covers unlisted refusal, exit 2, zero-request banner, DNS TXT, redirect/userinfo/path lookalikes, case, trailing dot, IDN lookalike, and true subdomains. Target gate remains live and uncached in `burhan/authorized_targets.py`. | Owner review of whether the current proof classes are the approved v2 definition. |
| C. Python packaging | DONE | Clean venv: `python3 -m venv /tmp/burhan-package-check`; `pip install .` → `pip_install=0`; `burhan doctor` → `doctor_exit=0`, `doctor_checks=19`, `doctor_failures=0`, `doctor_warnings=1`. | Review package name/version and release ownership before upload. |
| C. Dockerfile | PENDING | `command -v docker` → `docker_binary=missing`; image build and `docker run` could not be executed in this environment. | Run the exact commands in `docs/PUBLISHING.md` on a host with Docker and a local fixture. |
| D. SBOM | PENDING | No real security-ops run was performed against an actual release artifact. | Run approved security-ops at release time; do not mark this DONE from local dependency inspection. |
| E. Parser fuzzing | DONE (local campaign) | `python3 scripts/fuzz_parsers.py --seconds 1` → `targets=10`, `total_inputs=23758`, `total_crashes=0`, `wall_clock_s=10.0`; HTTP and SARIF targets were added. | Run the approved longer campaign and memory/hang watchdog in CI or security-ops. |
| Section 2. Design cards | PENDING OWNER REVIEW | Added `docs/DETECTION_EXPANSION_CARDS.md`; design only, with no detector or payload implementation. | Stop for owner review and independent review before any v2 code. |

## Files changed

- `tests/test_modernsec2.py`: removed the fixed `time.sleep(1.5)` from A6; the synchronous request completion is now the observable synchronization point.
- `scripts/fuzz_parsers.py`: added bounded vault-envelope JSON, HTTP-header, and SARIF-shape campaigns.
- `pyproject.toml`: added pip-installable metadata and the `burhan` console script.
- `Dockerfile`: installs the package and runs as UID 10001, not root.
- `docs/PUBLISHING.md`: exact local, Docker, PyPI, and GHCR instructions; publication is owner-operated and was not performed.
- `docs/DETECTION_EXPANSION_CARDS.md`: six design-only cards; the mandated review gate is recorded.

## Not tested or not performed

The full test suite, macOS check-runs, Docker build/run, a real release SBOM,
PyPI upload, GHCR push, and any remote PR/merge were not performed. No isolated
Shepherd, XVWA, WackoPicko, VAmPI, or RailsGoat target was read or contacted.
Only repository-local fixtures and parser inputs were used.

## Owner actions required

1. Revoke and rotate the GitHub personal access token that was pasted into the
   work-order attachment. It was not used, copied into the repository, or echoed
   in this report.
2. Review and approve the six v2 class definitions and their measurement/oracle
   rules in `docs/DETECTION_EXPANSION_CARDS.md`.
3. Provide or enable a Docker-capable environment for the Docker validation and
   a macOS check-run source for the required 100%/zero-failure release gate.
4. Decide the package version/name and authorize any release publication.
5. Run approved security-ops for the actual release artifact to close the SBOM
   item.

## Stop condition

Work stops here pending owner review of the design cards and release/security
validation. No detector expansion has been implemented.

# Development competitor comparison

This report describes the manual-only `internal` mode of the existing
`.github/workflows/vulnweb-pin-probe.yml` dispatch workflow. The mode is
explicitly selected and is not a push or pull-request trigger. The legacy
permission-page probe is skipped in this mode.

## Scope

The controlled development set is Juice Shop v20.3.0, crAPI from pinned source
commit `700f03d12a392d9e408260b4beae72ed02a4a1a4`, WebGoat v2023.4, and DVWA
1.9. They run on a private Docker bridge named `burhan-dev`; host ports are
bound to loopback only. ZAP and Nuclei join the same bridge and address targets
by container alias. No external target is used.

All target images, crAPI service images, databases, and scanner images are
referenced by immutable Docker digests in
`scripts/ci_internal_competitor.sh`. The crAPI compose file is fetched from the
pinned source commit and its expected image references are checked before
replacement with the pinned digests.

## Comparison output

For each target the workflow runs a ZAP baseline scan and a Nuclei scan, then
writes raw artifacts and `comparison-summary.json`. The summary reports totals,
severity/category keys, and the intersection of normalized `severity:name`
keys. This is a tool-output comparison, not a claim of ground truth or equal
coverage. Findings do not fail the workflow; tool execution errors do.

## Execution status

The first dispatch was run 43870912563. The internal job completed successfully
in 16m05s and produced Nuclei outputs for all four targets, but ZAP reported an
`AccessDeniedException` while writing its report, so the expected ZAP JSON/HTML
reports were absent. The second dispatch, 43876225804, correctly failed closed
when the reports were still missing. The script now runs ZAP as root only
inside the disposable container, uses relative report names (the image maps
them under `/zap/wrk`), and fails closed when either report is missing.

The third dispatch, 43877456695, passed in 5m43s. It produced non-empty ZAP
JSON/HTML reports and Nuclei JSONL outputs for all four targets, plus the
[comparison artifact](https://github.com/mememamaly-oss/burhan/actions/runs/43877456695/artifacts/14231905000).
The summary recorded ZAP totals of 10 (crAPI), 15 (DVWA), 9 (Juice Shop), and
13 (WebGoat). Nuclei completed with zero emitted findings in this run; that is
reported as zero output, not as proof that the applications are clean. The
comparison is tool-output telemetry, not ground truth or a coverage claim.
No external target, isolated target, phaseC path, or seal path is an input.

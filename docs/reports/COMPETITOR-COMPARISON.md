# Development competitor comparison

This report describes the manual-only workflow in
`.github/workflows/competitor-comparison.yml`. It is intentionally not a
pull-request or push trigger. A run requires the explicit input
`INTERNAL-LAB`.

## Scope

The controlled development set is Juice Shop v20.3.0, crAPI from pinned source
commit `700f03d12a392d9e408260b4beae72ed02a4a1a4`, WebGoat v2023.4, and DVWA
1.9. They run on a private Docker bridge named `burhan-dev`; host ports are
bound to loopback only. ZAP and Nuclei join the same bridge and address targets
by container alias. No external target is used.

All target images, crAPI service images, databases, and scanner images are
referenced by immutable Docker digests in the workflow. The crAPI compose file
is fetched from the pinned source commit and its expected image references are
checked before replacement with the pinned digests.

## Comparison output

For each target the workflow runs a ZAP baseline scan and a Nuclei scan, then
writes raw artifacts and `comparison-summary.json`. The summary reports totals,
severity/category keys, and the intersection of normalized `severity:name`
keys. This is a tool-output comparison, not a claim of ground truth or equal
coverage. Findings do not fail the workflow; tool execution errors do.

## Execution status

**PENDING:** the workflow must be dispatched manually on the development set.
No external target, isolated target, phaseC path, or seal path is an input.

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
replacement with the pinned digests. Nuclei templates are downloaded from the
official GitHub codeload archive in a separate networked preparation step as
v10.5.0, commit
`f8b8b8dcd70d93826c3767e1829ef8243af9f03b`, with tarball SHA-256
`80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41`. The
download step prints the YAML template count; the scan step independently
lists templates from the mounted directory before scanning.

## Comparison output

For each target the workflow runs **ZAP baseline mode**, not ZAP active mode,
and a Nuclei HTTP-template scan against the private Docker network. It writes
raw artifacts, `comparison-summary.json`, and a category matrix. The Nuclei
step fails closed on a fatal `[FTL]` log, any non-zero exit code, a missing
`nuclei.jsonl`, or invalid JSONL. The matrix reports each category's ZAP and
Nuclei findings, evidence names, and whether one tool observed a category that
the other did not. This is tool-output telemetry, not ground truth or a
coverage claim.

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


## Corrected final run

The corrected final dispatch was **43953761548**, on commit `b7df84e413ceb70539d6ee54503f494b85ef9664`, and passed in 16m47s. The artifact is [competitor-comparison-43953761548](https://github.com/mememamaly-oss/burhan/actions/runs/43953761548/artifacts/14271590177).

Nuclei used image `docker.io/projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97` with templates v10.5.0, commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`, and tarball SHA-256 `80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41`. The preparation step counted **14,036 YAML files**; the runtime Nuclei image listed **11,199 templates** from the mounted directory. No `[FTL]` records were present. The JSONL result counts were crAPI 17, DVWA 10, Juice Shop 15, and WebGoat 22, and all four JSONL files parsed successfully.

ZAP ran in **baseline mode**, not active mode. The category table below is generated from the artifact's `comparison-table.md`; `Gap=yes` means one tool emitted findings in that category while the other emitted none. It is a comparison of tool outputs, not ground truth.

| Target | Category | ZAP | Nuclei | Evidence | Gap? |
|---|---|---:|---:|---|---|
| crAPI | csp-clickjacking-csrf | 2 | 0 | CSP header not set; missing anti-clickjacking header | yes |
| crAPI | exposed-files-endpoints | 0 | 4 | `.env` discovery; generic env disclosure; robots.txt | yes |
| crAPI | other | 1 | 2 | storable/cacheable content; OpenResty; SOA detection | no |
| crAPI | security-headers | 5 | 10 | cross-origin policies; permissions policy; HTTP missing headers | no |
| crAPI | technology-version-disclosure | 2 | 1 | server version; modern web; Laravel sensitive disclosure | no |
| DVWA | cookies-and-session | 3 | 3 | HttpOnly; SameSite; session management | no |
| DVWA | csp-clickjacking-csrf | 2 | 0 | CSP header not set; missing anti-clickjacking header | yes |
| DVWA | exposed-files-endpoints | 0 | 3 | robots.txt; configuration listing | yes |
| DVWA | other | 2 | 3 | non-storable/cacheable content; WAF detection/fuzzing | no |
| DVWA | security-headers | 5 | 0 | cross-origin policies; permissions policy; X-Content-Type-Options | yes |
| DVWA | technology-version-disclosure | 3 | 1 | Apache version; server version; suspicious comments; Wappalyzer | no |
| Juice Shop | csp-clickjacking-csrf | 1 | 0 | CSP header not set | yes |
| Juice Shop | exposed-files-endpoints | 1 | 1 | cross-domain misconfiguration; public Swagger API | no |
| Juice Shop | javascript-xss | 0 | 1 | DOM EventListener detection | yes |
| Juice Shop | other | 5 | 3 | dangerous JS; deprecated policy; cache findings | no |
| Juice Shop | security-headers | 2 | 8 | cross-origin policies; HTTP missing security headers | no |
| Juice Shop | technology-version-disclosure | 1 | 2 | modern web; FingerprintHub; Wappalyzer | no |
| WebGoat | authentication-authorization | 1 | 0 | authentication request identified | yes |
| WebGoat | cookies-and-session | 3 | 3 | HttpOnly; SameSite; session/cookie findings | no |
| WebGoat | csp-clickjacking-csrf | 2 | 0 | anti-CSRF tokens; CSP header not set | yes |
| WebGoat | exposed-files-endpoints | 0 | 3 | Spring Boot env/configprops/health actuator | yes |
| WebGoat | javascript-xss | 1 | 1 | potential XSS attribute; XSS-Protection detection | no |
| WebGoat | other | 2 | 4 | cacheability; internal IP; form/WordPress detection | no |
| WebGoat | security-headers | 4 | 8 | cross-origin policies; permissions policy | no |
| WebGoat | technology-version-disclosure | 0 | 3 | Wappalyzer technology detections | yes |

The raw reports, complete evidence names, JSONL files, and machine-readable matrix are in the linked artifact. No PR was merged.

## References

[1]: https://docs.projectdiscovery.io/opensource/nuclei/running "Nuclei running and template directory documentation"
[2]: https://github.com/projectdiscovery/nuclei-templates/releases/tag/v10.5.0 "Nuclei templates v10.5.0 release"

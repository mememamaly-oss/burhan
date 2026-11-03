#!/usr/bin/env python3
"""CodeQL alert dismissals (owner order 2026-10-31, part 4.8 follow-up).

Dismisses the alerts that the 2026-10-31 triage classified as
false-positives-by-context, each with its documented reason. Alerts fixed
in code (#31 readLogTail, and the ReDoS trio after the caps) close
themselves when the next main-branch analysis runs — they are NOT
dismissed here. Token comes from the GITHUB_TOKEN env (inline only).

Exit 0 = all attempted dismissals succeeded; non-zero lists failures.
"""
import json
import os
import sys
import urllib.request

API = "https://api.github.com/repos/mememamaly-oss/burhan/code-scanning/alerts"

# alert number -> (reason, comment). Reasons must be one of:
# "false positive" | "won't fix" | "used in tests" | "mitigated"
DISMISSALS = {
    # py/bad-tag-filter — scanner PARSER regexes (extract script blocks from
    # attacker-controlled pages); the rule targets regex SANITIZERS. Worst
    # case is a missed detection, never a platform vulnerability.
    49: ("false positive", "Scanner parser regex (extracts <script> blocks from scanned pages for analysis), not a sanitizer. Evasion would mean a missed detection in scan output, not a compromise of the platform. Triage 2026-10-31, STATE.md."),
    48: ("false positive", "Same parser-not-sanitizer class as #49 (browser.py script-block extraction). Triage 2026-10-31, STATE.md."),
    47: ("false positive", "Same parser-not-sanitizer class as #49 (detect.py script/style span check for Angular-context analysis). Triage 2026-10-31, STATE.md."),
    # py/weak-sensitive-data-hashing — SHA-1 over INTERNAL id derivation
    # (finding/hypothesis/canary ids). Not sensitive data; a collision's
    # worst case is a shared id prefix. Changing them would break the
    # committed deterministic reproducibility floors.
    46: ("false positive", "SHA-1 for internal TwinNode id derivation (_nid), not sensitive-data hashing. Deterministic ids are a product property (reproducibility floors pin them). Triage 2026-10-31, STATE.md."),
    45: ("false positive", "SHA-1 for internal hypothesis id derivation (_hid), same class as #46. Triage 2026-10-31, STATE.md."),
    44: ("false positive", "SHA-1 for upload-canary name derivation, same class as #46. Triage 2026-10-31, STATE.md."),
    43: ("false positive", "SHA-1 for OOB probe id derivation, same class as #46. Triage 2026-10-31, STATE.md."),
    # py/insecure-protocol — the scanner's own WsClient connecting to SCAN
    # TARGETS with certificate verification disabled: a DAST tool must
    # accept self-signed certificates on the systems it assesses.
    42: ("won't fix", "The scanner's raw WebSocket client connecting to scan TARGETS; certificate verification is deliberately disabled so self-signed targets stay assessable. Not a trust decision about burhan's own infrastructure. Triage 2026-10-31, STATE.md."),
    # py/clear-text-logging-sensitive-data — the CLI printing scan findings
    # and statistics is the product's report output, not credential logs.
    41: ("won't fix", "CLI scan summary output (target, stats, finding lines) — the product's report channel, not secret logging. Triage 2026-10-31, STATE.md."),
    40: ("won't fix", "Same output channel as #41. Triage 2026-10-31, STATE.md."),
    39: ("won't fix", "Benchmark JSON output, same channel class as #41. Triage 2026-10-31, STATE.md."),
    # py/incomplete-url-substring-sanitization — substring checks are the
    # DETECTION ORACLE for the probe host in redirect responses, not
    # sanitization of untrusted input.
    38: ("false positive", "Substring check is the detection ORACLE (does our canary host appear in the redirect target), not sanitization. A crafted target could at worst cause a false positive in scan output. Triage 2026-10-31, STATE.md."),
    37: ("false positive", "Same oracle class as #38. Triage 2026-10-31, STATE.md."),
    36: ("false positive", "Same oracle class as #38. Triage 2026-10-31, STATE.md."),
    35: ("false positive", "Same oracle class as #38. Triage 2026-10-31, STATE.md."),
    # js/insecure-temporary-file + py/overly-permissive-file — test and
    # one-off evidence scripts creating their own fixture files.
    34: ("used in tests", "Integration test writes its own fixture report file under BURHAN_DATA_DIR (a dedicated test-data dir), not a shared temp path with secrets. Triage 2026-10-31, STATE.md."),
    33: ("used in tests", "One-off XSS-proof evidence script writing a deliberately hostile report into its test-data dir; not invoked by CI. Triage 2026-10-31, STATE.md."),
    32: ("used in tests", "The vault hygiene test DELIBERATELY creates a 0644 key file to prove the permissions gate refuses it — that is the regression itself. Triage 2026-10-31, STATE.md."),
    # fixtures/vulnapp.py — the intentionally vulnerable fixture IS the
    # scanner's ground truth; removing these destroys the 38/38 benchmark.
    24: ("won't fix", "fixtures/vulnapp.py is the INTENTIONALLY vulnerable fixture that is the scanner's ground truth (deterministic 38/38 benchmark gate). Its SSRF is the product's test subject, not a defect. Triage 2026-10-31, STATE.md."),
    14: ("won't fix", "Intentionally vulnerable fixture, same class as #24. Triage 2026-10-31, STATE.md."),
    # py/clear-text-storage-sensitive-data — CI scan scripts writing scan
    # REPORTS (the evidence product) to the run's output dir.
    4: ("false positive", "reverify script stores the scan report (the product's evidence output) to its evidence dir; no credentials are persisted. Triage 2026-10-31, STATE.md."),
    3: ("false positive", "CI real-target script stores scan reports, same class as #4. Triage 2026-10-31, STATE.md."),
    2: ("false positive", "CI real-target script stores scan reports, same class as #4. Triage 2026-10-31, STATE.md."),
    1: ("false positive", "CI fixture script stores scan reports, same class as #4. Triage 2026-10-31, STATE.md."),
    # js/polynomial-redos — MEASURED linear on V8 (3 MB pathological email
    # = 7.1 ms; slugify 1 MB = 3.8 ms); length caps added as defense.
    30: ("false positive", "slugify regex measured LINEAR on V8 (1 MB input = 3.8 ms) — negated character classes, no catastrophic backtracking. Input length caps added anyway in PR #7. Triage 2026-10-31, STATE.md."),
    29: ("false positive", "Email validation regex measured LINEAR on V8 (3 MB pathological input = 7.1 ms). RFC 5321 length cap added before the regex in PR #7. Triage 2026-10-31, STATE.md."),
    28: ("false positive", "Same regex class as #29, measured linear, capped in PR #7. Triage 2026-10-31, STATE.md."),
    # py/clear-text-storage-sensitive-data — the live-validation script's
    # OWN seeded throwaway accounts (Burhan-Live-123! / Burhan-Race-123!
    # / marker passwords) for DISPOSABLE local crAPI/DVGA containers that
    # the CI job builds from scratch and tears down in the same run. The
    # verdict file it writes was inspected (run 41730556960 artifact): no
    # credential material beyond the tool's own canary markers — "plaintext
    # by design, the product's evidence output" (the script's own comment
    # at the write_report call). Same triage class as #4/#3/#2/#1. No real
    # credential exists anywhere in this flow — every password literal is
    # minted by the script itself for a container that dies with the job.
    256: ("used in tests", "Script's own seeded throwaway accounts for disposable CI containers (built and torn down in the same job) plus scanner canary markers — evidence output, plaintext by design; no real credential exists in the flow (verified vs run 41730556960 artifact). Round-7 triage 2026-11-03."),
}


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("FATAL: GITHUB_TOKEN env not provided")
        return 1
    failures = []
    for num, (reason, comment) in sorted(DISMISSALS.items()):
        body = json.dumps({"state": "dismissed", "dismissed_reason": reason,
                           "dismissed_comment": comment}).encode()
        req = urllib.request.Request(f"{API}/{num}", data=body, method="PATCH",
                                     headers={
                                         "Authorization": f"Bearer {token}",
                                         "Accept": "application/vnd.github+json",
                                         "Content-Type": "application/json",
                                     })
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                print(f"#{num}: dismissed ({reason}) HTTP {r.status}")
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:160]
            print(f"#{num}: FAILED HTTP {e.code} {detail}")
            failures.append(num)
        except Exception as e:  # noqa: BLE001
            print(f"#{num}: FAILED {e}")
            failures.append(num)
    if failures:
        print("FAILURES:", failures)
        return 2
    print(f"all {len(DISMISSALS)} dismissals applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())

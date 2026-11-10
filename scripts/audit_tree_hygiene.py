#!/usr/bin/env python3
"""Tree hygiene gate (R16-1, owner order 2026-11-07).

The r15 incidents: `git add -A` under time pressure swept RUNTIME
artifacts into real commits on main — twice (CAPABILITY_MATRIX.md via
3e34202, results/scan.json via cce5852 and AGAIN via 217ce0b; the second
one was only caught because close-out forced a fresh clone). The review
afterwards made the human rule permanent — explicit `git add <file>`
only, `git status` read before every commit, `git show --stat HEAD`
after. This gate is the CI backstop for the same failure class:
whatever slips past a human must fail the build, not ride to main.

What it enforces, on the TRACKED tree (`git ls-files`) only:
  - results/** must not be tracked. results/ is the CLI's default --out
    directory (scan, benchmark, replay-rate-limit state): per-run
    output, never a deliverable. The one historical exception,
    results/replay-rate-limit.json (r13), was untracked in the same
    commit that introduced this gate — replay.py recreates the file at
    runtime (mkdir parents=True) and treats a missing file as fresh
    state by design, so untracking changes nothing at runtime.
  - CAPABILITY_MATRIX.md must not be tracked anywhere — a session lab
    artifact, never a product deliverable.

The ALLOWLIST exists for the day a file under results/ genuinely earns
tracking (none today). An entry must carry a reason and a date; the
gate prints the ledger on every run so an unreviewed entry is visible.

Deliberately NOT flagged: evidence/** and fixtures/** — intentionally
vulnerable/regex-bearing test data IS the product's ground truth
(SCA manifests, vulnapp, gitleaks config); the hygiene gate must never
punish the evidence doctrine.

Exit 0 = tree clean; exit 1 = violations listed as ::error annotations.
"""

import argparse
import re
import subprocess
import sys

# (anchored pattern, class label, why) — deny rules for TRACKED paths.
DENY_RULES = [
    (
        re.compile(r"^results/"),
        "runtime output",
        "results/ is the CLI's default --out dir (scan/benchmark/replay "
        "state) — per-run output, never a tracked deliverable (r15: "
        "results/scan.json reached main twice via add -A)",
    ),
    (
        re.compile(r"(^|/)CAPABILITY_MATRIX\.md$"),
        "lab artifact",
        "session lab artifact, not a product deliverable (r15: reached "
        "main via add -A in 3e34202)",
    ),
    (
        re.compile(r"(^|/)--$"),
        "stray flag artifact",
        "empty file born of a mistyped CLI flag — removed in 7ed4cdf, "
        "re-tracked in 2a4210e; a filename the shell ate once will be "
        "eaten again (r17-1)",
    ),
    # Phase-A.3b (2026-11-10): credential artifacts. History shows the
    # class is real: `git add -A` swept .env into git via the b9c8b03
    # container-junk commit (benign 1-line sqlite path, untracked two
    # weeks later in 88fa11c) — next time the file may not be benign.
    # The staged file itself is the failure; no content sniffing (that
    # is a scanner's job, not a tree gate's).
    (
        re.compile(r"^\.secrets/"),
        "credential artifact",
        "local credential store — never tracked (.secrets/ holds "
        "operator tokens; the 9e9037c accident class, Phase A audit)",
    ),
    (
        re.compile(r"(^|/)(id_rsa|id_ed25519)(\.|$)"),
        "credential artifact",
        "SSH private key by name — staging it must fail the build",
    ),
    (
        re.compile(r"(^|/)\.env(\.[^.]+)?$"),
        "credential artifact",
        "environment file — the exact 9e9037c accident (.env tracked "
        "for two weeks); .env.example stays allowed as the template",
    ),
    (
        re.compile(r".*\.(pat|pem|key)$"),
        "credential artifact",
        "credential-bearing extension (*.pat/*.pem/*.key) — staging it "
        "must fail the build (Phase A audit)",
    ),
]

# Tracked exceptions for the credential rules above, same reviewed-ledger
# discipline as ALLOWLIST: (date, reason). These are REAL product files
# whose names merely resemble credentials.
CREDENTIAL_ALLOWLIST = {
    ".env.example": (
        "2026-11-10",
        "the shipped environment template — documented in README and "
        "INSTALLATION_GUIDE; contains placeholders only",
    ),
}

# tracked path -> (date, reason). Empty today; any addition is a
# reviewed, documented decision that the gate prints on every run.
ALLOWLIST: dict = {}


def tracked_files() -> list:
    """The tracked tree, straight from git (no directory walk tricks)."""
    out = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p.decode() for p in out.split(b"\0") if p]


def violation(path: str):
    """Return (rule_label, why) if a tracked path is denied, else None.

    Allowlisted paths pass REGARDLESS of the deny rules — the allowlist
    is the reviewed exception ledger, checked first on purpose.
    """
    if path in ALLOWLIST:
        return None
    for pattern, label, why in DENY_RULES:
        if pattern.search(path):
            if path in CREDENTIAL_ALLOWLIST:
                return None
            return (label, why)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="runtime-artifact tracking gate")
    ap.add_argument(
        "--ci-gate",
        action="store_true",
        help="exit 1 with ::error annotations on any violation",
    )
    args = ap.parse_args()

    bad = []
    for path in tracked_files():
        verdict = violation(path)
        if verdict:
            bad.append((path, verdict[0], verdict[1]))

    if ALLOWLIST:
        print(f"allowlist ({len(ALLOWLIST)} reviewed exceptions):")
        for path, (date, reason) in sorted(ALLOWLIST.items()):
            print(f"  {path}  [{date}]  {reason}")

    if not bad:
        print("tree hygiene: clean — no runtime artifacts tracked")
        return 0

    for path, label, why in bad:
        print(f"::error file={path}::tracked {label}: {path} — {why}")
    print(
        f"tree hygiene: {len(bad)} violation(s) — untrack with "
        f"`git rm --cached <path>` (it is runtime output); a genuine "
        f"exception needs a reviewed ALLOWLIST entry with a reason and "
        f"a date"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

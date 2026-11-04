"""Propose-and-prove remediation — round 9, part 3 (2026-11-04).

THE HARD ARCHITECTURAL RULE (order 3.1), ENFORCED IN CODE, not in
documentation: this pipeline NEVER writes to or modifies the actual
scanned target. It operates only on an ISOLATED CLONE the client
explicitly provides (a client-owned repo checkout / a copied source tree)
or a client-provided staging instance. The enforcement points:

  - assert_isolated() (below) — the single choke point every entry passes
    FIRST: it raises IsolationViolation when the work surface's host:port
    equals the scanned target's host:port, when the work surface is the
    scanned target itself, or when no isolated surface is provided at
    all (3.4: the stage is refused entirely, never substituted with the
    live target). Same host on a different port additionally requires the
    explicit allow_same_host_staging=True flag (a plausible staging shape,
    but never the default).
  - the patch application function (apply_patch) takes ONLY a local
    directory path of the clone — it has no code path that can write to
    any URL; it never sees the target.
  - there is NO merge and NO deploy function in this module — by design.
    The output is a diff/PR bundle delivered to the CLIENT's review
    system; the client's own team merges it. Nothing here can push to a
    client remote even with the master-password step-up (the step-up
    gates patch generation and closure re-exploitation; it unlocks
    nothing else).

Pipeline per finding: RED (the original exploit reproduced on the
UNPATCHED clone — a real probe, refused if it does not reproduce) →
patch (applied to the clone only) → BLUE (the same exploit re-run on the
PATCHED clone and observed to FAIL) → the diff/PR bundle.

Unsupported finding classes are refused loudly (RemediationRefused) with
the Part-1 report-only fallback (report_only_fallback) — never a
best-effort patch on an unsupported shape.
"""
from __future__ import annotations

import difflib
import json
import os
import urllib.parse
import urllib.request

from .stepup import StepUpGate


class IsolationViolation(RuntimeError):
    """3.1's hard rule fired: the work surface is not isolated from the
    scanned target. The whole stage refuses — loud, not silent."""


class RemediationRefused(RuntimeError):
    """The remediation stage refuses: no isolated clone/staging available
    (3.4), or the finding class has no patch strategy yet. The Part-1
    report-only fallback is the output in this case."""


# ---- 3.1: the isolation choke point -----------------------------------------

def _host_port(url: str) -> tuple[str, int]:
    u = urllib.parse.urlsplit(url if "//" in url else "//" + url,
                              scheme="http")
    host = (u.hostname or "").lower()
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port


def assert_isolated(target_url: str, work_url: str,
                    *, allow_same_host_staging: bool = False) -> None:
    """THE hard rule in code. `work_url` is where the pipeline may operate
    (the clone/staging base URL). Raises IsolationViolation unless the
    work surface is provably not the scanned target."""
    if not target_url:
        raise IsolationViolation("no scanned target given — nothing to "
                                 "isolate from, refusing")
    if not work_url:
        raise IsolationViolation(
            "3.4: no isolated clone/staging instance provided — the "
            "remediation stage is REFUSED ENTIRELY (the live target is "
            "never a substitute); the output falls back to the Part-1 "
            "report-only guidance")
    th, tp = _host_port(target_url)
    wh, wp = _host_port(work_url)
    if (th, tp) == (wh, wp):
        raise IsolationViolation(
            f"the work surface {work_url!r} IS the scanned target "
            f"({target_url!r}, host:port {th}:{tp}) — the pipeline never "
            f"writes to the scanned target under any circumstance")
    if th == wh and not allow_same_host_staging:
        raise IsolationViolation(
            f"the work surface {work_url!r} shares the scanned target's "
            f"host ({th}) on a different port — that only counts as "
            f"staging with the explicit allow_same_host_staging=True flag "
            f"(not the default); refusing")


# ---- the patch strategies (line-anchored, source-pattern based) --------------

STRATEGIES: dict[str, dict] = {
    "xss_reflected": {
        # the fixed shape is the fixture's OWN safe pattern
        # (fixtures/vulnapp.py /safe/search.php) — same escaping the app
        # already uses elsewhere, not an invented fix.
        "file": "vulnapp.py",
        "anchor": 'if path == "/vuln/xss.php":',
        "vulnerable": 'qv = q.get("q", "")',
        "fixed": ('qv = q.get("q", "").replace("<", "&lt;")'
                  '.replace(">", "&gt;")'),
        "probe_path": "/vuln/xss.php",
        "probe_param": "q",
        "probe_payload": "<burhan-r9-xss>",
        "explanation": ("HTML-escape the reflected parameter before "
                        "rendering — the exact escaping the application "
                        "already applies on its own /safe/search.php "
                        "surface (defense the codebase itself proves "
                        "correct)."),
    },
}


def build_patch(finding: dict, clone_dir: str) -> dict:
    """Produce the unified diff for one finding on the clone. Refuses
    (RemediationRefused) for unsupported classes — never a best-effort
    patch on an unsupported shape."""
    st = STRATEGIES.get(finding.get("type", ""))
    if st is None:
        raise RemediationRefused(
            f"no patch strategy for {finding.get('type')!r} yet — this "
            f"stage refuses rather than guessing; the Part-1 report-only "
            f"guidance is the output for this finding")
    src = os.path.join(clone_dir, st["file"])
    try:
        # EAFP (CI-live-caught TOCTOU, 2026-11-04): the open IS the check —
        # no exists() window between looking and reading; a missing file is
        # the loud refusal below.
        lines = open(src, encoding="utf-8").read().splitlines(keepends=True)
    except FileNotFoundError:
        raise RemediationRefused(
            f"the clone does not contain {st['file']!r} — the strategy's "
            f"anchor file is absent; refusing")
    anchor_i = next((i for i, ln in enumerate(lines)
                     if ln.strip() == st["anchor"].strip()), None)
    if anchor_i is None:
        raise RemediationRefused(
            f"anchor {st['anchor']!r} not found in {st['file']} — the "
            f"clone's shape does not match the strategy; refusing")
    window = lines[anchor_i + 1:anchor_i + 6]
    vuln_i = next((anchor_i + 1 + j for j, ln in enumerate(window)
                   if ln.strip() == st["vulnerable"]), None)
    if vuln_i is None:
        raise RemediationRefused(
            f"the vulnerable line {st['vulnerable']!r} was not found "
            f"after the anchor — either already patched or a different "
            f"shape; refusing to guess")
    new_lines = list(lines)
    indent = new_lines[vuln_i][:len(new_lines[vuln_i]) -
                               len(new_lines[vuln_i].lstrip())]
    new_lines[vuln_i] = indent + st["fixed"] + "\n"
    diff = list(difflib.unified_diff(
        lines, new_lines, fromfile=f"a/{st['file']}",
        tofile=f"b/{st['file']}", lineterm="\n"))
    return {"file": st["file"], "line": vuln_i + 1, "diff": "".join(diff),
            "strategy": finding.get("type"), "explanation": st["explanation"]}


def apply_patch(patch: dict, clone_dir: str) -> str:
    """Apply the diff to the CLONE ONLY (a local directory path — this
    function has no URL code path at all; the scanned target is not a
    parameter it can even see)."""
    src = os.path.join(clone_dir, patch["file"])
    lines = open(src, encoding="utf-8").read().splitlines(keepends=True)
    i = patch["line"] - 1
    st = STRATEGIES[patch["strategy"]]
    if lines[i].strip() != st["vulnerable"]:
        raise RemediationRefused(
            "the clone changed under the patch (line no longer "
            "vulnerable shape) — refusing to apply blind")
    indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
    lines[i] = indent + st["fixed"] + "\n"
    open(src, "w", encoding="utf-8").write("".join(lines))
    return src


# ---- the RED->BLUE probes -----------------------------------------------------

def reflection_probe(work_url: str, finding: dict) -> dict:
    """The original exploit re-run as a real HTTP probe: the finding's own
    parameter reflected unescaped = exploitable (RED); escaped = the
    exploit fails (BLUE). This is the exploit's oracle itself, not a
    simulation."""
    st = STRATEGIES.get(finding.get("type", ""))
    if st is None:
        raise RemediationRefused(
            f"no probe strategy for {finding.get('type')!r}")
    url = work_url.rstrip("/") + st["probe_path"] + "?" + \
        urllib.parse.urlencode({st["probe_param"]: st["probe_payload"]})
    with urllib.request.urlopen(url, timeout=10) as r:
        body = r.read().decode("utf-8", "replace")
    raw = st["probe_payload"] in body            # unescaped reflection
    escaped = "&lt;" in body and st["probe_payload"] not in body
    return {"url": url, "raw_reflection": raw, "escaped": escaped,
            "exploitable": raw}


# ---- the gated pipeline --------------------------------------------------------

def closure_reexploit(finding: dict, work_url: str, gate: StepUpGate,
                      credential: str | None,
                      probe=reflection_probe) -> dict:
    """2.1(a): re-exploit a finding for closure-proof purposes — gated by
    the master-password step-up FIRST (StepUpRequired without it, the
    refusal already in the audit chain). The probe runs against the
    isolated work surface only."""
    gate.require("closure_reexploit", credential)
    return probe(work_url, finding)


def report_only_fallback(finding: dict, reason: str) -> dict:
    """3.4: the explicit fallback — no isolated clone/staging available,
    so the fix stage is refused entirely and the output is the Part-1
    bilingual report's remediation guidance (sourced from the compliance
    registry), plus the refusal reason. The live target is NEVER touched
    as a substitute."""
    from .bilingual import _guidance
    g = _guidance(finding)
    return {
        "mode": "report-only-fallback",
        "reason": reason,
        "type": finding.get("type", ""),
        "remediation_ar": g["steps_ar"],
        "remediation_en": g["steps_en"],
        "guidance_source": g["source"],
        "note": ("no isolated clone/staging was provided for this target; "
                 "the fix stage was refused ENTIRELY (order 3.4) — the "
                 "live scanned target is never a substitute"),
    }


def run_remediation(finding: dict, *, target_url: str, work_url: str,
                    clone_dir: str, gate: StepUpGate,
                    credential: str | None,
                    allow_same_host_staging: bool = False,
                    restart_workload=None,
                    probe=reflection_probe) -> dict:
    """The full propose-and-prove pipeline. Order of operations is the
    discipline itself:
      0. assert_isolated — 3.1's hard rule, FIRST, before anything;
         no work surface -> RemediationRefused + the report-only fallback
         payload (3.4) instead of ever considering the live target.
      1. the step-up gate (patch_generation purpose) — 2.1(b).
      2. RED: the original exploit on the UNPATCHED clone. If it does not
         reproduce, the pipeline refuses (no honest RED, no claim).
      3. patch: built from the strategy, applied to the clone source only.
      4. BLUE: the SAME exploit on the PATCHED clone, served by the
         CLIENT-PROVIDED staging restart hook (the client controls the
         staging lifecycle; without a hook the BLUE proof is impossible
         and the pipeline refuses rather than assuming the fix).
      5. the diff/PR bundle — for the CLIENT's own review system; this
         tool never merges or deploys anything (no such code exists).
    """
    try:
        assert_isolated(target_url, work_url,
                        allow_same_host_staging=allow_same_host_staging)
    except IsolationViolation as e:
        if not work_url:
            # 3.4: the explicit report-only fallback, not a silent skip
            return {"status": "refused-report-only",
                    "fallback": report_only_fallback(
                        finding, str(e))}
        raise
    gate.require("patch_generation", credential)

    try:
        red = probe(work_url, finding)
    except RemediationRefused as e:
        # unsupported class: refuse the stage entirely, fall back to the
        # Part-1 report-only guidance — never a best-effort guess
        return {"status": "refused-report-only",
                "fallback": report_only_fallback(finding, str(e))}
    if not red["exploitable"]:
        return {"status": "refused-no-red",
                "reason": ("the original exploit did NOT reproduce on the "
                           "unpatched clone — no honest RED, no patch "
                           "claim; refusing"),
                "probe": red}

    try:
        patch = build_patch(finding, clone_dir)
        apply_patch(patch, clone_dir)
        if restart_workload is None:
            raise RemediationRefused(
                "no staging restart hook provided — the BLUE proof needs "
                "the PATCHED clone served live; refusing to assume the "
                "patch works without observing the exploit fail")
        restart_workload(clone_dir)
    except RemediationRefused as e:
        return {"status": "refused-report-only",
                "fallback": report_only_fallback(finding, str(e))}

    blue = probe(work_url, finding)
    bundle = {
        "status": "proposed-and-proved" if not blue["exploitable"]
                  else "patch-did-not-prove",
        "finding_type": finding.get("type", ""),
        "target_url": target_url,
        "work_url": work_url,
        "red": red,
        "blue": blue,
        "patch": patch,
        "delivery": {
            "form": "pull-request-bundle",
            "diff": patch["diff"],
            "instructions": ("open a PR in the CLIENT's own repository / "
                             "review system with this diff; the client's "
                             "team reviews and merges it — this tool "
                             "never merges or deploys to client systems "
                             "(no such code path exists)"),
        },
    }
    return bundle

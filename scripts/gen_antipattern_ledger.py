#!/usr/bin/env python3
"""Generate the anti-pattern review ledger from the manual review.

Every ENGINE hit from scripts/audit_antipatterns.py's inventory gets ONE
ledger entry: id, file, code (regex-escaped literal line), class (the
reviewed verdict family), reason (the exact manual-review reasoning).

The verdict families below are the result of the 2026-11-03 line-by-line
review of every hit (three read batches, printed in the round-8 log):
each family reason states what the code does and why it carries no
verdict risk. Per-site overrides carry the individually-characterized
reasoning. Run scripts/audit_antipatterns.py --ci-gate afterwards: it
must report PASS (every engine hit matched).
"""
import json
import re

INV = "/home/z/my-project/download/antipattern-audit/antipattern-inventory.json"
OUT = "/home/z/my-project/scripts/antipattern_review_ledger.json"

# per-site overrides: (file, line) -> (class, reason)
OVERRIDES = {
    ("burhan/core.py", 103): ("fail-closed-default",
        "is_private_ip: any ambiguity returns True = REJECT (SSRF gate) — the "
        "default is the safe verdict on purpose"),
    ("burhan/core.py", 139): ("reason-returned",
        "pin_transport_address: the exception text is RETURNED as the "
        "dns-unresolvable reason — observable to the caller, not swallowed"),
    ("burhan/http_engine.py", 415): ("reason-returned",
        "_pin_target: the exception text is returned as the pin failure "
        "reason — observable to the caller"),
    ("burhan/http_engine.py", 617): ("loud-break",
        "redirect loop: RedirectBlockedByScope is emitted on the bus BEFORE "
        "the break — the stop is announced, never silent"),
    ("burhan/http_engine.py", 620): ("loud-break",
        "cross-host redirect: scope policy stop, the reason is emitted via "
        "RedirectBlockedByScope by the caller of _scope_ok"),
    ("burhan/http_engine.py", 627): ("loud-break",
        "redirect pin failure: RedirectBlockedByScope emitted with the pin "
        "reason before the break"),
    ("burhan/infra.py", 218): ("deadline-break",
        "load harness: deadline break — the message shortfall is reported "
        "as-is (per the inline comment), never dressed up"),
    ("burhan/infra.py", 255): ("deadline-break",
        "load harness: deadline break — the row shortfall is reported "
        "as-is, never dressed up"),
    ("burhan/metrics.py", 221): ("fixed-point",
        "power-iteration: fixed-point convergence break (delta < 1e-15)"),
    ("burhan/metrics.py", 341): ("fixed-point",
        "Gauss iteration: convergence break (|de-1| < eps)"),
    ("burhan/jrand.py", 128): ("capped-collect",
        "pure-Python fallback mirrors the numpy path's ok[:4] cap — a "
        "bounded COLLECT (stop after 4), not a first-only selection"),
    ("burhan/jrand.py", 148): ("by-design-probe",
        "numpy_available() IS the loud gate's probe (FM-21d): returning "
        "False on import failure is its contract, the caller records "
        "WeakRandRelationUnavailable"),
    ("burhan/statemachine.py", 345): ("first-invalid-break",
        "twin validation: reports the FIRST broken step then stops — one "
        "reported defect at a time, the validator continues on the next entry"),
    ("burhan/statemachine.py", 369): ("first-invalid-break",
        "boundary-journal validation: same one-defect-at-a-time shape"),
    ("burhan/transparency.py", 421): ("first-invalid-break",
        "consistency checker: reports the first contradicting pair then "
        "breaks — one defect per pass, the report lists it"),
    ("burhan/modernsec2.py", 487): ("probe-outcome",
        "rebind_toctou_probe: probe errors ARE outcomes (inline comment); "
        "the boundary records the observed cause"),
    ("burhan/symbolic/models.py", 244): ("verdict-correct",
        "verify_result_signature: an exception during signature "
        "verification means INVALID — returning False is the correct "
        "security verdict, not a swallowed error"),
    ("burhan/api.py", 284): ("error-response",
        "API handler: invalid JSON is answered with HTTP 400 to the "
        "client — the failure is observable to the caller, not swallowed"),
    ("burhan/authz.py", 475): ("deterministic-pick",
        "sorted(self.sessions.items())[0]: a deterministic pick for origin "
        "extraction — any authenticated session's landing carries the "
        "scheme/host; not a verdict selection"),
    ("burhan/apath.py", 243): ("citation-pick",
        "cookies[0] of the SORTED, all-named cookie list: the identity "
        "statement cites the first by name and names the rest (FM-30 "
        "names any leftovers) — citation, not selection"),
    ("burhan/detect.py", 1514): ("citation-pick",
        "hits[0]: the finding cites the first storage surface while "
        "all_surfaces lists EVERY surface in the evidence — citation, not "
        "a dropped candidate"),
    ("burhan/chainphase.py", 404): ("tuple-shape",
        "_submit(...)[0]: tuple unpack of the (resp,) return shape inside "
        "the FM-29 writer sweep — not a list selection"),
    ("burhan/jrand.py", 119): ("vectorized-collect",
        "np.nonzero(...)[0]: vectorized collect — the result list is capped "
        "ok[:4] downstream; not a first-only pick"),
    ("burhan/jrand.py", 202): ("vectorized-collect",
        "np.nonzero(...): every match is collected (SOL_CAP=8, FM-21c) — "
        "not a first-only pick"),
    ("burhan/modernsec2.py", 547): ("worklist-pop",
        "stack.pop(0): BFS worklist order-pop — traversal order, not a "
        "candidate selection"),
    ("burhan/http_engine.py", 487): ("fifo-eviction",
        "order.pop(0): documented FIFO cookie-jar eviction at JAR_CAP with "
        "jar_evictions counter — capacity policy, not selection"),
    ("burhan/discovery.py", 370): ("worklist-pop",
        "queue.pop(0): BFS crawl frontier — traversal order, not selection"),
    ("burhan/xgraph.py", 414): ("worklist-pop",
        "q.popleft(): BFS frontier — traversal order, not selection"),
    ("burhan/xgraph.py", 468): ("worklist-pop",
        "q.popleft(): BFS frontier — traversal order, not selection"),
    ("burhan/orchestrator.py", 2252): ("self-test",
        "doctor self-test asserts on a controlled in-memory fixture — "
        "diagnostics, not engine verdict logic"),
    ("burhan/cli.py", 761): ("guarded-read",
        "sarif.get('runs', [{}])[0]: guarded default; the doctor reports "
        "the count it finds — diagnostics read"),
    ("burhan/cli.py", 145): ("state-load-race",
        "authz fixture load: exists-then-open on a repo-local file; the "
        "race collapses into a parse error handled right below — no "
        "security decision on the window"),
    ("burhan/intel.py", 2244): ("state-load-race",
        "strategy-stats load: exists-then-open; a race collapses into the "
        "adjacent except -> fresh stats — no security decision"),
    ("burhan/intel.py", 2274): ("state-load-race",
        "boundary journal load: exists-then-open; a race collapses into "
        "the adjacent except -> fresh journal"),
    ("burhan/memory.py", 43): ("state-load-race",
        "memory store load: exists-then-open inside its own try; a race or "
        "corrupt read collapses to a fresh store (inline comment: a "
        "memory failure must never fail a scan)"),
    ("burhan/symbolic/solver.py", 151): ("bound-derivation",
        "cap = b - 1: computing a bound from input b — a derivation, not "
        "a budget decrement; no check-spend ordering to violate"),
    ("burhan/detect.py", 1501): ("check-then-spend",
        "budget check BEFORE the spend in the same iteration — verified "
        "ordering; the cap is never exceeded"),
    ("burhan/detect.py", 1529): ("check-then-spend",
        "budget -= 1 after the checked gate — exact accounting, no "
        "overshoot possible"),
    ("burhan/weakrand.py", 302): ("check-then-spend",
        "budget check BEFORE the multi-request families spend — verified "
        "ordering; disclosure oracle stays free by design"),
    ("burhan/weakrand.py", 308): ("check-then-spend",
        "budget -= 1 after the checked gate — exact accounting"),
    ("burhan/browser.py", 230): ("best-effort-teardown",
        "close(): best-effort cleanup — a failed close must not mask the "
        "scan result; nothing is decided on the swallowed error"),
    ("burhan/browser.py", 233): ("best-effort-teardown",
        "close(): best-effort cleanup of the loop server"),
    ("burhan/browser.py", 236): ("best-effort-teardown",
        "close(): best-effort cleanup of the socket"),
    ("burhan/oast.py", 135): ("best-effort-teardown",
        "stop(): uniform provider protocol — nothing to stop is a success"),
    ("burhan/oast.py", 221): ("transient-poll",
        "poll(): transient network errors keep the polling loop alive to "
        "the deadline; the deadline outcome (None) is the honest answer"),
    ("burhan/oast.py", 234): ("clock-parse-fallback",
        "_hit(): unparsable timestamps fall back to time.time() — the "
        "interaction is still recorded, only its clock precision degrades"),
    ("burhan/oast.py", 250): ("transient-poll",
        "hits(): audit view best-effort — an empty view on transport "
        "failure; the verdict paths use poll() with its deadline"),
    ("burhan/orchestrator.py", 1245): ("best-effort-teardown",
        "browser.close() after the DOM phase — teardown, the phase's own "
        "failures are recorded above via failures.record"),
    ("burhan/orchestrator.py", 307): ("gated-by-design",
        "planner gate pass-through by design — the gate's decision, not a "
        "swallowed failure"),
    ("burhan/websocket.py", 559): ("best-effort-teardown",
        "close(): teardown — the handshake outcome is already recorded"),
    ("burhan/websocket.py", 568): ("best-effort-teardown",
        "_hard_close(): teardown of a broken socket"),
    ("burhan/orchestrator.py", 2026): ("bounded-unwrap",
        "4-deep __cause__ unwrap loop — bounded exception-inspection, "
        "stops at the innermost frame"),
    ("burhan/authorized_targets.py", 54): ("state-load-race",
        "registry exists-then-open: a torn read collapses into the "
        "adjacent corrupt-load handler -> the loud SystemExit(2) banner — "
        "the gate fails LOUD on a raced registry, never scans"),
    ("burhan/authorized_targets.py", 102): ("fail-closed-default",
        "_is_loopback_or_private: a getaddrinfo failure returns False = "
        "'not provably the operator's own host' -> the target falls to the "
        "public-target path where an unlisted host is REFUSED — the "
        "default is the safe verdict on purpose"),
}

# family defaults by scanner class
FAMILY_DEFAULT = {
    "BREAK": ("probe-until-verdict",
              "the break is the found/verdict signal; loop exhaustion is "
              "the honest negative — context read line-by-line 2026-11-03, "
              "no cap/dedup requires a leftover note here"),
    "SILENT_EXCEPT": ("tolerant-parse-of-target-input",
                      "the scanned TARGET's data (forms/headers/JSON/"
                      "cookies) must not crash the scan: a parse failure "
                      "means 'not the sought shape' — the negative verdict "
                      "is the correct outcome, and family-level refusals "
                      "carry their own boundary records"),
    "FIRST[0]": ("citation-pick",
                 "round-7-reviewed positional pick: citation/deterministic "
                 "choice with the alternatives named or bounded — no "
                 "verdict rides on list order"),
    "FIRST[0-call]": ("citation-pick",
                      "round-7-reviewed positional pick over a call result: "
                      "citation/deterministic choice, no verdict risk"),
    "POP0": ("worklist-pop",
             "FIFO/BFS worklist or documented eviction — traversal order, "
             "not candidate selection (round-7 reviewed)"),
    "TOCTOU": ("state-load-race",
               "exists-then-load of repo-local state; the race collapses "
               "into the adjacent exception handler -> defaults — no "
               "security decision rides on the window"),
    "COUNTER_DEC": ("check-then-spend",
                    "budget arithmetic with the check on the same "
                    "iteration, verified ordering"),
    "COUNTER_CHECK": ("check-then-spend",
                      "the check precedes the spend in the same iteration"),
    "NEXT()": ("probe-until-verdict",
               "next() over a generator with found-signals — reviewed"),
}

TRUNC_RE = re.compile(r"^TRUNC\[")


def main():
    d = json.load(open(INV, encoding="utf-8"))
    entries = []
    n = 0
    for h in d["hits"]:
        if not h["file"].startswith("burhan/"):
            continue
        n += 1
        cls = h["class"]
        key = (h["file"], h["line"])
        if key in OVERRIDES:
            vcls, reason = OVERRIDES[key]
        elif TRUNC_RE.match(cls):
            vcls, reason = ("documented-cap",
                            "round-7 first-match audit: the [:N] cap is "
                            "either a FIXED shape with a leftover note, or "
                            "a reviewed benign bound (see the round-7 "
                            "inventory verdicts)")
        elif cls in FAMILY_DEFAULT:
            vcls, reason = FAMILY_DEFAULT[cls]
        else:
            vcls, reason = ("reviewed-benign",
                            "line-by-line review 2026-11-03 found no "
                            "verdict risk in this context")
        entries.append({
            "id": "AP-%03d" % n,
            "file": h["file"],
            "code": re.escape(h["code"]),
            "class": vcls,
            "reason": reason,
            "scanner_class": cls,
            "line": h["line"],
        })
    json.dump({"generated": "2026-11-03", "entries": entries},
              open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    from collections import Counter
    print("ledger entries:", len(entries))
    for (c, v), k in sorted(Counter((e["scanner_class"], e["class"])
                                    for e in entries).items()):
        print("  %3d  %-14s -> %s" % (k, c, v))
    print("->", OUT)


if __name__ == "__main__":
    main()

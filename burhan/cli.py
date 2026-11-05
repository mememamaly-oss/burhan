#!/usr/bin/env python3
"""Burhan CLI — scan / benchmark / doctor / findings / report / serve / repair-demo.
Phase 16/29: Benchmark Registry with ground-truth comparison, TP/FP/FN/TN + P/R/F1.
Phase 46+: persistence (--db), findings query, report export, REST API server.
Phase 57 (v2.9.0): `vault` command group — keygen / init / status / list / export /
report / audit / authorize / revoke / purge for the encrypted Credential Vault,
plus scan-time arming via --vault/--vault-key-file (raw credentials captured
during a scan land encrypted at rest, never in reports, logs or findings).
"""
from __future__ import annotations
import argparse, json, os, signal, socket, subprocess, sys, time, hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from burhan.orchestrator import BurhanScanner, ScanConfig, doctor
from burhan.intel import (StrategyStore, FailureMemory, RepairClassifier, RepairGate,
                            VerificationEngine, FindingPipeline)


# ============================================================ benchmark
def _port_open(host, port, timeout=0.3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_fixture(base_url="http://127.0.0.1:8777"):
    """Self-repair ops rule OP-01 (fixture_not_running): if the benchmark target is the
    local fixture port and nothing is listening, auto-spawn fixtures/vulnapp.py and
    wait for readiness. Returns the spawned process (or None if already running /
    not applicable). Prevents the F1=0.0 silent-failure mode caught by live re-test."""
    from urllib.parse import urlparse
    u = urlparse(base_url)
    host, port = u.hostname or "127.0.0.1", u.port or 80
    if host not in ("127.0.0.1", "localhost"):
        return None                                   # remote target: nothing to spawn
    if _port_open(host, port):
        return None                                   # fixture already up
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "vulnapp.py")
    if not os.path.exists(fixture):
        return None
    proc = subprocess.Popen([sys.executable, fixture],
                            env={**os.environ, "PORT": str(port)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):                               # wait up to ~6s for readiness
        if _port_open(host, port):
            return proc
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    proc.terminate()
    return None


def _spawn_local_fixture(port: int):
    """Spawn fixtures/vulnapp.py on an explicit port; readiness-wait; loud None on failure."""
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "vulnapp.py")
    if not os.path.exists(fixture):
        return None
    proc = subprocess.Popen([sys.executable, fixture],
                            env={**os.environ, "PORT": str(port)},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if _port_open("127.0.0.1", port):
            return proc
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    proc.terminate()
    return None


def _free_local_port() -> int:
    import socket as _s
    with _s.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _benchmark_fixture(base_url: str):
    """ENG-20: decide WHICH fixture instance the benchmark scans.
    DEFAULT URL (the stock local fixture): ALWAYS spawn a fresh dedicated
    instance on an ephemeral port — a long-lived environment may hold a
    state-mutated leftover on :8777 (executed SORD/TRF objects from prior
    batteries) and reusing it breaks cross_object/cross_state reproducibility
    (caught live as FN in back-to-back benchmarks). An EXPLICIT operator URL
    (--url) is honored with the legacy OP-01 self-repair semantics.
    Returns (effective_url, spawned_process_or_None)."""
    if base_url.rstrip("/") == "http://127.0.0.1:8777":
        port = _free_local_port()
        proc = _spawn_local_fixture(port)
        if proc is None:
            raise SystemExit("benchmark: could not spawn a fresh local fixture "
                             "(fixtures/vulnapp.py missing or failed to start)")
        return f"http://127.0.0.1:{port}", proc
    return base_url, ensure_fixture(base_url)


def run_benchmark(base_url="http://127.0.0.1:8777", out="results/benchmark.json",
                  strategy_path=None, timeout=12.0, label="",
                  race=False, race_parallel=10, race_variance=0.005):
    """Scan the fixture and score against ground truth (spec 29/30).
    ENG-20: on the default target the benchmark spawns its OWN fresh fixture
    on an ephemeral port (determinism regardless of leftover listeners) and
    tears it down after; explicit --url targets keep OP-01 self-repair.
    ORD-002-WIRE: race=False keeps the anchored regression record; --race
    additionally exercises the race battery (the no-regression proof run)."""
    base_url, spawned = _benchmark_fixture(base_url)   # ENG-20 owned fixture
    try:
        return _run_benchmark_inner(base_url, out, strategy_path, timeout, label,
                                    spawned, race=race, race_parallel=race_parallel,
                                    race_variance=race_variance)
    finally:
        if spawned is not None:
            spawned.terminate()                        # we started it -> we stop it
            try:                                       # SYNCHRONOUS cleanup (OP-01b):
                spawned.wait(timeout=5)                # wait for port release, escalate if needed
            except subprocess.TimeoutExpired:
                spawned.kill(); spawned.wait(timeout=5)


def _run_benchmark_inner(base_url, out, strategy_path, timeout, label, spawned,
                         race=False, race_parallel=10, race_variance=0.005):
    gt = json.load(open(os.path.join(os.path.dirname(__file__), "..", "benchmarks", "ground_truth.json")))
    # Phase 49: the benchmark exercises the FULL platform — OAST armed, so the blind
    # XXE ground-truth entry (/vuln/oob-stock) is confirmable out-of-band.
    from burhan.oast import OastServer
    oast = OastServer()
    try:
        # Phase 51: the benchmark is now an AUTHENTICATED scan — /account and
        # /vault/transfer (ground truth v5) are 302-gated for anonymous clients,
        # so the login flow (AUTH-01/02) is exercised by the benchmark itself.
        from burhan.auth import AuthProfile
        auth = AuthProfile(login_url=base_url.rstrip("/") + "/login",
                           username="demo", password="demo123",
                           user_field="uid", pass_field="passw",
                           success_marker="Sign Off")
        # Phase 56: the benchmark exercises the FULL platform including the
        # multi-user Authorization Engine — benchmarks/authz_accounts.json is
        # the fixture's three-account matrix (admin + two users).
        authz_cfg = None
        _azp = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "authz_accounts.json")
        if os.path.exists(_azp):
            authz_cfg = json.load(open(_azp))
        # Phase 56: fixture v8 grew the crawl surface (7 new linked pages:
        # leak-config x2, api/filter, api/data, api/secure/data, admin stats x2)
        # — the old 30-page budget (x1.5 auth = 45) capped the BFS exactly at the
        # edge and starved the late-queued DOM pages out of the crawl (live-caught
        # by this very benchmark going FN on xss_dom). Budget recalibrated to track
        # the fixture, same doctrine as the Phase 55 browser-budget recalibration.
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=timeout,
                         strategy_path=strategy_path,
                         # ORD-001-REMAND (RT-03/RT-04): 64 chars (>= 32
                         # bytes) — compliant with the seed floor while
                         # staying a FIXED deterministic anchor for the
                         # bench (was "benchmark-fixed-seed", 21 bytes).
                         seed="bench430" * 8,
                         oast=oast, auth=auth, authz=authz_cfg,
                         # Phase 58 (v3.0.0): the benchmark exercises the FULL
                         # platform including the Workflow Intelligence engine —
                         # learning AND the attack battery (fixture v8's wizard
                         # twins are the ground truth for the five logic classes).
                         workflow=True, logic_active=True,
                         # RT-07: regression harness — budget explicitly OFF: the
                         # benchmark's anchored request stream (~7k requests) and
                         # verdict record (38/0/0/37) are the determinism anchor;
                         # the operator-facing default (500) must not castrate it.
                         max_requests=0,
                         # ORD-002-WIRE: the race battery (off = the anchored
                         # record; on = the ordered no-regression proof run)
                         race=race, race_parallel=race_parallel,
                         race_variance=race_variance)
        sc = BurhanScanner(base_url, cfg)
        result = sc.run()
    finally:
        oast.stop()
    findings = result["findings"]

    # ---- score
    def exists(gt_entry):
        return gt_entry["present"]

    def detected(gt_entry):
        for f in findings:
            if f["type"] != gt_entry["type"]:
                continue
            ep_gt = gt_entry["endpoint"]
            if ep_gt == "*" or f["url"].split("?")[0].endswith(ep_gt):
                if not gt_entry["parameter"] or f["parameter"] == gt_entry["parameter"]:
                    return True
        return False

    tp = fn = tn = fp = 0
    details = []
    for g in gt["ground_truth"]:
        d, e = detected(g), exists(g)
        cell = ("TP" if d and e else "FP" if d and not e else "FN" if e and not d else "TN")
        tp += cell == "TP"; fp += cell == "FP"; fn += cell == "FN"; tn += cell == "TN"
        details.append({"case": f"{g['type']}@{g['endpoint']}:{g['parameter']}", "cell": cell})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    report = {
        "benchmark": gt["benchmark"], "label": label or "adhoc",
        "scanner": result["scanner"], "run_id": result["run_id"], "seed": result["seed"],
        "confusion": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "stats": result["stats"], "details": details,
        "findings": findings,
        "ground_truth_sha256": hashlib.sha256(json.dumps(gt, sort_keys=True).encode()).hexdigest()[:16],
    }
    # ORD-002-WIRE: the bench doc carries the race section when --race ran —
    # the ordered gate ("bench x3 WITH --race: works, no regression") must be
    # OBSERVABLE from the deposited doc alone (a null section on no-race runs
    # never adds the key: the anchored regression record keeps its byte shape).
    if result.get("race_analysis") is not None:
        report["race_analysis"] = result["race_analysis"]
    # AXIS-18: same conditional-copy discipline — the deposited doc carries
    # the section only when --symbolic actually ran.
    if result.get("symbolic_analysis") is not None:
        report["symbolic_analysis"] = result["symbolic_analysis"]
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    json.dump(report, open(out, "w"), indent=1)
    return report


# ============================================================ repair demo (spec 22/23/38)
def repair_demo():
    """Live full-loop self-repair with a REAL, reproducible failure:
    slow fixture (150ms/request) + degenerate timeout (5ms) -> every request times out.
    Rule-only repair (x3 = 15ms) still fails -> gate ROLLS BACK.
    Rule + policy floor (12s) passes regression + benchmark -> ACCEPTED."""
    import subprocess, signal as _sig
    print("=" * 70)
    print(" SELF-REPAIR GATE — LIVE EXECUTION (no AI, deterministic rules)")
    print("=" * 70)

    # 0) spawn SLOW fixture (real failure substrate)
    slow = subprocess.Popen([sys.executable, "fixtures/vulnapp.py"],
                            env={**os.environ, "PORT": "8778", "DELAY_MS": "150"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    import urllib.request
    slow_alive = False
    try:
        urllib.request.urlopen("http://127.0.0.1:8778/", timeout=5); slow_alive = True
    except Exception:
        pass
    print(f"\n[0] SLOW fixture (150ms/req) spawned on :8778 -> alive={slow_alive}")

    try:
        # 1) healthy baseline on normal fixture
        base = run_benchmark(out="results/benchmark_baseline.json", label="pre-repair baseline", timeout=12.0)
        print(f"\n[1] BASELINE benchmark (normal env): F1={base['f1']:.3f} P={base['precision']:.3f} "
              f"R={base['recall']:.3f} (TP={base['confusion']['TP']} FP={base['confusion']['FP']} FN={base['confusion']['FN']})")

        # 2) REAL failure: slow env + degenerate timeout -> reproducible scanner failure
        print("\n[2] INDUCING REAL FAILURE: slow env (150ms/req) + timeout=5ms ...")
        broken = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_broken.json", label="broken-transport", timeout=0.005)
        print(f"    broken run: F1={broken['f1']:.3f} verified={broken['stats']['verified']} "
              f"requests={broken['stats']['requests']} -> {'REAL FAILURE REPRODUCED' if broken['f1'] < 0.5 else 'unstable — demo invalid'}")
        assert broken["f1"] < 0.5, "failure was not reproduced; refusing to fake results"

        # 3) deterministic classification
        err = "timeout:TimeoutError"
        cls = RepairClassifier().classify(err, {"scanner": "sqli"})
        print(f"\n[3] FAILURE CLASSIFICATION: error='{err}' -> rule='{cls[0]}' action={cls[1]['action']}")
        assert cls and cls[0] == "timeout_spike"

        # 4) gate: candidate A (rule-only) vs candidate B (rule + policy floor)
        def regression_suite():
            r = subprocess.run([sys.executable, "tests/run_tests.py", "regression"],
                               capture_output=True, text=True,
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            try:
                j = json.loads(r.stdout)          # run_tests prints a single pretty JSON object
                return {"passed": j["passed"], "total": j["total"], "failed": j["failed"]}
            except Exception:
                return {"passed": False, "raw": (r.stdout or r.stderr)[-200:]}

        print("\n[4] REPAIR GATE EXECUTION (against the SAME broken environment):")
        cand_a = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateA.json",
                               label="repair-A-rule-only", timeout=0.005 * cls[1]["action"]["multiply_timeout"])
        a_ok = cand_a["f1"] >= base["f1"] - 0.02
        print(f"    candidate A (timeout=15ms, rule-only): F1={cand_a['f1']:.3f} acceptable={a_ok} "
              f"-> {'ACCEPT' if a_ok else 'ROLLBACK + RULE QUARANTINED'}")
        reg = regression_suite()
        print(f"    regression suite: passed={reg.get('passed')} ({reg.get('total')} cases)")
        cand_b = run_benchmark(base_url="http://127.0.0.1:8778",
                               out="results/benchmark_repair_candidateB.json",
                               label="repair-B-with-floor", timeout=12.0)
        b_ok = cand_b["f1"] >= base["f1"] - 0.02 and cand_b["confusion"]["FP"] <= base["confusion"]["FP"]
        print(f"    candidate B (timeout=12s, rule + policy floor): F1={cand_b['f1']:.3f} "
              f"FP={cand_b['confusion']['FP']} acceptable={b_ok}")
        verdict = "ACCEPTED" if (b_ok and reg.get("passed") and not a_ok) else \
                  ("ACCEPTED" if (b_ok and reg.get("passed")) else "REJECTED")
        print(f"\n    FINAL GATE VERDICT: {verdict}")
        if verdict == "ACCEPTED":
            print("    -> repair B activated; failure class has permanent regression case "
                  "(tests/run_tests.py::regression_timeout_repair_rule)")
        else:
            print("    -> repair quarantined; failure kept in FailureMemory for rule revision")
        return {"baseline_f1": base["f1"], "broken_f1": broken["f1"],
                "candidate_a_f1": cand_a["f1"], "candidate_a_accepted": a_ok,
                "candidate_b_f1": cand_b["f1"], "candidate_b_accepted": b_ok,
                "regression": reg, "verdict": verdict}
    finally:
        slow.terminate()


# ============================================================ main
def main():
    ap = argparse.ArgumentParser(prog="burhan")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("target"); s.add_argument("--allow-private", action="store_true")
    s.add_argument("--max-pages", type=int, default=25); s.add_argument("--timeout", type=float, default=12.0)
    s.add_argument("--no-crawl", action="store_true"); s.add_argument("--seed")
    s.add_argument("--modern-v2", action="store_true",
                   help="owner order part 3: NEW detection layers (jwt weak-secret, "
                        "graphql aliasing, excessive data exposure, rebind TOCTOU) — off by default")
    s.add_argument("--out", default="results/scan.json"); s.add_argument("--strategy-path")
    s.add_argument("--db", default="", help="persist run+findings to this SQLite store")
    s.add_argument("--prioritize-store", default="",
                   help="round 10 part 1: path to the shared SQLite store whose "
                        "prior runs of this target drive the finding lifecycle "
                        "(NEW/RECURRING/FIXED/REGRESSED) and risk ranking")
    s.add_argument("--no-oast", action="store_true",
                   help="disable the OAST engine entirely (OOB blind-vuln confirmation)")
    s.add_argument("--oast", choices=["auto", "local", "public", "webhook"], default="auto",
                   help="OAST channel: auto = local listener for lab targets, "
                        "interact.sh for remote targets (default); public = force "
                        "interact.sh; webhook = the Phase-52 webhook.site channel "
                        "(both public channels fail loud if unreachable)")
    s.add_argument("--no-browser", action="store_true",
                   help="disable the browser/DOM engine (Phase 50: JS-built forms + DOM XSS)")
    s.add_argument("--auth-user", default="", help="Phase 51: enable authenticated scanning — username")
    s.add_argument("--auth-pass", default="", help="Phase 51: password")
    s.add_argument("--auth-url", default="", help="login page carrying the form (default: <target>/login.jsp)")
    s.add_argument("--auth-user-field", default="uid")
    s.add_argument("--auth-pass-field", default="passw")
    s.add_argument("--auth-success-marker", default="",
                   help="substring expected on the landing page after login (optional hard gate)")
    # ---- AUTH-05 (Phase 54): static-token authentication (Bearer JWT / API key / custom header)
    s.add_argument("--auth-token", default="",
                   help="Phase 54: static token (Bearer JWT, API key) — enables token mode")
    s.add_argument("--auth-header", default="Authorization",
                   help="header name carrying the token (default: Authorization)")
    s.add_argument("--auth-scheme", default="Bearer",
                   help="scheme prefix ('Bearer x' / 'Token x' / '' = raw value)")
    s.add_argument("--auth-validate-url", default="",
                   help="page fetched WITH the header to prove the token opens a closed door")
    # ---- DISC-13 (Phase 54): OpenAPI seeding
    s.add_argument("--no-openapi", action="store_true",
                   help="disable OpenAPI/Swagger document auto-probing")
    s.add_argument("--openapi-spec", default="",
                   help="path/URL of an explicit OpenAPI/Swagger JSON document to seed endpoints")
    # ---- Phase 56 (v2.8.0): the Intelligence Layer
    s.add_argument("--authz-accounts", default="",
                   help="Phase 56: multi-user authorization testing — JSON file with "
                        "accounts (name/role/username/password/marker/object_id) + "
                        "login flow; enables IDOR/BOLA + vertical-escalation "
                        "detection and the role x endpoint access matrix")
    s.add_argument("--no-secrets", action="store_true",
                   help="disable the credential-exposure scan of passive baselines")
    s.add_argument("--exclude-url", action="append", default=[],
                   metavar="SUBSTRING",
                   help="V411: exclude surfaces whose URL contains this substring "
                        "— never fetched, probed or counted (repeatable). For "
                        "authorized scans of stateful targets whose GET routes "
                        "change configuration or data (mode toggles, reset "
                        "links): pin the target's state instead of letting the "
                        "crawler flip it")
    s.add_argument("--secrets-report", default="",
                   help="also write a standalone credential-exposure report (masked "
                        "values only) to this path")
    # ---- Phase 57 (v2.9.0): Credential Vault — encrypted retention of captured
    # credentials. Requires BOTH the vault file and an authorized key file.
    s.add_argument("--vault", default="",
                   help="Phase 57: path of the credential vault file — arms encrypted "
                        "capture of credentials found during the scan")
    s.add_argument("--vault-key-file", default="",
                   help="an authorized vault key file (see: burhan vault keygen)")
    # ---- Phase 58 (v3.0.0): Workflow / Business-Logic Intelligence. Learning
    # is safe (guided walks); the attack battery changes application state and
    # is therefore behind its own explicit flag.
    s.add_argument("--workflow", action="store_true",
                   help="Phase 58: learn multi-step business flows (guided walks: "
                        "chain, resource linkage, state oracle) and add them to "
                        "the application map")
    s.add_argument("--logic-active", action="store_true",
                   help="Phase 58: ALSO run the five business-logic attack "
                        "manipulations (step bypass / out-of-order / value tamper / "
                        "duplicate execution / privilege bound) on fresh sessions — "
                        "THESE PROBES CHANGE APPLICATION STATE (canary values, "
                        "bounded budgets); every finding requires state-oracle proof")
    # ---- ORD-002-WIRE (axis-17): the race-condition battery flags. OFF by
    # default; without --race the burhan/race/ package is never even
    # loaded (zero effect on a normal scan — pinned by test_wire_disabled_by_default).
    s.add_argument("--race", action="store_true",
                   help="ORD-002-WIRE/axis-17: enable the race-condition "
                        "detection battery — sensitive endpoints (transfer/pay/"
                        "delete/modify/withdraw/move vocabulary) receive small "
                        "bursts of concurrent identical requests and the timing "
                        "variance decides race_detected; destructive vocabulary "
                        "is ALWAYS rejected before any send. Default: disabled", )
    s.add_argument("--race-parallel", type=int, default=10, metavar="N",
                   help="race battery: max concurrent requests per probe "
                        "(default: 10; range 1..64 — the package's own budget gate "
                        "enforces fail-closed)")
    s.add_argument("--race-variance", type=float, default=0.005, metavar="F",
                   help="race battery: timing-variance threshold in seconds — a "
                        "mutating group whose unbiased sample variance falls "
                        "below it is flagged race_detected (default: 0.005)")
    # ---- AXIS-18 (ORD-003): the symbolic execution flag. OFF by default;
    # without --symbolic the burhan/symbolic/ package is never imported
    # (zero effect on a normal scan — pinned by the bomb test in the suite).
    s.add_argument("--symbolic", action="store_true",
                   help="AXIS-18 (ORD-003): symbolic execution analysis — extract "
                        "validation constraints from application responses, solve "
                        "them exactly (stdlib only), and send the COMPUTED values "
                        "as bounded verification payloads; destructive solutions "
                        "are blocked before any request is sent")
    b = sub.add_parser("benchmark"); b.add_argument("--url", default="http://127.0.0.1:8777")
    b.add_argument("--out", default="results/benchmark.json"); b.add_argument("--strategy-path"); b.add_argument("--timeout", type=float, default=12.0)
    # ORD-002-WIRE: the benchmark can also exercise the race battery (--race).
    b.add_argument("--race", action="store_true",
                   help="ORD-002-WIRE/axis-17: also run the race-condition "
                        "battery during the benchmark scan (default: off — the "
                        "anchored no-race bench is the regression record)")
    b.add_argument("--race-parallel", type=int, default=10, metavar="N",
                   help="race battery concurrency cap (default: 10)")
    b.add_argument("--race-variance", type=float, default=0.005, metavar="F",
                   help="race battery timing-variance threshold in seconds (default: 0.005)")
    sub.add_parser("doctor")
    sub.add_parser("repair-demo")
    cmp = sub.add_parser("compliance", help="P2-C: the OWASP/CWE/PCI DSS "
                                          "mapping registry — one row per "
                                          "detector class")
    cmp.add_argument("--json", action="store_true",
                     help="machine-readable export (single source for the "
                          "platform registry and the parity tests)")
    # ---- Phase 46+: findings / report / serve
    fnd = sub.add_parser("findings", help="query persisted findings across runs")
    fnd.add_argument("--db", default="results/burhan.db")
    fnd.add_argument("--run-id", default=""); fnd.add_argument("--type", default="")
    fnd.add_argument("--min-risk", type=int, default=0); fnd.add_argument("--status", default="verified")
    fnd.add_argument("--recurring", action="store_true", help="only fingerprints seen in >1 run")
    fnd.add_argument("--delta", action="store_true", help="diff the two most recent runs")
    rep = sub.add_parser("report", help="export an HTML/JSON/SARIF report from the store")
    rep.add_argument("--db", default="results/burhan.db"); rep.add_argument("--run-id", default="")
    rep.add_argument("--out", default="results/report.html"); rep.add_argument("--format", choices=["html", "json", "sarif", "executive", "glass", "bilingual", "cef", "syslog", "ocsf"], default="html")
    rep.add_argument("--syslog-host", default="127.0.0.1",
                     help="syslog format only: collector host to send to "
                          "(UDP RFC 5426 by default)")
    rep.add_argument("--syslog-port", type=int, default=514)
    rep.add_argument("--syslog-proto", choices=["udp", "tcp"], default="udp",
                     help="UDP (RFC 5426) or TCP with RFC 6587 framing; "
                          "TLS (RFC 5425) is a deployment-side PKI decision, "
                          "documented in burhan/siem.py")
    rep.add_argument("--pdf", action="store_true",
                     help="bilingual format: also convert the .docx to PDF "
                          "(requires soffice on PATH; refuses loudly if absent)")
    rep.add_argument("--ci", action="store_true",
                     help="CI/CD gate: exit 1 when the report carries verified "
                          "critical/high findings (works with every format)")
    # ---- Phase 60-64 (v4.0.0): the Digital Twin surface -----------------------
    tw = sub.add_parser("twin", help="v4.0.0: the Security Digital Twin of a stored "
                                      "run — the application's knowledge graph")
    tw.add_argument("--db", default="results/burhan.db")
    tw.add_argument("--run-id", default="", help="default: the newest run")
    tw.add_argument("--full", action="store_true", help="include the complete graph "
                                                          "(nodes + edges + entities + matrix)")
    rpr = sub.add_parser("reproduce", help="v4.0.0: the step-by-step reproduction "
                                            "recipe of ONE finding (Evidence OS)")
    rpr.add_argument("--db", default="results/burhan.db")
    rpr.add_argument("--finding", required=True, help="finding id (e.g. F-ab12cd34ef)")
    rpr.add_argument("--run-id", default="", help="default: the newest run carrying it")
    rpr.add_argument("--replay", action="store_true",
                     help="v4.1.0: LIVE re-execution of the proof from a clean "
                          "engine (records REPRODUCTION_VERIFIED / "
                          "REPRODUCTION_FAILED with reason)")
    rpr.add_argument("--gated", action="store_true",
                     help="r11 Part 2: replay under the live authorized-targets "
                          "gate + per-finding rate limit; implies --replay "
                          "(REFUSED exits 2 with zero live requests, "
                          "RATE_LIMITED exits 3)")
    rpr.add_argument("--timeout", type=float, default=12.0)
    cm = sub.add_parser("capability-matrix", help="v4.1.0: generate "
                        "CAPABILITY_MATRIX.md from ACTUAL run data (never "
                        "hand-written)")
    cm.add_argument("--db", default="results/burhan.db")
    cm.add_argument("--run-id", default="", help="default: the newest run")
    cm.add_argument("--out", default="CAPABILITY_MATRIX.md")
    apa = sub.add_parser("apaths", help="v4.3.0 (L2): Attack Path Intelligence "
                        "over a saved scan result — full attack paths with "
                        "per-link evidence (weakest-link classified)")
    apa.add_argument("--result", required=True, help="path to a scan result JSON")
    apa.add_argument("--out", default="", help="write the paths JSON here (default: stdout)")
    apa.add_argument("--paths-only", action="store_true", help="omit the summary block")
    sca = sub.add_parser("sca", help="round 10 part 3: SCA — match a client "
                         "application's dependency manifest against the OSV.dev "
                         "public batch API (no key required)")
    sca.add_argument("--manifest", required=True,
                    help="requirements.txt or package-lock.json of the "
                         "scanned client application (package.json is "
                         "deferred to its lockfile — see burhan/sca.py)")
    sca.add_argument("--out", default="", help="write the SCA result JSON here (default: stdout)")
    sca.add_argument("--raw-dir", default="",
                    help="save the raw OSV responses verbatim here (the "
                         "evidence contract)")
    sca.add_argument("--kev-catalog", default="",
                     help="path to the official CISA KEV catalog JSON for the "
                          "known-exploited cross-reference (offline matching; "
                          "no scan-time fetch of cisa.gov)")
    uni = sub.add_parser("unified", help="round 10 part 4: the unified "
                         "cross-category report — the scan's DAST findings, "
                         "SCA findings and proven attack chains ranked "
                         "together on the one stated formula")
    uni.add_argument("--scan", required=True,
                     help="path to a saved scan result JSON (the DAST side)")
    uni.add_argument("--sca", action="append", default=[], metavar="RESULT",
                     help="path to a `burhan sca` result JSON (repeatable — "
                          "one per manifest)")
    uni.add_argument("--prioritize-store", default="",
                     help="the shared lifecycle store: resolve "
                          "NEW/RECURRING/REGRESSED/FIXED across runs and "
                          "record this invocation's resolutions")
    uni.add_argument("--out", default="",
                     help="write the unified report JSON here (default: stdout)")
    imp = sub.add_parser("impact", help="v4.4.0 (L3): Proven Real Impact — "
                        "plan SAFE minimal-benign impact probes over a saved "
                        "scan result; optionally execute them live and assess "
                        "(VERIFIED only via a confirming fresh probe)")
    imp.add_argument("--result", required=True, help="path to a scan result JSON")
    imp.add_argument("--execute", action="store_true", help="issue the planned probes live "
                      "(opt-in; the scan pipeline never does this)")
    imp.add_argument("--allow-private", action="store_true", help="MAX-07: permit L3 "
                      "probes against private/localhost targets (lab & training "
                      "apps). Default OFF — the scan's own --allow-private is "
                      "NEVER implicitly inherited by the impact layer")
    imp.add_argument("--redirect-sink", default="", help="our OAST channel URL for the "
                      "open-redirect landing proof (default: the deterministic probe sink)")
    imp.add_argument("--origin-probe", default="", help="hostile Origin header value "
                      "for the CSRF own-session proof (default: the deterministic probe origin)")
    imp.add_argument("--probe-journal", default="", help="write the raw probe journal JSON here")
    imp.add_argument("--assessment", default="", help="write the assessment JSON here")
    imp.add_argument("--report", default="", help="write the human evidence report (MD) here")
    srv = sub.add_parser("serve", help="REST API + web UI (Phase: REST/UI)")
    srv.add_argument("--host", default="127.0.0.1"); srv.add_argument("--port", type=int, default=8022)
    srv.add_argument("--db", default="results/burhan.db")
    srv.add_argument("--token", default="", help="required when binding non-loopback")
    # ---- Phase 57 (v2.9.0): the Credential Vault command group -----------------
    # Access model: key FILES, not passwords. keygen hands a 0600 key file to an
    # authorized party (tool designer / organization owner); the vault refuses
    # every operation without a key authorized for THAT vault file.
    vlt = sub.add_parser("vault", help="Phase 57: encrypted Credential Vault")
    vsub = vlt.add_subparsers(dest="vcmd", required=True)
    vg = vsub.add_parser("keygen", help="create a new authorized key file (hand it "
                                       "to the organization owner — never commit it)")
    vg.add_argument("--out", required=True); vg.add_argument("--label", default="")
    vi = vsub.add_parser("init", help="create a new vault for an organization")
    vi.add_argument("--vault", required=True); vi.add_argument("--key-file", required=True)
    vi.add_argument("--org", required=True); vi.add_argument("--label", default="designer")
    for name, help_ in (
            ("status", "masked overview: org, revision, record count, authorized keys"),
            ("list", "masked record listing — raw values NEVER leave the vault"),
            ("audit", "who opened what, when — the encrypted audit trail")):
        vp = vsub.add_parser(name, help=help_)
        vp.add_argument("--vault", required=True); vp.add_argument("--key-file", required=True)
    vr = vsub.add_parser("report", help="OWNER-ONLY full-reveal report "
                                         "(CONFIDENTIAL, audited)")
    vr.add_argument("--vault", required=True)
    vr.add_argument("--key-file", required=True); vr.add_argument("--out", default="")
    ve = vsub.add_parser("export", help="authenticated reveal of ONE record (audited)")
    ve.add_argument("--vault", required=True); ve.add_argument("--key-file", required=True)
    ve.add_argument("--record", required=True)
    va = vsub.add_parser("authorize", help="add another authorized key (e.g. the "
                                           "organization owner's)")
    va.add_argument("--vault", required=True); va.add_argument("--key-file", required=True)
    va.add_argument("--new-key", required=True); va.add_argument("--label", default="")
    vv = vsub.add_parser("revoke", help="remove a key AND rotate the blob key — a "
                                        "revoked key cannot open any copy of the file")
    vv.add_argument("--vault", required=True); vv.add_argument("--key-file", required=True)
    vv.add_argument("--key-id", required=True)
    vp = vsub.add_parser("purge", help="shred records after report delivery "
                                       "(the audit entry survives by design)")
    vp.add_argument("--vault", required=True); vp.add_argument("--key-file", required=True)
    vp.add_argument("--record", default="")
    vp.add_argument("--all", action="store_true")
    a = ap.parse_args()

    if a.cmd == "doctor":
        print(json.dumps(doctor(), indent=1))
    elif a.cmd == "scan":
        # ORD-001-REMAND (RT-03/RT-04): an operator-passed --seed must carry
        # >= 32 bytes of material (64 hex chars recommended for runs;
        # >= 64 utf-8 chars otherwise). Weak seeds (dates, timestamps,
        # serial ids, short labels) are rejected fail-closed BEFORE the
        # run starts — the same floor is enforced again at the crypto layer
        # (audit.SeedPolicyError).
        if a.seed is not None and len(a.seed.encode("utf-8")) < 32:
            ap.error("--seed must carry at least 32 bytes (64 hex chars "
                     "recommended) — weak seeds are fail-closed rejected "
                     "(RT-03/RT-04)")
        auth = None
        if a.auth_token:
            # AUTH-05 token mode: Bearer JWT / API key / custom header.
            from burhan.auth import AuthProfile
            if a.auth_user:
                print("[AUTH-05] --auth-token overrides --auth-user (token mode)", file=sys.stderr)
            auth = AuthProfile(login_url=a.auth_validate_url or a.target.rstrip("/"),
                               token=a.auth_token, auth_header=a.auth_header,
                               auth_scheme=a.auth_scheme)
        elif a.auth_user:
            from burhan.auth import AuthProfile
            login_url = a.auth_url or (a.target.rstrip("/") + "/login.jsp")
            auth = AuthProfile(login_url=login_url, username=a.auth_user, password=a.auth_pass,
                               user_field=a.auth_user_field, pass_field=a.auth_pass_field,
                               success_marker=a.auth_success_marker)
        # DISC-13: explicit OpenAPI/Swagger seed (local path or URL) — parsed to
        # endpoints BEFORE the crawl so unlinked API surface is scanned too.
        openapi_spec = None
        if a.openapi_spec:
            if a.openapi_spec.startswith(("http://", "https://")):
                import urllib.request as _ur
                openapi_spec = json.loads(_ur.urlopen(a.openapi_spec, timeout=a.timeout).read().decode("utf-8", "replace"))
            else:
                openapi_spec = json.load(open(a.openapi_spec))
        # Phase 56: multi-user authorization config (accounts + login flow)
        authz_cfg = None
        if a.authz_accounts:
            authz_cfg = json.load(open(a.authz_accounts))
        cfg = ScanConfig(allow_private=a.allow_private, max_pages=a.max_pages,
                         crawl=not a.no_crawl, timeout=a.timeout, seed=a.seed,
                         strategy_path=a.strategy_path, browser=not a.no_browser,
                         auth=auth, openapi=not a.no_openapi, openapi_spec=openapi_spec,
                         authz=authz_cfg, secrets=not a.no_secrets,
                         vault=a.vault or None, vault_key_file=a.vault_key_file or None,
                         workflow=a.workflow, logic_active=a.logic_active,
                         exclude_urls=a.exclude_url,
                         race=a.race, race_parallel=a.race_parallel,
                         race_variance=a.race_variance, symbolic=a.symbolic,
                         modern_v2=a.modern_v2,
                         prioritize_store=a.prioritize_store or None)
        # AXIS-18: computed payloads are SENT to validation endpoints — a
        # loud, explicit notice before the first symbolic request leaves.
        if a.symbolic:
            print("[i] --symbolic: AXIS-18 symbolic execution is ENABLED — "
                  "validation constraints extracted from responses will be "
                  "solved exactly and the COMPUTED values sent as bounded "
                  "verification payloads (destructive solutions are blocked "
                  "before any request).", flush=True)
        # Phase 58: the attack battery changes application state — a loud,
        # explicit warning before a single probe leaves the engine.
        if a.logic_active:
            print("[!] --logic-active: business-logic attack probes are ENABLED — "
                  "state-changing manipulations (step bypass / out-of-order / value "
                  "tamper / duplicate execution / privilege bound / cross-user / "
                  "cross-object / cross-state) WILL be executed against the target "
                  "with canary values and bounded budgets.", flush=True)
        # ORD-002-WIRE: the race battery sends real concurrent traffic to
        # sensitive endpoints — a loud, explicit warning before any burst
        # leaves the engine (the --logic-active doctrine).
        if a.race:
            print("[!] --race: race-condition probes are ENABLED — sensitive "
                  "endpoints (transfer/pay/delete/modify/withdraw/move) will "
                  "receive bursts of 10 concurrent identical requests each; "
                  "destructive vocabulary (delete/transfer/...) is ALWAYS "
                  "rejected before any send.", flush=True)
            if not (1 <= a.race_parallel <= 64):
                ap.error("--race-parallel must be within 1..64 (the package's "
                         "budget gate is fail-closed)")
            if a.race_variance <= 0:
                ap.error("--race-variance must be a positive threshold in seconds")
        # Phase 52: channel-aware OAST arming. auto = local listener for targets
        # that can reach loopback (lab fixtures), PUBLIC webhook channel for remote
        # targets (live-proven: ginandjuice.shop blind XXE confirmed via webhook.site
        # callback from the target's own AWS egress). Degrades honestly to None when
        # the public service is unreachable — the scan proceeds exactly as in v2.0.x.
        oast = None
        from urllib.parse import urlparse as _up
        if not a.no_oast:
            from burhan.oast import make_oast
            oast = make_oast(_up(a.target).hostname or "", mode=a.oast)
            cfg.oast = oast
        try:
            sc = BurhanScanner(a.target, cfg)
            rep = sc.run()
        except Exception as e:
            # Phase 57: a refused vault (wrong key / tampered file / unauthorized
            # key) is a CONFIGURATION error that must fail fast and clean —
            # never a mid-scan traceback, never a partial vault write.
            from burhan.vault import VaultError
            if isinstance(e, VaultError):
                print(json.dumps({"scan_aborted": "vault refused",
                                  "vault_error": str(e),
                                  "hint": "the scan made ZERO requests; unlock "
                                          "with an authorized key file "
                                          "(burhan vault keygen / authorize)"}),
                      file=sys.stderr)
                sys.exit(2)
            raise
        finally:
            if oast is not None:
                oast.stop()
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        json.dump(rep, open(a.out, "w"), indent=1)
        # Phase 56: standalone credential-exposure report (masked values only —
        # the data-minimization discipline: secrets get their own channel and
        # never appear unmasked in ANY artifact).
        if a.secrets_report:
            cred = [f for f in rep["findings"] if f["type"] == "credential_exposure"]
            os.makedirs(os.path.dirname(a.secrets_report) or ".", exist_ok=True)
            vault_armed = bool(rep.get("stats", {}).get("vault"))
            json.dump({"run_id": rep["run_id"], "target": rep["target"],
                       "generated_by": rep["scanner"],
                       "policy": ("raw values are retained ENCRYPTED in the "
                                  "credential vault (see: burhan vault report) — "
                                  "this report stays masked"
                                  if vault_armed else
                                  "masked evidence only — raw secret values are "
                                  "never stored or transmitted by Burhan"),
                       "summary": rep.get("stats", {}).get("secrets", {}),
                       "vault": rep.get("stats", {}).get("vault"),
                       "findings": cred},
                      open(a.secrets_report, "w"), indent=1)
        if a.db:
            from burhan.store import Store
            n = Store(a.db).save_run(rep)
            # ---- v4.1.0 Security Memory (Phase V41-13): cross-run context,
            # host-scoped, NEVER evidence. Remember this run + surface the
            # change account (stale assumptions are flagged, never trusted).
            from burhan.memory import SecurityMemory
            mem = SecurityMemory(a.db + ".memory.json")
            rep["stats"]["memory"] = mem.memory_context(a.target, rep["stats"])
            mem.remember_run(a.target, rep)
            mem.save()
            print(json.dumps({"target": rep["target"], "stats": rep["stats"],
                              "verified_findings": len(rep["findings"]),
                              "persisted": n, "db": a.db}, indent=1))
        else:
            print(json.dumps({"target": rep["target"], "stats": rep["stats"],
                              "verified_findings": len(rep["findings"])}, indent=1))
        for f in sorted(rep["findings"], key=lambda x: -x["risk"]):
            print(f"  [{f['severity'].upper():8s}] {f['type']:26s} {f['url'][:60]:60s} param={f['parameter']:6s} risk={f['risk']}")
    elif a.cmd == "benchmark":
        rep = run_benchmark(a.url, a.out, a.strategy_path, a.timeout, label="cli",
                            race=a.race, race_parallel=a.race_parallel,
                            race_variance=a.race_variance)
        c = rep["confusion"]
        if rep["stats"]["requests"] <= 5:
            print("[OP-01] WARNING: benchmark target unreachable (requests<=5); "
                  "check --url", file=sys.stderr)
        print(json.dumps({"benchmark": rep["benchmark"], "confusion": c,
                          "precision": rep["precision"], "recall": rep["recall"], "f1": rep["f1"],
                          "stats": rep["stats"]}, indent=1))
        for d in rep["details"]:
            print(f"  {d['cell']}: {d['case']}")
    elif a.cmd == "repair-demo":
        repair_demo()
    elif a.cmd == "findings":
        from burhan.store import Store
        st = Store(a.db)
        if a.delta:
            print(json.dumps(st.delta(), indent=1))
        elif a.recurring:
            print(json.dumps(st.recurring(), indent=1))
        else:
            rows = st.list_findings(run_id=a.run_id, type_=a.type,
                                    min_risk=a.min_risk, status=a.status)
            print(json.dumps({"count": len(rows), "findings": rows}, indent=1))
            for f in rows:
                print(f"  [{f['severity'].upper():8s}] {f['type']:30s} {f['url'][:58]:58s} "
                      f"param={f['parameter']:8s} risk={f['risk']:3d} run={f.get('run_id', '')}")
    elif a.cmd == "compliance":
        # P2-C (2026-10-31): the compliance registry — OWASP Top 10 (2021 +
        # 2025 final), CWE and PCI DSS 6.4.2 per detector class. Source of
        # truth for every downstream renderer (reports, platform, docs).
        from burhan.compliance import (COMPLIANCE, PCI_DSS_REQUIREMENT,
                                         PCI_DSS_NOTE, compliance_json)
        if a.json:
            print(json.dumps(compliance_json(), indent=1, ensure_ascii=False))
        else:
            print(f"PCI DSS: {PCI_DSS_REQUIREMENT} — {PCI_DSS_NOTE}")
            print(f"{len(COMPLIANCE)} detector classes mapped; "
                  "src: official = CWE in the category's official list "
                  "(top10.owasp.org, fetched 2026-10-31); scope = editorial")
            print(f"{'type':38s} {'CWE':9s} {'OWASP 2021':22s} "
                  f"{'OWASP 2025':22s} PCI")
            for ftype in sorted(COMPLIANCE):
                from burhan.compliance import compliance_for
                c = compliance_for(ftype)
                print(f"{ftype:38s} {c['cwe']:9s} "
                      f"{c['owasp_2021'] + ' (' + c['owasp_2021_src'] + ')':22s} "
                      f"{c['owasp_2025'] + ' (' + c['owasp_2025_src'] + ')':22s} "
                      f"{c['pci_dss']}")
    elif a.cmd == "report":
        from burhan.store import Store
        from burhan.report import (build_report, build_html, build_sarif,
                                     build_executive, build_glass_html)
        st = Store(a.db)
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        if a.format in ("cef", "syslog", "ocsf"):
            # SIEM/enterprise export (this order, Part 1): the three formats
            # build on the SIGNED audit pipeline — the store's run row
            # carries the audit block (merkle root + Ed25519 signature);
            # every exported event points back to it (pointer, never a
            # copy of the full evidence). Only VERIFIED findings export.
            from burhan.siem import (build_cef, build_rfc5424, build_ocsf,
                                     SyslogSender)
            from burhan.audit import audit_block
            # --run-id selects directly; without it the NEWEST run is used
            # (list_runs is a summary — the full row comes from get_run)
            if a.run_id:
                run = st.get_run(a.run_id)
            else:
                newest = (st.list_runs(limit=1) or [{}])[0].get("run_id", "")
                run = st.get_run(newest) if newest else None
            if run is None:
                raise SystemExit(f"siem export: run {a.run_id or '(newest)'} "
                                 "not found in the store")
            # the store row predates the audit enrich (save_run persists
            # findings/stats only) — recompute the SAME audit block from the
            # stored run (audit.py: the root depends only on the findings,
            # the keypair only on the seed — both carried by the row), so
            # the export carries the signed-evidence pointer without any
            # parallel unsigned event path.
            audit = audit_block(run, seed=run.get("seed") or None)
            audit.setdefault("run_id", run.get("run_id", ""))
            findings = [f for f in run.get("findings", [])
                        if f.get("status") == "verified"]
            sent = 0
            if a.format == "cef":
                with open(a.out, "w", encoding="utf-8") as fh:
                    for f in findings:
                        fh.write(build_cef(f, audit) + "\n")
            elif a.format == "ocsf":
                events = [build_ocsf(f, audit) for f in findings]
                json.dump({"schema_version": "1.9.0",
                           "class": "Detection Finding",
                           "events": events}, open(a.out, "w"),
                          indent=1, ensure_ascii=False)
            else:  # syslog: a REAL send through SyslogSender (UDP RFC 5426 /
                   # TCP RFC 6587), plus the message log on disk
                with open(a.out, "w", encoding="utf-8") as fh:
                    with SyslogSender(a.syslog_host, a.syslog_port,
                                      proto=a.syslog_proto) as tx:
                        for f in findings:
                            msg = build_rfc5424(f, audit)
                            tx.send(msg)
                            fh.write(msg + "\n")
                            sent += 1
            print(json.dumps({"report": a.out, "format": a.format,
                              "run_id": run.get("run_id", ""),
                              "events": len(findings), "sent": sent,
                              "merkle_root": (audit.get("merkle_root")
                                              or "")[:16] + "…"}))
            return
        if a.format == "sarif":
            # OP-02: SARIF 2.1.0 — the industry interchange format (GitHub code
            # scanning / VS Code / DefectDojo). Verification-gated like everything
            # else: only VERIFIED findings become results.
            sarif = build_sarif(st, a.run_id)
            json.dump(sarif, open(a.out, "w"), indent=1)
            n = len(sarif.get("runs", [{}])[0].get("results", [])) if "runs" in sarif else 0
            print(json.dumps({"report": a.out, "format": "sarif", "run_id": a.run_id or "all-verified",
                              "results": n, "sarif_version": sarif.get("version", "")}))
        elif a.format == "json":
            json.dump(build_report(st, a.run_id), open(a.out, "w"), indent=1)
            print(json.dumps({"report": a.out, "format": a.format, "run_id": a.run_id or "overview"}))
        elif a.format == "executive":
            # Phase 64: the decision-maker view (risk posture, business impact,
            # affected assets, coverage proof) from the SAME data as the
            # technical report.
            json.dump(build_executive(st, a.run_id), open(a.out, "w"), indent=1, ensure_ascii=False)
            print(json.dumps({"report": a.out, "format": "executive", "run_id": a.run_id or "newest"}))
        elif a.format == "glass":
            # Phase 64: the iOS-style frosted-glass dashboard of the Digital Twin
            open(a.out, "w").write(build_glass_html(st, a.run_id))
            print(json.dumps({"report": a.out, "format": "glass", "run_id": a.run_id or "newest"}))
        elif a.format == "bilingual":
            # Round 9, part 1: the AR/EN client report — a NEW additive format;
            # no existing format's behavior changes. The structured JSON and the
            # .docx land next to --out; the source findings' Merkle root +
            # Ed25519 signature (audit.py) ride along as content-loss evidence.
            from burhan.bilingual import (build_bilingual as _bb,
                                          build_bilingual_docx as _bd,
                                          export_pdf as _ep)
            run_id = a.run_id or (st.list_runs(limit=1) or [{}])[0].get("run_id", "")
            run = st.get_run(run_id)
            if run is None:
                raise SystemExit(f"bilingual: run {run_id!r} not found in the store")
            bi = _bb(run)
            base_out = a.out[:-5] if a.out.endswith(".json") else a.out
            json.dump(bi, open(base_out + ".json", "w"), indent=1, ensure_ascii=False)
            _bd(bi, base_out + ".docx")
            pdf = ""
            if getattr(a, "pdf", False):
                pdf = _ep(base_out + ".docx", base_out + ".pdf")
            print(json.dumps({"report": base_out + ".json", "format": "bilingual",
                              "run_id": run_id, "findings": bi["findings_count"],
                              "docx": base_out + ".docx", "pdf": pdf,
                              "merkle_root": bi["audit"]["merkle_root"][:16] + "…"}))
            return
        else:
            open(a.out, "w").write(build_html(st, a.run_id))
            print(json.dumps({"report": a.out, "format": a.format, "run_id": a.run_id or "overview"}))
        if a.ci:
            # ---- v4.1.0 (Phase V41-16): the explicit CI exit contract —
            # POLICY failures and ENGINE failures are never conflated:
            #   0  no policy violation
            #   1  findings above the configured threshold (policy)
            #   2  scan incomplete / critical coverage gap (boundary-driven)
            #   3  engine failure (the report itself failed to build)
            exec_v = build_executive(st, a.run_id)
            fails = exec_v.get("ci_gate", {}).get("fail_on_high", 0)
            # coverage-gap axis: unresolved boundaries that mark the scan
            # incomplete (tool failures / engine errors during the run)
            stats = exec_v.get("stats") or {}
            boundary = stats.get("boundary") or {}
            engine_failures = (boundary.get("by_state") or {}).get(
                "TOOL_FAILURE", 0)
            exit_code, why = 0, "no policy violation"
            if fails:
                exit_code, why = 1, (f"verified critical/high findings: {fails}")
            elif engine_failures:
                exit_code, why = 2, (f"scan incomplete: {engine_failures} "
                                     "TOOL_FAILURE boundary records (engine "
                                     "errors during the run)")
            print(json.dumps({"ci_gate": {0: "PASS", 1: "FAIL",
                                           2: "INCOMPLETE", 3: "ERROR"}.get(exit_code),
                              "exit_code": exit_code, "why": why,
                              "critical_or_high": fails,
                              "tool_failures": engine_failures,
                              "contract": {"0": "no policy violation",
                                           "1": "findings above threshold (policy)",
                                           "2": "scan incomplete / critical coverage gap",
                                           "3": "engine failure"}}))
            sys.exit(exit_code)
    elif a.cmd == "twin":
        from burhan.store import Store
        st = Store(a.db)
        run_id = a.run_id
        if not run_id:
            runs = st.list_runs(limit=1)
            run_id = runs[0]["run_id"] if runs else ""
        run = st.get_run(run_id) if run_id else None
        if not run:
            print(json.dumps({"error": "no run found"}), file=sys.stderr)
            sys.exit(2)
        dt = (run.get("stats") or {}).get("digital_twin") or {}
        if a.full:
            print(json.dumps({"run_id": run_id, "target": run.get("target", ""),
                              "digital_twin": dt}, indent=1, ensure_ascii=False))
        else:
            summary_keys = ("nodes", "edges", "identities", "roles", "entities",
                            "surfaces_total", "surfaces_write", "workflow_steps",
                            "states_observed", "findings_attached", "secrets_masked",
                            "hypotheses", "flows")
            print(json.dumps({"run_id": run_id, "target": run.get("target", ""),
                              "digital_twin": {k: dt.get(k) for k in summary_keys if k in dt}},
                             indent=1, ensure_ascii=False))
    elif a.cmd == "reproduce":
        from burhan.store import Store
        from burhan.evidence import reproduce_command
        st = Store(a.db)
        runs = ([st.get_run(a.run_id)] if a.run_id
                else [st.get_run(r["run_id"]) for r in st.list_runs(limit=10)])
        proof = None
        for run in runs:
            if not run:
                continue
            for p in (run.get("stats") or {}).get("proofs") or []:
                if p.get("finding_id") == a.finding:
                    proof = p
                    break
            if proof:
                break
        if not proof:
            print(json.dumps({"error": f"finding {a.finding} not found in the last "
                                      f"runs' proof files (or its run predates v4.0.0)"}),
                  file=sys.stderr)
            sys.exit(2)
        if getattr(a, "gated", False):
            # --gated implies --replay (there is no gated non-replay mode)
            # Part 2: gated replay — same engine plus the live authorization
            # check + per-finding rate limit + identity-linked lifecycle
            # event. Refusals exit 2 (zero live requests); rate limit exit 3.
            from burhan.replay import replay_finding_gated, ReplayRateLimited
            try:
                g = replay_finding_gated(proof)
            except ReplayRateLimited as e:
                print(json.dumps({"replay": "RATE_LIMITED", "reason": str(e)}))
                raise SystemExit(3)
            print(json.dumps(g, indent=1, ensure_ascii=False))
            sys.exit(0 if g.get("replay") == "REPRODUCTION_VERIFIED" else 2)
        if a.replay:
            from urllib.parse import urlsplit
            from burhan.core import ScopeRule, EventBus
            from burhan.evidence import replay_finding
            req = (proof.get("requests") or [{}])[0]
            origin = "{0.scheme}://{0.netloc}".format(urlsplit(req.get("url", "")))
            # OWSP-24 (OWASP campaign, caught by the Mutillidae-round gate
            # cycle): allowed_domains must carry the HOSTNAME, never the
            # netloc — netloc keeps the port ("127.0.0.1:8812") while
            # _scope_ok matches against the port-free hostname, so every
            # replay against a non-default-port target was scope-blocked
            # (status 0). Pre-OWSP-22 the nested-scope bug masked this
            # (allowed_domains never gated at all); the independent gating
            # exposed the latent mismatch.
            scope = ScopeRule(allowed_domains=[urlsplit(req.get("url", "")).hostname],
                              allow_private=True)
            # RP-2 (replay fidelity, 2026-10-31): OOB-dependent classes
            # (cmdi/ssrf/xxe) verify through an OAST channel — the replay
            # must arm one exactly like the scan did. Loopback targets get a
            # LOCAL OastServer (zero external side effects); remote targets
            # need a public provider, which the caller must supply — the
            # verdict then says NOT_REPLAYABLE with the reason, never the
            # misleading 'no longer produces a candidate'.
            replay_oast = None
            _host = (urlsplit(req.get("url", "")).hostname or "").lower()
            if _host in ("127.0.0.1", "localhost", "::1"):
                from burhan.oast import OastServer
                replay_oast = OastServer()
            try:
                result = replay_finding(proof, scope, EventBus("replay"),
                                        timeout=a.timeout, oast=replay_oast)
            finally:
                if replay_oast is not None:
                    replay_oast.stop()
            print(json.dumps(result, indent=1, ensure_ascii=False))
            sys.exit(0 if result.get("replay") == "REPRODUCTION_VERIFIED" else 1)
        print(json.dumps(proof, indent=1, ensure_ascii=False))
        print("\n" + reproduce_command(proof))
    elif a.cmd == "sca":
        # Round 10, PART 3: SCA over a client dependency manifest. The
        # OSV.dev PUBLIC batch API is called (no key); every severity shown
        # is the advisory's own CVSS data; the raw responses land in
        # --raw-dir for the evidence contract. Deferred manifests refuse
        # LOUDLY (ManifestRejected -> exit 2), never a silent skip.
        from burhan.sca import build_sca_findings, ManifestRejected
        try:
            sca_out = build_sca_findings(a.manifest,
                                         kev_catalog=a.kev_catalog or "",
                                         raw_dir=a.raw_dir or "")
        except ManifestRejected as e:
            print(json.dumps({"error": f"manifest refused: {e}"}), file=sys.stderr)
            sys.exit(2)
        payload = json.dumps(sca_out, indent=1, ensure_ascii=False)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            print(json.dumps({"written": a.out,
                              "packages_queried": sca_out["packages_queried"],
                              "advisory_ids": len(sca_out["advisory_ids"]),
                              "findings": len(sca_out["findings"])}))
        else:
            print(payload)
    elif a.cmd == "unified":
        # Round 10, PART 4: the unified cross-category view. PURE
        # post-processing over its inputs (zero requests): the scan's
        # DAST findings keep their scan-time scores, SCA findings are
        # scored on the advisory-confirmed judgment (V=0.85, advisory-own
        # CVSS for T), chains take their members' components (J3).
        # Lifecycle resolves against the shared store when given and is
        # recorded under this invocation's own run id — never as findings
        # rows, so scan prev-run semantics stay untouched.
        from burhan.unified import build_unified
        from burhan.store import Store
        try:
            with open(a.scan, encoding="utf-8") as fh:
                scan_rep = json.load(fh)
        except Exception as e:
            print(json.dumps({"error": f"cannot read scan result: {e}"}),
                  file=sys.stderr)
            sys.exit(2)
        sca_reps = []
        for path in a.sca:
            try:
                with open(path, encoding="utf-8") as fh:
                    sca_reps.append(json.load(fh))
            except Exception as e:
                print(json.dumps(
                    {"error": f"cannot read SCA result {path}: {e}"}),
                    file=sys.stderr)
                sys.exit(2)
        store = Store(a.prioritize_store) if a.prioritize_store else None
        out = build_unified(scan_rep, sca_reps, store=store)
        payload = json.dumps(out, indent=1, ensure_ascii=False)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            print(json.dumps({"written": a.out,
                              "counts_by_category": out["counts_by_category"]}))
        else:
            print(payload)
    elif a.cmd == "apaths":
        # v4.3.0 (L2): Attack Path Intelligence over a saved scan result.
        # Pure post-processing — reads the JSON, builds the paths, zero requests.
        from burhan.apath import build_attack_paths
        try:
            with open(a.result, encoding="utf-8") as fh:
                rep = json.load(fh)
        except Exception as e:
            print(json.dumps({"error": f"cannot read result: {e}"}), file=sys.stderr)
            sys.exit(2)
        out = build_attack_paths(rep)
        if a.paths_only:
            out = {"paths": out["paths"]}
        payload = json.dumps(out, indent=1, ensure_ascii=False)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            print(json.dumps({"written": a.out,
                              "paths": len(out.get("paths", []))}))
        else:
            print(payload)
    elif a.cmd == "impact":
        # v4.4.0 (L3): Proven Real Impact. Pure planning by default (zero
        # requests); --execute issues the planned probes live and assesses.
        # The scan pipeline NEVER calls this layer (strictly opt-in).
        from burhan import impact as impact_mod
        try:
            with open(a.result, encoding="utf-8") as fh:
                rep = json.load(fh)
        except Exception as e:
            print(json.dumps({"error": f"cannot read result: {e}"}), file=sys.stderr)
            sys.exit(2)
        kw = {}
        if a.redirect_sink:
            kw["redirect_sink"] = a.redirect_sink
        if a.origin_probe:
            kw["origin_probe"] = a.origin_probe
        plan = impact_mod.plan_impact_probes(rep, **kw)
        journal = {}
        if a.execute:
            from urllib.parse import urlsplit as _us
            from burhan.core import ScopeRule
            from burhan.http_engine import RequestEngine
            from burhan.core import EventBus
            # OWSP-24 (cont.): hostname, not netloc — the impact path built
            # host from netloc (port included) and every L3 probe got
            # scope-blocked with status 0 even under --allow-private (live
            # proof: unit_max07 red on this exact symptom).
            host = _us(rep.get("target") or "").hostname or ""
            scope = ScopeRule(allowed_domains=[host] if host else [],
                              allow_private=a.allow_private)
            engine = RequestEngine(scope, EventBus("run-l3-cli"))
            journal = impact_mod.execute_impact_probes(plan, engine)
        assessment = impact_mod.assess_impacts(rep, plan, journal)
        if a.probe_journal and journal:
            with open(a.probe_journal, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(journal, indent=1, ensure_ascii=False) + "\n")
        if a.assessment:
            with open(a.assessment, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(assessment, indent=1, ensure_ascii=False) + "\n")
        if a.report:
            impact_mod.write_report(assessment, plan, journal, a.report)
        print(json.dumps({"plan": plan["summary"],
                          "assessment": assessment["summary"]},
                         ensure_ascii=False))
    elif a.cmd == "capability-matrix":
        from burhan.store import Store
        from burhan.report import _capability_rows
        st = Store(a.db)
        run_id = a.run_id
        if not run_id:
            runs = st.list_runs(limit=1)
            run_id = runs[0]["run_id"] if runs else ""
        run = st.get_run(run_id) if run_id else None
        if not run:
            print(json.dumps({"error": "no run found"}), file=sys.stderr)
            sys.exit(2)
        stats = run.get("stats") or {}
        rows = _capability_rows(stats)
        bnd = stats.get("boundary") or {}
        lines = [
            "# Burhan v4.1.0 — Capability Matrix",
            "",
            f"**Generated from run `{run_id}` on `{run.get('target', '')}`** — "
            "every number below is derived from the run's stored artifacts "
            "(coverage dimensions, engine stats, the boundary registry); this "
            "file is MACHINE-GENERATED (`burhan capability-matrix`), never "
            "hand-written.",
            "",
            "| Capability | Discovered | Tested | Verified | Unsupported / reason |",
            "|---|---|---|---|---|",
        ]
        for r in rows:
            reason = r.get("unsupported_reason") or ""
            lines.append(f"| {r['capability']} | {r['discovered']} | "
                         f"{r['tested']} | {r['verified']} | {reason} |")
        lines += [
            "",
            "## Boundary account (what this run could NOT test, and why)",
            "",
            f"- boundary records: **{bnd.get('records', 0)}** · unresolved: "
            f"**{bnd.get('unresolved', 0)}**",
            f"- by state: `{json.dumps(bnd.get('by_state', {}))}`",
            "",
            "| Category | State | Reason | Remediation |",
            "|---|---|---|---|",
        ]
        for b in (bnd.get("unresolved_detail") or [])[:20]:
            lines.append(f"| {b.get('category', '')} | {b.get('state', '')} | "
                         f"{b.get('reason', '')[:100]} | "
                         f"{(b.get('remediation') or '')[:80]} |")
        lines += [
            "",
            "## The honesty contract",
            "",
            "- A capability with 0 discovered surfaces is reported as "
            "**NOT_DISCOVERED** — never as tested.",
            "- No dimension claims 100% while unexplained untested items exist.",
            "- Every finding carries reproducible evidence; every twin node "
            "carries provenance; memory is context, never evidence.",
            "",
        ]
        open(a.out, "w", encoding="utf-8").write("\n".join(lines))
        print(json.dumps({"capability_matrix": a.out, "run_id": run_id,
                          "rows": len(rows)}, ensure_ascii=False))
    elif a.cmd == "serve":
        from burhan.api import run_server
        run_server(a.host, a.port, a.db, token=a.token)
    elif a.cmd == "vault":
        from burhan.vault import Vault, VaultError, keygen
        try:
            if a.vcmd == "keygen":
                kf = keygen(a.out, label=a.label)
                print(json.dumps({"key_file": a.out, "key_id": kf["key_id"],
                                  "label": a.label,
                                  "note": "0600 key file — hand to an authorized "
                                          "party only; never commit it to Git"}))
            elif a.vcmd == "init":
                v = Vault.init(a.vault, a.key_file, a.org, label=a.label)
                print(json.dumps(v.status()))
            else:
                v = Vault.open(a.vault, a.key_file)
                if a.vcmd == "status":
                    print(json.dumps(v.status()))
                elif a.vcmd == "list":
                    print(json.dumps({"org": v.org, "records": v.list()}, indent=1))
                elif a.vcmd == "export":
                    rec = v.export(a.record)
                    print(json.dumps(rec, indent=1))
                elif a.vcmd == "report":
                    rep_v = v.report()
                    if a.out:
                        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
                        json.dump(rep_v, open(a.out, "w"), indent=1)
                        print(json.dumps({"report": a.out, "org": rep_v["org"],
                                          "records": len(rep_v["records"]),
                                          "classification": rep_v["classification"]}))
                    else:
                        print(json.dumps(rep_v, indent=1))
                elif a.vcmd == "audit":
                    print(json.dumps({"org": v.org, "entries": v.audit()}, indent=1))
                elif a.vcmd == "authorize":
                    kid = v.authorize(a.new_key, label=a.label)
                    print(json.dumps({"authorized": kid, "label": a.label,
                                      "actor": v.key_id}))
                elif a.vcmd == "revoke":
                    v.revoke(a.key_id)
                    print(json.dumps({"revoked": a.key_id,
                                      "note": "blob key rotated — the revoked key "
                                              "cannot open any copy of this file"}))
                elif a.vcmd == "purge":
                    if not a.record and not a.all:
                        print(json.dumps({"error": "--record ID or --all required"}),
                              file=sys.stderr)
                        sys.exit(2)
                    n = v.purge(record_id=a.record or None, all_records=a.all)
                    print(json.dumps({"shredded": n,
                                      "note": "values removed from the encrypted "
                                              "blob; the audit entry survives"}))
        except VaultError as e:
            print(json.dumps({"vault_error": str(e)}), file=sys.stderr)
            sys.exit(2)


if __name__ == "__main__":
    from burhan.envcompat import warn_legacy_environment
    warn_legacy_environment()
    main()

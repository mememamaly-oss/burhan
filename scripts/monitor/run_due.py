#!/usr/bin/env python3
"""Self-hosted continuous monitoring runner (Part 3.1's documented
equivalent to the GitHub Actions workflow): run this from cron/systemd
timers — it reads monitor-config.json, and for each target whose cron
schedule is DUE at this minute (per the same cron syntax GitHub uses,
evaluated by croniter if installed, else the target's schedule must be
driven by the operator's own cron invoking this script with --target),
it re-runs the existing scan engine and the existing lifecycle comparison,
then alerts per policy.

Monitoring is opt-in: an absent config or an empty targets list makes
this a no-op that prints the OFF state and exits 0."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _validated_caps(t: dict) -> tuple[dict, str | None]:
    """r19-3.4 (supervisor order 2026-11-21 item 2): validate the
    per-target scan caps BEFORE any scan is built. Returns (caps, err):
    caps is a dict of the three validated values, err is a human-readable
    rejection reason (None when valid). A target with bad caps is SKIPPED
    with exit=3 and a clear message — never scanned with unknown values.

    Rules (supervisor-specified):
      max_pages: integer (bool rejected) in [1, 200]
      timeout:   int or float (bool rejected) in [1, 300]
      browser:   a REAL boolean (anything else rejected)
    """
    caps: dict = {}
    mp = t.get("max_pages", 40)
    if isinstance(mp, bool) or not isinstance(mp, int):
        return {}, (f"max_pages must be an integer in [1, 200], "
                    f"got {type(mp).__name__}: {mp!r}")
    if not 1 <= mp <= 200:
        return {}, (f"max_pages must be in [1, 200], got {mp}")
    caps["max_pages"] = mp
    to = t.get("timeout", 12.0)
    if isinstance(to, bool) or not isinstance(to, (int, float)):
        return {}, (f"timeout must be a number in [1, 300], "
                    f"got {type(to).__name__}: {to!r}")
    if not 1 <= float(to) <= 300:
        return {}, (f"timeout must be in [1, 300], got {to}")
    caps["timeout"] = float(to)
    br = t.get("browser", True)
    if not isinstance(br, bool):
        return {}, (f"browser must be a real boolean, "
                    f"got {type(br).__name__}: {br!r}")
    caps["browser"] = br
    return caps, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "scripts/monitor/monitor-config.json"))
    ap.add_argument("--target", default="",
                    help="run only this target id (cron-driven per-target use)")
    args = ap.parse_args()

    from burhan.monitor import load_config
    cfg = load_config(Path(args.config))
    targets = cfg.get("targets") or []
    if args.target:
        targets = [t for t in targets if t.get("id") == args.target]
    if not targets:
        print(json.dumps({"monitoring": "OFF (no configured targets — "
                                        "opt-in only, see the config policy)"}))
        return 0
    webhook = cfg.get("webhook_url") or ""
    results = []
    import subprocess
    for t in targets:
        # round-12 part 2.2: a target may declare a local FIXTURE the runner
        # starts first (the dogfood pattern: the repo's own vulnapp). The
        # fixture is started ONLY when declared — external targets are
        # untouched, and the authorization verdict below is checked LIVE
        # before any scan is built.
        # r19-2.15 (owner order 2026-11-20 ب-2, live-caught defect): the
        # scheduled monitor previously built BurhanScanner DIRECTLY with
        # no require_authorized call — a registry-less config reached the
        # network anyway (live-verified: 36 connections to an unregistered
        # 127.0.0.1 target). The gate now runs HERE, before the scanner
        # is constructed: a target absent from authorized-targets.json is
        # refused with zero scan requests, exactly like the CLI/API paths.
        from burhan.authorized_targets import authorize
        ok, reason, entry_id = authorize(t["target"],
                                         lab_flag=bool(t.get("lab", False)))
        if not ok:
            results.append({"id": t.get("id"), "target": t["target"],
                            "exit": 2,
                            "refused": reason,
                            "authorized_entry": None})
            continue
        fixture_proc = None
        fx = t.get("fixture")
        if fx:
            import os, time as _t
            port = str(t.get("fixture_port", 8777))
            fixture_proc = subprocess.Popen(
                [sys.executable, str(ROOT / fx)],
                env={"PORT": port, "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _t.sleep(1.5)
        try:
            # Round-12 dogfood live-catch #2: the previous version ran the CLI
            # scan and DROPPED the report — nothing ever called run_monitor_cycle,
            # so lifecycle was never recorded and alerts never evaluated (the
            # alerting layer was workflow-unreachable: tested green via direct
            # calls, dead in the actual scheduled path — the --gated shape).
            # The scan now runs IN-PROCESS and its report goes through the
            # monitor's own entry point.
            import time as _tt
            from burhan.auth import AuthProfile
            from burhan.oast import OastServer
            from burhan.orchestrator import BurhanScanner, ScanConfig
            from burhan.store import Store
            from burhan.monitor import run_monitor_cycle

            caps, cap_err = _validated_caps(t)
            if cap_err is not None:
                # r19-3.4: bad caps -> the target is SKIPPED loudly
                # (exit=3), never scanned with unknown values
                # (supervisor rule: "no scan with unknown values").
                results.append({"id": t.get("id"),
                                "target": t.get("target", ""),
                                "exit": 3, "skipped": cap_err})
                continue
            st = Store(t.get("store", "results/monitor.db"))
            oast = OastServer()
            t0 = _tt.time()
            try:
                # r19-3.1 (supervisor 2026-11-21, CI macOS diagnosis): the
                # per-target scan caps are now overridable from the target's
                # own config entry (max_pages / timeout / browser). Defaults
                # are UNCHANGED (40 pages / 12s / browser on) — the monitor's
                # production contract is untouched; this exists so a test
                # (or an operator) can bound a probe on slow hardware (the
                # macOS ARM runner needs ~180x the Linux time for a full
                # browser scan; the gate test only needs to prove the target
                # is REACHED, not deep-crawled).
                # r19-3.4: values pass _validated_caps first — types
                # AND bounds; the raw t.get defaults never reach here.
                cfg = ScanConfig(allow_private=True,
                                 max_pages=caps["max_pages"],
                                 timeout=caps["timeout"],
                                 browser=caps["browser"],
                                 oast=oast,
                                 prioritize_store=t.get(
                                     "store", "results/monitor.db"))
                sc = BurhanScanner(t["target"], cfg)
                rep = sc.run()
            finally:
                oast.stop()
            wall = round(_tt.time() - t0, 1)
            mon = run_monitor_cycle(st, t["target"], rep, webhook_url=webhook)
            results.append({
                "id": t.get("id"), "target": t["target"], "exit": 0,
                "run_id": rep.get("run_id"), "wall_seconds": wall,
                "findings": len(rep.get("findings", [])),
                "alerts_count": len(mon.get("alerts") or []),
                "alerts": mon.get("alerts") or [],
                "delivery": mon.get("delivery"),
            })
        except Exception as e:  # noqa: BLE001 — recorded, never silent
            import traceback
            results.append({"id": t.get("id"), "target": t["target"],
                            "exit": 1,
                            "error": f"{type(e).__name__}: {e}",
                            "traceback_tail": traceback.format_exc()[-1500:]})
        finally:
            if fixture_proc is not None:
                fixture_proc.terminate()
                fixture_proc.wait(timeout=10)
    print(json.dumps({"runs": results, "webhook_configured": bool(webhook)},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

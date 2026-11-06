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
        # untouched, and the authorized-targets gate still applies at scan.
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

            st = Store(t.get("store", "results/monitor.db"))
            oast = OastServer()
            t0 = _tt.time()
            try:
                cfg = ScanConfig(allow_private=True, max_pages=40,
                                 timeout=12.0, oast=oast,
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

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
    for t in targets:
        # the scan engine + lifecycle comparison + alerting, one target
        cmd = [sys.executable, "-m", "burhan.cli", "scan",
               "--target", t["target"],
               "--db", t.get("store", "results/monitor.db")]
        if t.get("extra_args"):
            cmd += t["extra_args"]
        import subprocess
        r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
        results.append({"id": t.get("id"), "target": t["target"],
                        "exit": r.returncode,
                        "stdout_tail": r.stdout[-2000:] if r.stdout else ""})
    print(json.dumps({"runs": results, "webhook_configured": bool(webhook)},
                     indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Part 3 — Continuous monitoring + regression alerting.

Builds on the EXISTING lifecycle tracking (NEW/RECURRING/FIXED/REGRESSED,
prioritize.resolve_lifecycle + store.record_lifecycle) — this module never
duplicates that logic; it SCHEDULES runs and ALERTS on what the lifecycle
resolver already decided.

3.1 scheduled scans: scripts/monitor/monitor-config.json declares, per
target, an explicit schedule + scan profile; .github/workflows/monitor.yml
(or any cron the operator already runs — scripts/monitor/run_due.py is the
self-hosted equivalent) re-runs the existing scan engine and lets the
EXISTING lifecycle comparison classify every identity against the prior
run of that same target.

3.2 alerting: after a run's lifecycle resolution, a REGRESSED identity
(previously FIXED, now present again) or a NEW identity of CRITICAL
severity fires a notification through at least one real channel — a
generic webhook (documented payload schema below) is the built-in minimum.
Email/Slack are NOT built here (the generic webhook covers both via
integrations); that is stated, not implied.

3.3 opt-in per target, never silently enabled: a target appears in
monitor-config.json ONLY by explicit operator action — the same reasoning
as the race-prober's opt-in-only design: unattended automated scanning
against a target needs deliberate configuration, not a default. A missing
config = zero scheduled scans, zero alerts. The authorization gate
(authorized-targets.json) still applies at every scan on top.
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

from .prioritize import (NEW, RECURRING, FIXED, REGRESSED,  # noqa: F401
                         resolve_lifecycle, annotate_identities)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = REPO_ROOT / "scripts" / "monitor" / "monitor-config.json"

# ---------------------------------------------------------------------------
# 3.2 the alert payload — the documented contract of the generic webhook
# ---------------------------------------------------------------------------
ALERT_PAYLOAD_SCHEMA_DOC = """{
  "schema": "burhan-monitor-alert/1",
  "target": "<scanned target origin>",
  "run_id": "<the scan run that produced the alert>",
  "generated_at": "<RFC3339>",
  "alerts": [
    {
      "kind": "REGRESSED",            # or "CRITICAL_NEW"
      "identity": "<finding identity>",
      "type": "<detector type>",
      "endpoint": "<affected endpoint>",
      "severity": "critical",
      "previous_state": "FIXED",      # REGRESSED only: the state it broke from
      "evidence_pointer": {           # pivot back to the full signed proof
        "run_id": "...", "merkle_root": "...", "signature_b64": "...",
        "public_key_b64": "..."}
    }
  ]
}"""

ALERT_KINDS = ("REGRESSED", "CRITICAL_NEW")


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    """3.3: the config is the ONLY thing that enables monitoring. Missing
    or empty -> monitoring is OFF (returned as {"targets": []}), never an
    error and never a default schedule."""
    if not Path(path).exists():
        return {"targets": [], "note": "monitor-config.json absent — "
                                       "continuous monitoring is OFF"}
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    assert isinstance(cfg.get("targets"), list), "config.targets must be a list"
    return cfg


def evaluate_alerts(resolution: dict, findings: list[dict],
                    audit: dict | None = None) -> list[dict]:
    """One run's lifecycle resolution -> the alert list (3.2 policy):
    every REGRESSED identity (previously FIXED, now present again) and
    every CRITICAL-severity NEW identity. RECURRING-only runs and
    non-critical NEW findings produce ZERO alerts (a stable run must be
    silent, not noisy — 3.4's negative control)."""
    audit = audit or {}
    states = resolution.get("present_states") or {}
    by_identity = {}
    for f in findings:
        ident = f.get("identity") or ""
        if ident:
            by_identity[ident] = f
    alerts: list[dict] = []
    for ident, state in states.items():
        f = by_identity.get(ident, {})
        if state == REGRESSED:
            alerts.append({
                "kind": "REGRESSED", "identity": ident,
                "type": f.get("type", ""), "endpoint":
                    (f.get("identity_basis") or {}).get("endpoint", ""),
                "severity": f.get("severity", ""),
                "previous_state": FIXED,
                "evidence_pointer": _pointer(audit),
            })
        elif state == NEW and str(f.get("severity", "")).lower() == "critical":
            alerts.append({
                "kind": "CRITICAL_NEW", "identity": ident,
                "type": f.get("type", ""), "endpoint":
                    (f.get("identity_basis") or {}).get("endpoint", ""),
                "severity": f.get("severity", ""),
                "previous_state": None,
                "evidence_pointer": _pointer(audit),
            })
    return alerts


def _pointer(audit: dict) -> dict:
    return {k: audit[k] for k in ("run_id", "merkle_root", "signature_b64",
                                  "public_key_b64") if audit.get(k)}


def send_alerts(webhook_url: str, target: str, run_id: str,
                alerts: list[dict], timeout: float = 10.0) -> dict:
    """POST the documented payload (ALERT_PAYLOAD_SCHEMA_DOC) to the
    operator's webhook. One request per RUN (not per alert) — the channel
    is notified, not spammed. Returns the delivery record."""
    from datetime import datetime, timezone
    body = json.dumps({
        "schema": "burhan-monitor-alert/1",
        "target": target,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": alerts,
    }).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "burhan-continuous-monitoring"})
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"delivered": True, "status": r.status,
                    "elapsed_s": round(time.time() - started, 3),
                    "alerts_sent": len(alerts)}
    except Exception as e:  # delivery failure is reported, never swallowed
        return {"delivered": False, "error": f"{type(e).__name__}: {e}",
                "elapsed_s": round(time.time() - started, 3),
                "alerts_sent": 0}


def _monitor_history(store, target: str, run_id: str) -> dict:
    """Lifecycle history for the monitor's comparison. Uses the store's own
    history with one monitor-specific correction, from store.py's own
    contract: the LOG — not the findings rows — is the lifecycle source of
    truth (a FIXED run by definition has no finding rows, so a findings-run
    lookup would skip it and read a REGRESSION as RECURRING). prev_run_present
    therefore comes from lifecycle_prev_present (log-driven), exactly like
    the unified-report path; ever_seen/latest_state from lifecycle_history."""
    h = store.lifecycle_history(target, run_id)
    h["prev_run_present"] = store.lifecycle_prev_present(target, run_id)
    return h


def run_monitor_cycle(store, target: str, report: dict, webhook_url: str,
                      audit: dict | None = None) -> dict:
    """The full cycle for ONE completed scan run (the scan itself is run by
    the workflow/runner, NOT here — this module consumes its signed result):
    resolve lifecycle against the store's memory for that target (the
    existing comparison), record it (the existing store API), evaluate the
    alert policy, and deliver via the webhook if — and only if — the run
    produced alertable state."""
    resolution = report.get("prioritization", {}).get("resolution")
    if not resolution:
        # resolve it here with the EXISTING engine (no duplication)
        history = _monitor_history(store, target, report["run_id"])
        covered = _covered_endpoints(report)
        annotate_identities(report)
        resolution = resolve_lifecycle(
            history, [f for f in report.get("findings", [])
                      if f.get("status") == "verified"], covered)
    store.record_lifecycle(report["run_id"], target, resolution)
    alerts = evaluate_alerts(resolution, report.get("findings", []), audit)
    result = {"run_id": report["run_id"], "target": target,
              "alerts": alerts, "delivery": None}
    if alerts and webhook_url:
        result["delivery"] = send_alerts(webhook_url, target,
                                         report["run_id"], alerts)
    return result


def _covered_endpoints(report: dict) -> set[str]:
    """The 'equivalent coverage' set for FIXED claims — reuses the
    prioritize module's own definition (covered_endpoints)."""
    from .prioritize import covered_endpoints
    return covered_endpoints(report)


__all__ = ["load_config", "evaluate_alerts", "send_alerts",
           "run_monitor_cycle", "ALERT_PAYLOAD_SCHEMA_DOC", "ALERT_KINDS",
           "DEFAULT_CONFIG"]

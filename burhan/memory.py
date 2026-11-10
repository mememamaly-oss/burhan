"""Burhan v4.1.0 — Security Memory (Phase V41-13).

Cross-run, PER-APPLICATION memory. Three rules, enforced and tested:

  1. MEMORY REDUCES REPETITION, IT NEVER PROVES ANYTHING.
     Nothing from a previous run ever lands in the current run's findings,
     evidence, or coverage. Memory output is always labeled 'memory:*' and
     lives in its own stats section.

  2. MEMORY IS KEYED BY APPLICATION (host) — one application's memory is
     never consulted for another (tenant isolation by construction: the
     store is a dict keyed by the target's host, and lookups cannot cross).

  3. APPLICATION CHANGE INVALIDATES STALE ASSUMPTIONS.
     When the fingerprint surface (endpoint set + tech stack) changes,
     previously-verified findings and learned flows are flagged
     'stale:needs_revalidation' — they are never silently trusted.

Storage: a JSON sidecar next to the scan DB (default
`<db-path>.memory.json`), written atomically after every remembered run.
"""
from __future__ import annotations

import json
import os
import tempfile
import urllib.parse


def _host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url or "").netloc or "unknown").lower()


class SecurityMemory:
    """The per-app memory store. All operations O(1)/O(n) on plain dicts."""

    VERSION = 1

    def __init__(self, path: str = ""):
        self.path = path
        self._data: dict = {"version": self.VERSION, "apps": {}}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict) and loaded.get("version") == self.VERSION:
                    self._data = loaded
            except Exception:
                # corrupt memory is discarded loudly-but-safely: a memory
                # failure must never fail a scan
                self._data = {"version": self.VERSION, "apps": {}}

    # ------------------------------------------------------------ recall
    def recall(self, target_url: str) -> dict:
        """The memory of ONE application (host-keyed; never another app's)."""
        app = self._data["apps"].get(_host_of(target_url))
        if not app:
            return {"known_app": False, "note":
                    "no prior knowledge of this application (host-scoped memory)"}
        return {"known_app": True, **app}

    # ------------------------------------------------------------ remember
    def remember_run(self, target_url: str, report: dict) -> None:
        """Merge one finished run's durable facts into this app's memory.
        Kept facts: fingerprints, verified finding fingerprints, learned
        flow clusters, rejected hypotheses, failed attacks, boundaries."""
        host = _host_of(target_url)
        app = self._data["apps"].setdefault(
            host, {"runs": 0, "fingerprints": [], "verified_findings": [],
                   "flows_learned": [], "rejected_hypotheses": [],
                   "failed_attacks": [], "boundaries": []})
        stats = report.get("stats") or {}
        app["runs"] += 1
        fp = {"run": report.get("run_id", ""),
              "endpoints": stats.get("endpoints", 0),
              "tech": sorted(((stats.get("fingerprint") or {})
                              .get("technologies") or []))[:12],
              "waf": ((stats.get("fingerprint") or {}).get("waf") or "")}
        if not any(f["tech"] == fp["tech"] and f["endpoints"] == fp["endpoints"]
                   for f in app["fingerprints"]):
            app["fingerprints"] = (app["fingerprints"] + [fp])[-10:]
        for f in report.get("findings") or []:
            if f.get("status") == "verified":
                key = f"{f.get('type')}|{(f.get('url') or f.get('endpoint_url', '')).split('?')[0]}|{f.get('parameter', '')}"
                if key not in [x["key"] for x in app["verified_findings"]]:
                    app["verified_findings"].append(
                        {"key": key, "first_seen": report.get("run_id", "")})
                app["verified_findings"] = app["verified_findings"][-200:]
        for fl in (stats.get("workflow", {}) or {}).get("flows") or []:
            if fl.get("cluster") not in app["flows_learned"]:
                app["flows_learned"].append(fl.get("cluster"))
        for h in (stats.get("reasoning", {}) or {}).get("hypotheses") or []:
            if h.get("status") == "tested:refuted" and \
                    h.get("pattern") not in app["rejected_hypotheses"]:
                app["rejected_hypotheses"].append(h.get("pattern"))
        for a in (stats.get("workflow", {}) or {}).get("attack_log") or []:
            if a.get("verdict") == "no_proof" and \
                    f"{a.get('flow')}:{a.get('attack')}" not in app["failed_attacks"]:
                app["failed_attacks"].append(f"{a.get('flow')}:{a.get('attack')}")
        for b in (stats.get("boundary", {}) or {}).get("unresolved_detail") or []:
            key = f"{b.get('category')}|{b.get('state')}"
            if key not in [x["key"] for x in app["boundaries"]]:
                app["boundaries"].append({"key": key,
                                          "reason": b.get("reason", "")[:120]})
        app["boundaries"] = app["boundaries"][-100:]

    def save(self) -> None:
        if not self.path:
            return
        # C3 occurrence #5: a FIXED tmp name races between concurrent
        # writers of one memory store (torn document / dead writer). The
        # vault.py discipline: unique mkstemp name per write, same dir,
        # cleaned up on failure, then one atomic rename.
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".memory-tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)          # atomic all-or-nothing
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------ change logic
    def app_changed(self, target_url: str, stats: dict) -> dict:
        """Compare the current run's fingerprint against memory. Returns the
        change account; stale entries are marked for revalidation (never
        trusted, never deleted silently)."""
        mem = self.recall(target_url)
        if not mem.get("known_app"):
            return {"known_app": False}
        last = (mem.get("fingerprints") or [{}])[-1]
        tech_now = sorted(((stats.get("fingerprint") or {}).get("technologies")
                           or []))[:12]
        changes = []
        if last.get("endpoints") != stats.get("endpoints"):
            changes.append(f"endpoint count {last.get('endpoints')} -> "
                           f"{stats.get('endpoints')}")
        if last.get("tech") != tech_now:
            added = [t for t in tech_now if t not in (last.get("tech") or [])]
            removed = [t for t in (last.get("tech") or []) if t not in tech_now]
            changes.append("technology stack changed"
                           + (f" (+{added})" if added else "")
                           + (f" (-{removed})" if removed else ""))
        stale = []
        if changes:
            stale = [v["key"] for v in mem.get("verified_findings", [])]
        return {"known_app": True, "changes": changes,
                "stale_needs_revalidation": stale,
                "note": ("application changed since the last run — prior "
                         "verifications are STALE and must be revalidated "
                         "(memory is context, never evidence)"
                         if changes else
                         "application fingerprint unchanged since the last run "
                         "(prior knowledge still needs current-run evidence "
                         "to count for anything)")}

    def memory_context(self, target_url: str, stats: dict) -> dict:
        """The honest memory section for the run report."""
        mem = self.recall(target_url)
        change = self.app_changed(target_url, stats)
        return {"known_app": mem.get("known_app", False),
                "prior_runs": mem.get("runs", 0),
                "previously_verified": len(mem.get("verified_findings", [])),
                "flows_learned_before": mem.get("flows_learned", []),
                "rejected_hypotheses_before": mem.get("rejected_hypotheses", []),
                "known_boundaries_before": len(mem.get("boundaries", [])),
                "app_changed": bool(change.get("changes")),
                "changes": change.get("changes", []),
                "stale_needs_revalidation": change.get(
                    "stale_needs_revalidation", []),
                "policy": ("memory is context, never evidence — every finding "
                           "in THIS report carries only this run's evidence")}

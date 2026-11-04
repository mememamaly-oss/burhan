"""Phase 46 (architecture continuation): Persistence Layer — SQLite store for runs
and findings. Pure stdlib (sqlite3). 

Why: until v2.0.x every scan was a stateless JSON file — the platform had no memory
ACROSS runs. The architecture's intelligence phases (trend analysis, recurring
findings, fix-regression detection "the same vuln came back after a deploy") require
a queryable store. This module is that store, wired behind the same determinism
contract as everything else (run_id is the join key; finding fingerprints are the
identity of a vulnerability across runs).

Schema (v1):
  runs     (run_id PK, seed, scanner, target, started, finished, stats_json)
  findings (id PK, run_id FK, type, severity, status, url, parameter, method,
            confidence, risk, fingerprint, evidence_json, verification_json,
            first_seen)

Queries:
  save_run()      — persist a scan report (idempotent per run_id+finding id)
  list_runs()     — newest first
  get_run()       — one run + its findings
  list_findings() — cross-run filterable query
  recurring()     — fingerprints seen in >1 run (the vuln came back)
  delta()         — new / fixed / recurring between two runs (or latest two)
"""
from __future__ import annotations
import json, os, sqlite3, time, hashlib


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    seed       TEXT,
    scanner    TEXT,
    target     TEXT,
    started    REAL,
    finished   REAL,
    stats_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id                TEXT,
    run_id            TEXT NOT NULL REFERENCES runs(run_id),
    type              TEXT,
    severity          TEXT,
    status            TEXT,
    url               TEXT,
    parameter         TEXT,
    method            TEXT,
    confidence        REAL,
    risk              INTEGER,
    fingerprint       TEXT,
    evidence_json     TEXT,
    verification_json TEXT,
    first_seen        REAL,
    PRIMARY KEY (id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run   ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(type);
"""

# Round 10, PART 1 — the lifecycle resolution log. The findings table can
# only hold rows for findings a run PRODUCED; a FIXED identity is by
# definition ABSENT from the current run, so its resolution needs a home
# of its own. This table records, per run, the resolved state of every
# identity the resolver touched — present (NEW/RECURRING/REGRESSED),
# FIXED (absent AND the endpoint re-tested), or UNTESTED_ABSENCE (absent
# with no coverage — the previous state stands; never a silent negative).
LIFECYCLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS lifecycle_log (
    run_id      TEXT NOT NULL,
    target      TEXT NOT NULL,
    identity    TEXT NOT NULL,
    state       TEXT NOT NULL,
    endpoint    TEXT,
    resolved_at REAL,
    PRIMARY KEY (run_id, identity)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_target ON lifecycle_log(target);
"""

# Round 10, PART 1 — the risk-prioritization columns (identity + lifecycle +
# risk_score). ALTER TABLE ... ADD COLUMN on every open (IF NOT EXISTS is not
# supported by sqlite for columns): the PRAGMA probe keeps old stores intact
# and makes the migration idempotent — no store is ever rebuilt or dropped.
V10_COLUMNS = {
    "identity":    "TEXT",     # prioritize.finding_identity — stable across runs
    "endpoint":    "TEXT",     # normalized endpoint (the identity's basis, auditable)
    "lifecycle":   "TEXT",     # NEW / RECURRING / FIXED / REGRESSED (this run)
    "risk_score":  "INTEGER",  # the Part-1 formula's score for this run
    "risk_components": "TEXT", # the score's components, JSON (transparency)
}

# Round 10, PART 2: the proven attack chains ride the RUN row (a list,
# not per-finding data). Same idempotent ALTER TABLE discipline.
V10_RUN_COLUMNS = {
    "attack_chains_json": "TEXT",
}


def finding_fingerprint(type_: str, method: str, url: str, parameter: str) -> str:
    """Stable cross-run identity of ONE vulnerability at ONE injection point
    (same contract as Finding.fingerprint(), minus per-instance evidence kinds)."""
    base = f"{type_}|{method}|{url.split('?')[0]}|{parameter}"
    return hashlib.sha256(base.encode()).hexdigest()[:16]


class Store:
    """SQLite persistence. One file, WAL mode, thread-safe via per-call connections
    (the REST API serves scans from worker threads while readers poll)."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
            c.executescript(LIFECYCLE_SCHEMA)
            self._migrate_v10(c)

    @staticmethod
    def _migrate_v10(c) -> None:
        """Idempotent ADD COLUMN migration for the round-10 lifecycle layer.
        Old stores keep every row; new columns read as NULL -> treated as
        legacy (no lifecycle recorded yet)."""
        have = {r["name"] for r in c.execute("PRAGMA table_info(findings)")}
        for col, decl in V10_COLUMNS.items():
            if col not in have:
                c.execute(f"ALTER TABLE findings ADD COLUMN {col} {decl}")
        have_runs = {r["name"] for r in c.execute("PRAGMA table_info(runs)")}
        for col, decl in V10_RUN_COLUMNS.items():
            if col not in have_runs:
                c.execute(f"ALTER TABLE runs ADD COLUMN {col} {decl}")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
        return c

    # ---------------------------------------------------------------- write
    def save_run(self, report: dict) -> int:
        """Persist one scan report dict (as produced by BurhanScanner.report()).
        Round 10, part 1: when the report's findings carry the prioritization
        block (identity + lifecycle + risk_score — attached by
        orchestrator.report() BEFORE save), it is persisted in the same
        signed-store row; reports without it (legacy callers) persist exactly
        as before, with the columns left NULL."""
        stats = dict(report.get("stats") or {})
        now = time.time()
        rows = 0
        cols = ("id, run_id, type, severity, status, url, parameter, method, "
                "confidence, risk, fingerprint, evidence_json, verification_json, "
                "first_seen, identity, endpoint, lifecycle, risk_score, "
                "risk_components")
        n_ph = "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"   # 19 placeholders = 19 cols
        chains = report.get("attack_chains") or []
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO runs "
                "(run_id, seed, scanner, target, started, finished, stats_json, "
                " attack_chains_json) VALUES (?,?,?,?,?,?,?,?)",
                (report["run_id"], report.get("seed", ""), report.get("scanner", ""),
                 report.get("target", ""), now, now, json.dumps(stats),
                 json.dumps(chains) if chains else None))
            for f in report.get("findings", []):
                fp = finding_fingerprint(f["type"], f.get("method", "GET"),
                                         f.get("url", ""), f.get("parameter", ""))
                comps = f.get("risk_components")
                c.execute(
                    f"INSERT OR REPLACE INTO findings ({cols}) VALUES ({n_ph})",
                    (f["id"], report["run_id"], f["type"], f.get("severity", ""),
                     f.get("status", "verified"), f.get("url", ""), f.get("parameter", ""),
                     f.get("method", "GET"), f.get("confidence", 0.0), f.get("risk", 0), fp,
                     json.dumps(f.get("evidence", []))[:4000],
                     json.dumps(f.get("verification", {}))[:2000], now,
                     f.get("identity") or None,
                     (f.get("identity_basis") or {}).get("endpoint") or None,
                     f.get("lifecycle") or None,
                     f.get("risk_score") if f.get("risk_score") is not None else None,
                     json.dumps(comps) if comps is not None else None))
                rows += 1
            # rejected candidates stored too (status='rejected') — audit trail of the
            # verification gate's decisions, queryable for FN forensics
            for f in report.get("rejected_candidates", []):
                fp = finding_fingerprint(f["type"], f.get("method", "GET"),
                                         f.get("url", ""), f.get("parameter", ""))
                c.execute(
                    f"INSERT OR REPLACE INTO findings ({cols}) VALUES ({n_ph})",
                    (f["id"], report["run_id"], f["type"], f.get("severity", ""),
                     "rejected", f.get("url", ""), f.get("parameter", ""),
                     f.get("method", "GET"), f.get("confidence", 0.0), 0, fp,
                     json.dumps(f.get("evidence", []))[:4000],
                     json.dumps(f.get("verification", {}))[:2000], now,
                     None, None, None, None, None))
                rows += 1
        # round 10, part 1: the resolver's decisions ride the report; record
        # them in the lifecycle log so FIXED/absent identities keep a state
        # trail. The SAME store stays the only persistence layer.
        resolution = ((report.get("prioritization") or {}).get("resolution") or {})
        if resolution:
            self.record_lifecycle(report["run_id"], report.get("target", ""),
                                  resolution)
        return rows

    # ---------------------------------------------------------------- read
    def list_runs(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT run_id, seed, scanner, target, started, stats_json FROM runs "
                "ORDER BY started DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            out.append({"run_id": r["run_id"], "seed": r["seed"], "scanner": r["scanner"],
                        "target": r["target"], "started": r["started"],
                        **({"stats": json.loads(r["stats_json"])} if r["stats_json"] else {})})
        return out

    def get_run(self, run_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if not r:
                return None
            fs = c.execute(
                "SELECT * FROM findings WHERE run_id=? AND status='verified' "
                "ORDER BY risk DESC, type", (run_id,)).fetchall()
            rec = c.execute(
                "SELECT * FROM findings WHERE run_id=? AND status='rejected'", (run_id,)).fetchall()
        return {"run_id": r["run_id"], "seed": r["seed"], "scanner": r["scanner"],
                "target": r["target"], "started": r["started"],
                "stats": json.loads(r["stats_json"] or "{}"),
                "attack_chains": json.loads(r["attack_chains_json"] or "[]"),
                "findings": [self._finding_row(f) for f in fs],
                "rejected_candidates": [self._finding_row(f) for f in rec]}

    @staticmethod
    def _finding_row(f) -> dict:
        # risk_components: only round-10 rows carry it, and only this module
        # writes it (always valid JSON) — a NULL reads as absent; anything
        # corrupt fails LOUD here rather than degrading to a silent None.
        comps = json.loads(f["risk_components"]) if f["risk_components"] else None
        return {"id": f["id"], "type": f["type"], "severity": f["severity"],
                "status": f["status"], "url": f["url"], "parameter": f["parameter"],
                "method": f["method"], "confidence": f["confidence"], "risk": f["risk"],
                "fingerprint": f["fingerprint"],
                "identity": f["identity"], "endpoint": f["endpoint"],
                "lifecycle": f["lifecycle"],
                "risk_score": f["risk_score"], "risk_components": comps,
                "evidence": json.loads(f["evidence_json"] or "[]"),
                "verification": json.loads(f["verification_json"] or "{}")}

    def list_findings(self, run_id: str = "", type_: str = "", min_risk: int = 0,
                      status: str = "verified", limit: int = 200) -> list[dict]:
        q = "SELECT * FROM findings WHERE status=?"
        args: list = [status]
        if run_id:
            q += " AND run_id=?"; args.append(run_id)
        if type_:
            q += " AND type=?"; args.append(type_)
        if min_risk:
            q += " AND risk>=?"; args.append(min_risk)
        q += " ORDER BY risk DESC, first_seen DESC LIMIT ?"; args.append(limit)
        with self._conn() as c:
            return [self._finding_row(f) for f in c.execute(q, args).fetchall()]

    # ---------------------------------------------------------------- intelligence
    def recurring(self, status: str = "verified") -> list[dict]:
        """Fingerprints confirmed in MORE THAN ONE run — the same vulnerability came
        back after (supposedly) being fixed, or persists across releases."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT fingerprint, type, url, parameter, COUNT(DISTINCT run_id) AS n_runs, "
                "       MIN(first_seen) AS first_seen, MAX(first_seen) AS last_seen "
                "FROM findings WHERE status=? GROUP BY fingerprint HAVING n_runs > 1 "
                "ORDER BY n_runs DESC, last_seen DESC", (status,)).fetchall()
        return [dict(r) for r in rows]

    def delta(self, run_a: str = "", run_b: str = "", status: str = "verified") -> dict:
        """Diff two runs (default: the two most recent). new = in B not A (fresh vuln
        or fix-regression of something previously remediated elsewhere), fixed = in A
        not B, recurring = in both."""
        with self._conn() as c:
            def _pick(rid, order):
                if rid:
                    return rid
                r = c.execute(f"SELECT run_id FROM runs ORDER BY started {order} LIMIT 1").fetchone()
                return r["run_id"] if r else ""
            a, b = _pick(run_a, "ASC" if run_a else "DESC"), _pick(run_b, "ASC" if run_b else "DESC")
            # default: A = previous (2nd newest), B = newest
            if not run_a and not run_b:
                runs = c.execute("SELECT run_id FROM runs ORDER BY started DESC LIMIT 2").fetchall()
                b = runs[0]["run_id"] if runs else ""
                a = runs[1]["run_id"] if len(runs) > 1 else b
            if not a or not b:
                return {"run_a": a, "run_b": b, "new": [], "fixed": [], "recurring": []}

            def fps(rid):
                return {r["fingerprint"]: r["type"] for r in
                        c.execute("SELECT fingerprint, type FROM findings WHERE run_id=? AND status=?",
                                  (rid, status)).fetchall()}
            fa, fb = fps(a), fps(b)
        return {"run_a": a, "run_b": b,
                "new": sorted(set(fb) - set(fa)), "fixed": sorted(set(fa) - set(fb)),
                "recurring": sorted(set(fa) & set(fb))}

    def stats_summary(self) -> dict:
        with self._conn() as c:
            runs = c.execute("SELECT COUNT(*) AS n FROM runs").fetchone()["n"]
            by_type = {r["type"]: r["n"] for r in c.execute(
                "SELECT type, COUNT(*) AS n FROM findings WHERE status='verified' "
                "GROUP BY type ORDER BY n DESC").fetchall()}
            by_sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE status='verified' "
                "GROUP BY severity").fetchall()}
            targets = c.execute("SELECT COUNT(DISTINCT target) AS n FROM runs").fetchone()["n"]
        return {"runs": runs, "targets_scanned": targets,
                "verified_findings": sum(by_type.values()),
                "by_type": by_type, "by_sev": by_sev,
                "recurring_fingerprints": len(self.recurring())}

    # ------------------------------------------------- round 10, part 1: lifecycle
    def previous_run_id(self, target: str, before_run_id: str = "",
                        status: str = "verified") -> str:
        """The newest run of THIS target (excluding the given run) that has
        findings — the run a new run's lifecycle is diffed against. Empty
        for a target's first run."""
        with self._conn() as c:
            q = ("SELECT run_id FROM runs WHERE target=? AND run_id<>? AND "
                 "run_id IN (SELECT DISTINCT run_id FROM findings WHERE status=?) "
                 "ORDER BY started DESC LIMIT 1")
            r = c.execute(q, (target, before_run_id, status)).fetchone()
        return r["run_id"] if r else ""

    def record_lifecycle(self, run_id: str, target: str,
                         resolved: dict) -> None:
        """Persist the resolver's full decision set for one run: every
        identity's resolved state (present: NEW/RECURRING/REGRESSED; absent
        with coverage: FIXED; absent without coverage: UNTESTED_ABSENCE).
        The log — not the findings rows — is the lifecycle source of truth,
        because a FIXED identity has no finding row to carry its state."""
        now = time.time()
        present = resolved.get("present_states") or {}
        endpoints = resolved.get("present_endpoints") or {}
        with self._conn() as c:
            c.executemany(
                "INSERT OR REPLACE INTO lifecycle_log VALUES (?,?,?,?,?,?)",
                [(run_id, target, ident, present.get(ident, ""),
                  endpoints.get(ident, ""), now)
                 for ident in present])
            c.executemany(
                "INSERT OR REPLACE INTO lifecycle_log VALUES (?,?,?,?,?,?)",
                [(run_id, target, ident, "FIXED", endpoint, now)
                 for ident, endpoint in (resolved.get("fixed") or {}).items()])
            c.executemany(
                "INSERT OR REPLACE INTO lifecycle_log VALUES (?,?,?,?,?,?)",
                [(run_id, target, ident, "UNTESTED_ABSENCE", "", now)
                 for ident in resolved.get("untested_absences", [])])

    def lifecycle_history(self, target: str, exclude_run: str = "") -> dict:
        """The lifecycle memory for one target (all runs recorded so far,
        excluding the given run):
          ever_seen        identities this target produced in ANY prior run
          latest_state     identity -> most recently recorded state (the
                           'was FIXED' memory behind REGRESSED)
          prev_run_present identity -> endpoint, for the immediately
                           previous findings-run of this target
        Legacy pre-round-10 stores simply have no rows here — the first
        run that records resolutions builds the memory."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT identity, state, resolved_at FROM lifecycle_log "
                "WHERE target=? AND run_id<>? ORDER BY resolved_at ASC",
                (target, exclude_run)).fetchall()
            ever_seen = set()
            latest_state: dict[str, str] = {}
            for r in rows:
                ever_seen.add(r["identity"])
                latest_state[r["identity"]] = r["state"]
            prev_run = self.previous_run_id(target, exclude_run)
            prev_present: dict[str, str] = {}
            if prev_run:
                for r in c.execute(
                        "SELECT identity, endpoint FROM lifecycle_log "
                        "WHERE run_id=? AND state IN ('NEW','RECURRING','REGRESSED')",
                        (prev_run,)).fetchall():
                    prev_present[r["identity"]] = r["endpoint"] or ""
        return {"ever_seen": ever_seen, "latest_state": latest_state,
                "prev_run_present": prev_present}

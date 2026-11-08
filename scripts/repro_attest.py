#!/usr/bin/env python3
"""PART 4B — reproducibility attestation for the canonical fixture scan.

Two GENUINELY separate executions (each step spawns its own fixture
process and its own engine process) must produce a byte-identical
finding set. The compare step is a HARD GATE: any mismatch fails CI.

Usage (three separate process invocations — do not merge):
  python3 scripts/repro_attest.py --tag a --out-dir "$RUNNER_TEMP/repro"
  python3 scripts/repro_attest.py --tag b --out-dir "$RUNNER_TEMP/repro"
  python3 scripts/repro_attest.py --compare "$RUNNER_TEMP/repro"

What is asserted by --compare (all three must match exactly):
  merkle_root       Merkle root over the canonical findings (volatile keys
                    stripped — the designed stable root)
  findings_count    number of findings
  findings_sha256   SHA-256 over the concatenated canonical finding bytes
                    (the FULL finding set, byte-identical or the gate fails)

run_id intentionally differs between executions (it is a per-run random
identity, not part of the determinism claim) and is recorded as
informational only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# R17-8: extend-inherited + scoped-neutralization spawn env (the same
# contract as ci_fixture_run.py — see the full rationale there; Windows
# Winsock needs SYSTEMROOT, and vulnapp's behavioral vars must stay
# neutralized to protect the deterministic record under test HERE).
from burhan.fixture_env import fixture_env  # noqa: E402

PORTS = {"a": 8777, "b": 8777}   # SAME target URL for both executions —
                                   # the finding url/id/OAST-iid fields are
                                   # URL-derived; different ports = different
                                   # findings (the first gate run caught exactly
                                   # that, in its own script, 2026-10-31)


def run_scan(tag: str, out_dir: Path) -> dict:
    """Spawn the fixture + run the canonical full-platform configuration
    (the exact ScanConfig of scripts/ci_fixture_run.py)."""
    port = PORTS[tag]
    base = f"http://127.0.0.1:{port}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # PRE-FLIGHT (2026-10-31, diagnosed live): an ACTIVE LISTENER on the port
    # would silently capture the scan (a stale fixture did exactly that) —
    # fail loudly. SO_REUSEADDR mirrors the fixture's own bind semantics, so
    # TIME_WAIT remnants from the previous execution (7k+ connections) do
    # NOT trip the check — only a real listener does.
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as exc:
        raise SystemExit(
            f"[{tag}] FATAL: port {port} has an active listener ({exc}) — a "
            f"stale fixture would silently capture this scan. Kill it and retry.")
    finally:
        sock.close()

    fixture = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env=fixture_env(port),
        stdout=open(out_dir / f"fixture-{tag}.log", "w"),
        stderr=subprocess.STDOUT)
    # r18-8.9: single 5s-shot probe is a Linux-shaped assumption — the
    # macOS runner (run 7, job ...128732062786) took longer than sleep
    # 1.5 + timeout 5 to accept the first connection, and the step died
    # 6.7s in with URLError before the scan ever started. Same doctrine
    # as the r18-8.2 readiness windows: poll until the fixture answers
    # or the process dies, with a hard bound. 60s covers cold APFS/spot
    # first-launch costs; 1.5s was tuned on Linux.
    import urllib.error
    deadline = time.time() + 60.0
    probe_exc = None
    while time.time() < deadline:
        if fixture.poll() is not None:
            tail = ""
            try:
                tail = (out_dir / f"fixture-{tag}.log").read_text()[-500:]
            except Exception:  # noqa: BLE001 — diagnostics only
                pass
            raise SystemExit(
                f"[{tag}] FATAL: fixture exited rc={fixture.returncode} "
                f"before answering — fixture log tail:\n{tail}")
        try:
            probe = urllib.request.urlopen(base + "/", timeout=5).status
            assert probe == 200, probe
            probe_exc = None
            break
        except (urllib.error.URLError, AssertionError, OSError) as exc:
            probe_exc = exc
            time.sleep(0.5)
    if probe_exc is not None:
        raise SystemExit(
            f"[{tag}] FATAL: fixture never answered within 60s "
            f"({type(probe_exc).__name__}: {probe_exc}) — see "
            f"{out_dir / f'fixture-{tag}.log'}")
    print(f"[{tag}] fixture up on {base} (pid {fixture.pid}) — liveness verified")

    from burhan.auth import AuthProfile
    from burhan.core import EventBus, ScopeRule  # noqa: F401
    from burhan.oast import OastServer
    from burhan.orchestrator import ScanConfig, BurhanScanner

    auth = AuthProfile(login_url=base + "/login", username="demo",
                       password="demo123", user_field="uid", pass_field="passw",
                       success_marker="Sign Off")
    authz_cfg = json.load(open(ROOT / "benchmarks" / "authz_accounts.json"))
    oast = OastServer()
    t0 = time.time()
    try:
        cfg = ScanConfig(allow_private=True, max_pages=40, timeout=12.0,
                         seed="bench430" * 8, oast=oast, auth=auth,
                         authz=authz_cfg, workflow=True, logic_active=True,
                         max_requests=0, race=True, race_parallel=10,
                         race_variance=0.005, symbolic=True)
        rep = BurhanScanner(base, cfg).run()
    finally:
        oast.stop()
        # release the port so execution B can bind the SAME one (same target
        # URL is the point of the attestation)
        fixture.terminate()
        try:
            fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            fixture.kill()

    # persist the full report for the artifact, compute the attestation
    (out_dir / f"scan-{tag}.json").write_text(
        json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")

    from burhan.audit import canonical_finding, merkle_root_of_records
    findings = rep["findings"]
    canonical_blob = b"".join(
        canonical_finding(f).encode("utf-8") for f in findings)
    attestation = {
        "tag": tag,
        "run_id": rep.get("run_id", ""),
        "seed": rep.get("seed", ""),
        "scanner": rep.get("scanner", ""),
        "target": rep.get("target", ""),
        "merkle_root": merkle_root_of_records(findings),
        "findings_count": len(findings),
        "findings_sha256": hashlib.sha256(canonical_blob).hexdigest(),
        "wall_seconds": round(time.time() - t0, 1),   # informational only
    }
    (out_dir / f"attestation-{tag}.json").write_text(
        json.dumps(attestation, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"[{tag}] scan done in {attestation['wall_seconds']}s: "
          f"findings={len(findings)} root={attestation['merkle_root'][:16]}…")
    return attestation


def compare(out_dir: Path) -> int:
    a = json.loads((out_dir / "attestation-a.json").read_text(encoding="utf-8"))
    b = json.loads((out_dir / "attestation-b.json").read_text(encoding="utf-8"))
    checks = {
        "merkle_root": a["merkle_root"] == b["merkle_root"],
        "findings_count": a["findings_count"] == b["findings_count"],
        "findings_sha256": a["findings_sha256"] == b["findings_sha256"],
    }
    verdict = {
        "run_a": a, "run_b": b, "checks": checks,
        "reproducible": all(checks.values()),
        "assertion": ("merkle_root == merkle_root AND findings_count == "
                      "findings_count AND findings_sha256 == findings_sha256"),
    }
    (out_dir / "attestation.json").write_text(
        json.dumps(verdict, indent=1, ensure_ascii=False), encoding="utf-8")

    print(f"run A: root={a['merkle_root']} count={a['findings_count']} "
          f"sha={a['findings_sha256']}")
    print(f"run B: root={b['merkle_root']} count={b['findings_count']} "
          f"sha={b['findings_sha256']}")
    for name, ok in checks.items():
        print(f"  {'MATCH  ' if ok else 'DIFFER '}: {name}")
    print(f"REPRODUCIBLE: {verdict['reproducible']}")

    # GitHub step summary (shown on the run page)
    summary = out_dir / "step-summary.md"
    if summary.parent.exists():
        rows = "\n".join(
            f"| {n} | {'match' if ok else '**DIFFER**'} |"
            for n, ok in checks.items())
        summary.write_text(
            "### Reproducibility attestation\n\n"
            "| check | result |\n|---|---|\n" + rows +
            f"\n\n**Byte-identical finding sets: "
            f"{verdict['reproducible']}**\n", encoding="utf-8")

    return 0 if verdict["reproducible"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tag", choices=["a", "b"])
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--compare", type=Path, metavar="DIR",
                    help="compare attestation-a.json vs attestation-b.json")
    args = ap.parse_args()
    if args.compare:
        return compare(args.compare)
    if not args.tag or not args.out_dir:
        ap.error("--tag + --out-dir, or --compare DIR")
    run_scan(args.tag, args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

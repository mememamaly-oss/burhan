#!/usr/bin/env python3
"""P4.4 — local end-to-end chain test for the PART-4 live script.

Proves scripts/live_validate_modern2.py itself (not just the engine
layers — those carry their own RED/BLUE pytest files) runs end to end
against the vulnapp fixture, verdict JSON included:

  RED  vulnapp armed (BFLA=1 SHADOW=1 SIGNOFF=1 CONFUSION=1
       RACE_MODE=broken) + the RED spec (declares every fixture /api
       route EXCEPT /api/v2/internal/telemetry, plus one
       deprecated:true path that is still live, plus one
       declared-but-never-deployed path):
         - 3G shadow MUST fire on telemetry (the single undeclared
           crawl-discovered JSON route)
         - 3G zombie MUST fire (dead declaration /gone/v2/x → 404;
           deprecated-but-alive /api/v1/users → 200)
         - the verdict JSON scores shadow/zombie confirmed-positive
         - the authz battery records its honest 404 login_errors
           (crAPI accounts do not exist on vulnapp) and the race
           candidate records TESTED_NEGATIVE (404 endpoint, 0 winners)
  BLUE vulnapp hardened (no env) + the BLUE spec (the full /api
       inventory declared, nothing deprecated, nothing dead):
         - 3G must stay SILENT (zero shadow, zero zombie) and record
           the "spec and live surface agree" boundary

The spec pair is the point: the ONLY difference between RED and BLUE is
the spec content and the fixture arming — exactly what the family
claims to detect. --max-requests 12000: the dense fixture exhausts the
default 2000 long before the m2 confirm probes, and a refused probe
(HTTP 0) records a false TESTED_NEGATIVE (the P4.4 catch that made
--max-requests a script flag in the first place).

Exit 0 = the chain holds. Any assertion failure exits non-zero.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "live_validate_modern2.py"

# the fixture's ENTIRE /api inventory (routes verified in
# fixtures/vulnapp.py do_GET/do_POST). /api/ and /api/users are NOT real
# fixture routes (404 live — crawled links only): declaring them would
# fabricate zombie-dead findings against a lying spec, the exact mistake
# this BLUE leg must not contain. BLUE declares all of them -> zero
# shadow candidates possible. RED declares all EXCEPT telemetry.
_API_PATHS = {
    "/api/account/dashboard": "get",
    "/api/data": "get",
    "/api/secure/data": "get",
    "/api/v1/users": "get",
    "/api/admin/stats": "get",
    "/api/secure/admin/stats": "get",
    "/api/filter": "get",
    "/api/nosql-lockout": "post",
    "/api/admin/rotate-keys": "post",
    "/api/secure/admin/rotate-keys": "post",
    "/api/coupon/redeem": "post",
}


def _spec(paths: dict, deprecated: set = frozenset()) -> dict:
    out = {}
    for p, m in paths.items():
        op = {"summary": p}
        if p in deprecated:
            op["deprecated"] = True
        out[p] = {m: op}
    return {
        "openapi": "3.0.3",
        "info": {"title": "chain-smoke-spec", "version": "smoke"},
        "paths": out,
    }


def red_spec() -> dict:
    """Everything except telemetry; /api/v1/users deprecated:true;
    /gone/v2/x declared but never deployed. Zombie probes read the spec
    in insertion order — the two interesting paths go FIRST so they sit
    well inside ZOMBIE_PROBE_CAP=8."""
    paths = {"/gone/v2/x": "get", "/api/v1/users": "get"}
    paths.update(_API_PATHS)
    return _spec(paths, deprecated={"/api/v1/users"})


def blue_spec() -> dict:
    """The full inventory (telemetry included — it EXISTS in the
    fixture code even when unlinked), nothing deprecated, nothing
    dead."""
    paths = dict(_API_PATHS)
    paths["/api/v2/internal/telemetry"] = "get"
    return _spec(paths)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _spawn(env_extra: dict | None):
    port = _free_port()
    env = {**os.environ, "PORT": str(port), **(env_extra or {})}
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "fixtures" / "vulnapp.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if proc.poll() is not None:
            raise SystemExit("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            return port, proc
        except OSError:
            time.sleep(0.25)
    proc.terminate()
    raise SystemExit("vulnapp fixture never became reachable")


def _run_script(base: str, spec_path: str, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    # 12000 budget: the armed fixture's crawl+active exhausts the default
    # 2000 long before the m2 confirm probes — every refused probe (HTTP
    # 0) records a false TESTED_NEGATIVE (the P4.4 catch; the flag exists
    # for exactly this case)
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--crapi", base,
         "--crapi-spec", spec_path, "--out-dir", str(out_dir),
         "--max-requests", "12000"],
        capture_output=True, text=True, timeout=600)
    print(f"--- script exit {r.returncode} ---")
    print(r.stdout[-3000:])
    if r.returncode != 0:
        print(r.stderr[-3000:])
    return r


def _verdict(out_dir: Path) -> dict:
    return json.loads((out_dir / "live-validation.json").read_text())


def _fam_types(res: dict) -> set:
    return {f["type"] for f in res["modern2_findings"]}


def _fam_boundaries(res: dict) -> dict:
    out = {}
    for b in res["boundaries"]:
        out.setdefault(b.get("family"), set()).add(b.get("kind"))
    return out


def _write_spec(spec: dict) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False)
    json.dump(spec, f)
    f.close()
    return f.name


def main() -> int:
    red_spec_file, blue_spec_file = _write_spec(red_spec()), \
        _write_spec(blue_spec())

    # ---------------- RED: every new surface armed ----------------
    port, proc = _spawn({"BFLA": "1", "SHADOW": "1", "SIGNOFF": "1",
                         "CONFUSION": "1", "RACE_MODE": "broken"})
    base = f"http://127.0.0.1:{port}"
    red_out = Path(tempfile.mkdtemp(prefix="p44-red-"))
    try:
        r = _run_script(base, red_spec_file, red_out)
        assert r.returncode == 0, "RED script run must exit 0"
        v = _verdict(red_out)
        res = v["results"]["crapi"]
        types = _fam_types(res)
        print("RED modern2 finding types:", sorted(types))
        print("RED boundaries:", json.dumps(_fam_boundaries(res), default=list))
        # 3G shadow: telemetry is the single undeclared crawl-discovered
        # JSON route — it MUST fire
        assert "shadow_api_endpoint" in types, \
            "3G shadow must fire on the armed fixture (SHADOW=1, telemetry undeclared)"
        # 3G zombie: both directions — dead declaration + deprecated-alive
        assert "zombie_api_endpoint" in types, \
            "3G zombie must fire (spec deprecated path live + declared-dead path 404)"
        # the race plumbing fired (vulnapp 404s the crAPI candidate —
        # the honest TESTED_NEGATIVE boundary must still be recorded)
        fam_b = _fam_boundaries(res)
        assert "race_condition" in fam_b, \
            "3F plumbing must record its boundary even on a 404 candidate"
        # authz ran honestly (crAPI accounts 404 on vulnapp — recorded,
        # not crashed)
        st = res["axes"].get("authz", {})
        assert st.get("accounts_configured") == 2, \
            f"the authz battery must have been configured: {st}"
        # scoring round-trip: shadow/zombie judged confirmed-positive
        # against the recorded ground truth
        verdicts = {s["type"]: s["verdict"]
                    for s in v["scores"]["crapi"]["confirmed_positive"]}
        print("RED confirmed-positive:", verdicts)
        assert "shadow_api_endpoint" in verdicts
        assert "zombie_api_endpoint" in verdicts
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    # ---------------- BLUE: hardened fixture + full spec ----------------
    port, proc = _spawn(None)
    base = f"http://127.0.0.1:{port}"
    blue_out = Path(tempfile.mkdtemp(prefix="p44-blue-"))
    try:
        r = _run_script(base, blue_spec_file, blue_out)
        assert r.returncode == 0, "BLUE script run must exit 0"
        v = _verdict(blue_out)
        res = v["results"]["crapi"]
        types = _fam_types(res)
        print("BLUE modern2 finding types:", sorted(types))
        print("BLUE boundaries:", json.dumps(_fam_boundaries(res), default=list))
        # nothing undeclared, nothing deprecated, nothing dead: 3G must
        # record the honest "agree" boundary and fire NOTHING
        assert "shadow_api_endpoint" not in types and \
            "zombie_api_endpoint" not in types, \
            "3G must stay silent on the hardened fixture + full spec"
        fam_b = _fam_boundaries(res)
        assert "TESTED_NEGATIVE" in fam_b.get("shadow_api", set()), \
            "3G must record the spec/live-agree boundary on BLUE"
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    os.unlink(red_spec_file)
    os.unlink(blue_spec_file)
    print("P4.4 LOCAL CHAIN: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

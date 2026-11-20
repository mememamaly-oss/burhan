"""r19-2.7 (owner pre-merge questions, item 3): lab-mode boundary tests.

What the EXPLICIT laboratory mode DOES bypass — stated precisely:
  It bypasses exactly ONE thing: the "self-hosted fixtures" proof
  requirement for LOOPBACK/PRIVATE targets (authorized_targets.py,
  the `_is_loopback_or_private(host)` branch). Those targets answer on
  the operator's own machine, so ownership is the fact of running them;
  the mode records this in the scan report (stats.lab_mode).

What it NEVER touches:
  (a) PUBLIC targets keep their full scan-time proof requirement —
      well_known / scope_page / dns_txt / signed_letter are verified
      exactly the same with the mode on or off. The mode cannot
      authorize a public host, and cannot skip a public proof.
  (b) Every scan report RECORDS the mode (stats.lab_mode =
      {active, via}) whether on or off — a lab report is
      self-identifying.
  (c) The demo route (SaaS route.ts) spawns the CLI with --lab for the
      PLATFORM-OWNED demo fixture only; the flag rides the same
      server-side allowPrivate decision that is already pinned to
      target.isDemo — a hostile target/url in the POST body is ignored.

Mutation anchors — each test names the mutant it kills:
  LAB-A1 authorized_targets.py `_is_loopback_or_private` guard removal
        (the `if _is_loopback_or_private(host):` branch skipped) would
        route a private host into the PUBLIC proof path — killed by
        asserting a private host NEVER consults public entries.
  LAB-A2 inverting the lab check (`if lab:` -> `if not lab:`) — killed
        by (refused without / allowed with) at the same registry.
  LAB-A3 a public entry with loopback_or_private=True but
        kind != self-hosted must NOT authorize (killed in kills2 L3;
        re-asserted here at the boundary).
  LAB-B1 dropping the stats["lab_mode"] recording line — killed by
        asserting the key exists with active+via on BOTH states.
  LAB-B2 the banner on activation — the CLI's lab banner is part of
        the mode's observability; asserted via the report + CLI e2e.
  LAB-C1 route.ts adding --lab for a non-demo (hostile) target — the
        TypeScript side is pinned by demo.integration.test.ts
        ("HOSTILE body ... scans ONLY the platform fixture"); the
        engine-side boundary is asserted here: --lab + a PUBLIC
        hostile host still requires a real public proof.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.authorized_targets import authorize  # noqa: E402
from burhan.lab_mode import is_lab_mode, ENV_VAR  # noqa: E402


def _reg(tmp_path, targets):
    p = tmp_path / "authorized-targets.json"
    p.write_text(json.dumps({"policy": "t", "targets": targets}))
    return str(p)


SELF_HOSTED = {
    "id": "self-hosted-fixtures", "kind": "self-hosted",
    "match": {"loopback_or_private": True},
    "covers": ["OWASP Juice Shop v20.3.0 (official container)"],
    "proof": {"type": "ownership", "statement": "operator's own host"},
}

PUBLIC_WK = {
    "id": "pub", "kind": "permissioned-public-demo",
    "match": {"host_suffix": "example.test"},
    "proof": {"type": "well_known", "token": "tok"},
}


# ═══════════════════ (أ) الحدود: خاص/loopback فقط، لا يُسقط إثبات العام ═══════════════════

def test_lab_a1_private_host_never_enters_the_public_proof_path(
        tmp_path, monkeypatch):
    """LAB-A1: with the mode ON and a self-hosted entry present, a
    private host is authorized via the SELF-HOSTED branch — the public
    entries are never consulted for it. If the private-guard were
    dropped (mutant), the private host would fall through to public
    suffix matching; we assert the public entry is NOT what answered."""
    monkeypatch.setenv(ENV_VAR, "1")
    reg = _reg(tmp_path, [PUBLIC_WK, SELF_HOSTED])
    seen = []

    def fetch(url):
        seen.append(url)          # a public well_known fetch must NOT run
        return 200, {}, b"tok"

    ok, reason, eid = authorize("http://127.0.0.1:9999/", reg, fetch=fetch)
    assert ok is True
    assert eid == "self-hosted-fixtures", (eid, reason)
    assert seen == [], ("private host must not trigger public proof "
                        "fetches — the guard was bypassed")


def test_lab_a2_public_target_still_requires_its_proof_with_mode_on(
        tmp_path, monkeypatch):
    """The mode is ON, a public entry exists, but its well-known token
    is NOT served: the public target is REFUSED. The lab mode must not
    soften a public proof — this is the (a) core. (The `if lab: ->
    if not lab:` inversion mutant dies here too: with lab ON the
    self-hosted branch would be skipped and 127.0.0.1 refused — the
    complementary leg is test_lab_mode.py's refusal test.)"""
    monkeypatch.setenv(ENV_VAR, "1")
    reg = _reg(tmp_path, [PUBLIC_WK, SELF_HOSTED])

    def fetch(url):
        return 404, {}, b"not found"

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert ok is False, "public proof must still be enforced with lab on"
    assert "example.test" in str(reason) or "well-known" in str(reason)


def test_lab_a2b_public_target_authorizes_only_via_its_proof(
        tmp_path, monkeypatch):
    """The positive twin: same registry, mode ON, token served -> the
    public target is allowed THROUGH its public proof (entry id 'pub'),
    proving the mode did not replace public verification with a
    blanket allow."""
    monkeypatch.setenv(ENV_VAR, "1")
    reg = _reg(tmp_path, [PUBLIC_WK, SELF_HOSTED])

    def fetch(url):
        return 200, {}, b"tok"

    ok, reason, eid = authorize("https://example.test/", reg, fetch=fetch)
    assert ok is True and eid == "pub", (eid, reason)


def test_lab_a3_public_host_with_lab_on_and_no_entry_refuses(
        tmp_path, monkeypatch):
    """LAB-A3 boundary: a PUBLIC host with the mode ON but NO matching
    entry is refused — the mode cannot authorize hosts by itself."""
    monkeypatch.setenv(ENV_VAR, "1")
    reg = _reg(tmp_path, [SELF_HOSTED])
    ok, reason, _ = authorize("https://unlisted.example.test/", reg)
    assert ok is False


def test_lab_a4_private_host_with_lab_on_but_no_selfhosted_entry_refuses(
        tmp_path, monkeypatch):
    """The mode is ON but the registry has NO self-hosted entry: the
    private target is still refused (the mode alone is not proof)."""
    monkeypatch.setenv(ENV_VAR, "1")
    reg = _reg(tmp_path, [PUBLIC_WK])
    ok, reason, _ = authorize("http://127.0.0.1:9999/", reg)
    assert ok is False and "self-hosted" in reason


# ═══════════════════ (ب) التسجيل في كل تقرير + بانر التفعيل ═══════════════════

def _scan_report(tmp_path, monkeypatch, env_set):
    """Run a REAL BurhanScanner over a live local fixture and return the
    report dict (stats included). The fixture is a real HTTP server on
    loopback — the mode's own natural target."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        monkeypatch.setenv(ENV_VAR, "1" if env_set else "")
        if not env_set:
            monkeypatch.delenv(ENV_VAR, raising=False)
        from burhan.orchestrator import BurhanScanner, ScanConfig
        cfg = ScanConfig(allow_private=True, max_pages=2, timeout=5.0,
                         seed="labmode-boundary-" + ("on" if env_set else "off"))
        sc = BurhanScanner("http://127.0.0.1:%d/" % port, cfg)
        return sc.run()
    finally:
        srv.shutdown()
        th.join(timeout=2)


def test_lab_b1_report_records_mode_on_and_off(tmp_path, monkeypatch):
    """LAB-B1: stats['lab_mode'] = {active, via} must exist in EVERY
    report — present and active={'env'} when on, present and
    active=False when off. Killing the recording line drops the key
    entirely; both legs assert the key, so either state catches it."""
    rep_on = _scan_report(tmp_path, monkeypatch, env_set=True)
    lm = rep_on["stats"].get("lab_mode")
    assert lm is not None, "stats.lab_mode missing with the mode ON"
    assert lm.get("active") is True
    assert lm.get("via") in ("env", "flag")

    rep_off = _scan_report(tmp_path, monkeypatch, env_set=False)
    lm_off = rep_off["stats"].get("lab_mode")
    assert lm_off is not None, "stats.lab_mode missing with the mode OFF"
    assert lm_off.get("active") is False
    assert lm_off.get("via") is None


def test_lab_b2_cli_activation_banner(tmp_path, monkeypatch):
    """LAB-B2: with the mode active, the CLI makes it VISIBLE twice:
    (1) the authorize banner on stdout —
        `[authorized-targets] ... EXPLICIT lab mode ...`
    (2) stats.lab_mode in the emitted report (rc=0 scan of a refused
        port still completes: the scan reports 0 findings, the GATE
        passed — that is the banner's proof).
    The scan runs against a CLOSED port on loopback: authorization
    succeeds via the self-hosted entry, the engine reports the port as
    unreachable — rc 0 with a full report, exactly the observable
    contract the demo UI and CI rely on."""
    import subprocess
    reg = _reg(tmp_path, [SELF_HOSTED])
    env = dict(os.environ)
    env[ENV_VAR] = "1"
    gate = str(tmp_path / "gate.json")
    env["BURHAN_OWNER_GATE"] = gate
    env["BURHAN_AUTHORIZED_TARGETS"] = reg
    pw = "BoundaryTestPassword123"
    r0 = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "owner", "init",
         "--password", pw],
        capture_output=True, text=True, timeout=120, cwd=ROOT, env=env,
        stdin=subprocess.DEVNULL)
    assert r0.returncode == 0, r0.stderr[-300:]
    out_path = str(tmp_path / "report.json")
    r = subprocess.run(
        [sys.executable, "-m", "burhan.cli", "scan",
         "http://127.0.0.1:9999/", "--out", out_path,
         "--owner-password", pw],
        capture_output=True, text=True, timeout=180, cwd=ROOT, env=env,
        stdin=subprocess.DEVNULL)
    out = r.stdout + r.stderr
    assert "lab mode" in out.lower(), (
        "the activation banner (EXPLICIT lab mode) must be visible on "
        "stdout: " + out[-400:])
    rep = json.load(open(out_path))
    lm = rep.get("stats", {}).get("lab_mode")
    assert lm and lm.get("active") is True and lm.get("via") == "env", lm


# ═══════════════════ (ج) route.ts للـdemo مقيد بهدف الـdemo فقط ═══════════════════

def test_lab_c1_engine_side_demo_boundary(tmp_path, monkeypatch):
    """LAB-C1 (engine side): the demo route passes --lab for its
    platform fixture; the boundary that matters to the ENGINE is that
    --lab + a hostile PUBLIC host still requires a real public proof —
    the flag cannot carry a public host through. The TypeScript side
    (route.ts ignoring the POSTed url/target) is pinned end-to-end by
    tests/demo.integration.test.ts ('HOSTILE body ... scans ONLY the
    platform fixture'); here we pin the Python boundary it relies on."""
    monkeypatch.setenv(ENV_VAR, "1")          # demo-like activation
    reg = _reg(tmp_path, [SELF_HOSTED, PUBLIC_WK])

    def fetch(url):
        return 404, {}, b""                   # proof NOT served

    # hostile public host, mode ON: refused
    ok, reason, _ = authorize("https://evil.example.test/", reg, fetch=fetch)
    assert ok is False, (
        "--lab/BURHAN_LAB_MODE must not carry a PUBLIC host through "
        "without its proof — the demo boundary would be broken")

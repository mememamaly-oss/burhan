"""Round-9 pins — the master-password step-up gate (part 2) and the
propose-and-prove remediation pipeline (part 3).

P2.2: the PAIRED proof — the gated action without the step-up credential
fails AND lands in the tamper-evident chain; with the credential it
succeeds AND lands in the chain.

P3.2: the REAL RED->BLUE — a live clone of the fixture: the original
exploit reproduced on the unpatched clone (RED), the patch applied to the
clone only, the SAME exploit re-run on the patched clone and observed to
FAIL (BLUE). Plus 3.1's hard rule proven enforced IN CODE (IsolationViolation
with the exact host:port check), the 3.4 report-only fallback, and the
no-merge-code-path guarantee asserted at module level.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from burhan.remediation import (IsolationViolation, RemediationRefused,
                                assert_isolated, build_patch,
                                reflection_probe, run_remediation)
from burhan.stepup import (GENESIS, StepUpChainTampered, StepUpGate,
                           StepUpRateLimited, StepUpRequired,
                           generate_master_secret)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "R9-test-step-up-secret-32-bytes-minimum!!"


@pytest.fixture()
def gate(tmp_path):
    return StepUpGate.setup(str(tmp_path / "stepup-store.json"), SECRET)


# ================= P2.2 — the paired step-up proof ===========================

def test_paired_gate_proof_without_then_with(gate, tmp_path):
    """THE 2.2 paired proof. Without the credential: the gated action
    REFUSES and the refusal is IN THE CHAIN. With it: the action runs and
    the grant is IN THE CHAIN. One store, both sides, in order."""
    # --- RED side: no credential -> refused + logged
    calls = []

    def _action(cred):
        gate.require("patch_generation", cred)
        calls.append("ran")

    with pytest.raises(StepUpRequired, match="step-up credential"):
        _action(None)
    assert calls == []                      # the action did NOT run
    ev = gate._load()["events"]
    assert len(ev) == 1 and ev[0]["ok"] is False
    assert ev[0]["purpose"] == "patch_generation"
    assert "not supplied" in ev[0]["detail"]

    # --- BLUE side: the credential -> granted + logged
    _action(SECRET)
    assert calls == ["ran"]
    ev = gate._load()["events"]
    assert len(ev) == 2 and ev[-1]["ok"] is True
    assert ev[-1]["purpose"] == "patch_generation"

    # the chain covers BOTH sides and verifies end-to-end
    assert gate.verify_chain() == 2


def test_wrong_secret_is_refused_and_logged(gate):
    with pytest.raises(StepUpRequired, match="wrong step-up credential"):
        gate.require("closure_reexploit", "not-the-secret")
    ev = gate._load()["events"]
    assert ev[-1]["ok"] is False and "mismatch" in ev[-1]["detail"]
    assert ev[-1]["purpose"] == "closure_reexploit"


def test_rate_limit_sliding_window(gate):
    """5 wrong attempts inside the window -> the 6th is refused by RATE
    LIMIT (the secret is not even compared), and the lock is recorded."""
    for i in range(5):
        with pytest.raises(StepUpRequired):
            gate.require("patch_generation", f"wrong-{i}")
    with pytest.raises(StepUpRateLimited, match="rate-limited|closed"):
        gate.require("patch_generation", SECRET)
    ev = gate._load()["events"]
    assert sum(1 for e in ev if e["ok"] is False) == 6
    assert any(str(e.get("detail", "")).startswith("rate-limited")
               for e in ev)
    # the correct secret still works once the window slides past the
    # failures (simulated by rewinding the failure timestamps)
    data = gate._load()
    for e in data["events"]:
        if e["ok"] is False:
            e["ts"] = 0.0
    # recompute the chain honestly after the rewind (the chain is over the
    # event content; ts is part of it, so re-derive head from GENESIS)
    from burhan.stepup import canonical_event
    head = GENESIS
    for e in data["events"]:
        head = __import__("hashlib").sha256(
            (head + canonical_event(e)).encode()).hexdigest()
    data["chain_head"] = head
    gate._save(data)
    ok = gate.require("patch_generation", SECRET)
    assert ok["ok"] is True


def test_chain_tamper_is_detected_and_gate_fails_closed(gate, tmp_path):
    gate.require("patch_generation", SECRET)
    # edit one event's detail in the store file
    data = json.load(open(gate.path, encoding="utf-8"))
    data["events"][0]["detail"] = "edited by an attacker"
    json.dump(data, open(gate.path, "w", encoding="utf-8"))
    with pytest.raises(StepUpChainTampered):
        gate.verify_chain()
    # the gate refuses EVERYTHING on a tampered trail (fail-closed)
    with pytest.raises(StepUpChainTampered):
        gate.require("patch_generation", SECRET)


def test_setup_refuses_to_overwrite_the_trail(tmp_path):
    p = str(tmp_path / "store.json")
    StepUpGate.setup(p, SECRET)
    with pytest.raises(FileExistsError):
        StepUpGate.setup(p, "another-secret")
    # the original verifier still governs
    g = StepUpGate(p)
    with pytest.raises(StepUpRequired):
        g.require("patch_generation", "another-secret")


def test_master_secret_is_high_entropy_and_distinct():
    a, b = generate_master_secret(), generate_master_secret()
    import base64
    assert len(base64.b64decode(a)) == 32      # 256 bits
    assert a != b


# ================= P3.2 — the real RED->BLUE on a live clone =================

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Fixture:
    """A live instance of fixtures/vulnapp.py on its own loopback port."""

    def __init__(self, source_file, workdir):
        self.port = _free_port()
        self.source = source_file
        self.base = f"http://127.0.0.1:{self.port}"
        self.proc = None
        self.workdir = workdir
        self.start()

    def start(self):
        self.log = open(os.path.join(self.workdir, f"fixture-{self.port}.log"),
                        "w")
        self.proc = subprocess.Popen(
            [sys.executable, self.source],
            env={"PORT": str(self.port), "PATH": "/usr/bin:/bin"},
            stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                urllib.request.urlopen(self.base + "/", timeout=2)
                return
            except Exception:
                time.sleep(0.25)
        raise RuntimeError(f"fixture on {self.base} did not come up")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)
            self.proc = None
        if self.log:
            self.log.close()

    def restart(self, _clone_dir=None):
        self.stop()
        self.start()


@pytest.fixture()
def lab(tmp_path):
    """The isolated remediation lab: the ORIGINAL fixture (the 'scanned
    target') and a CLONE fixture started from a copy of the source in
    tmp_path — a different process, a different port, a different file."""
    clone_dir = tmp_path / "clone"
    clone_dir.mkdir()
    shutil.copy(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                clone_dir / "vulnapp.py")
    original_bytes = open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                          "rb").read()
    target = Fixture(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                     str(tmp_path))
    clone = Fixture(str(clone_dir / "vulnapp.py"), str(tmp_path))
    try:
        yield {"target": target, "clone": clone, "clone_dir": str(clone_dir),
               "original_bytes": original_bytes,
               "tmp": tmp_path}
    finally:
        target.stop()
        clone.stop()


FINDING = {
    "id": "r9-xss-1", "type": "xss_reflected", "severity": "high",
    "status": "verified", "method": "GET",
    "url": "http://127.0.0.1:1/vuln/xss.php", "parameter": "q",
    "evidence": [{"kind": "reflection",
                  "detail": "raw reflection of the q parameter"}],
}


def test_real_red_to_blue_on_live_clone(lab, gate):
    """THE 3.2 real proof: the ORIGINAL exploit reproduced on the
    UNPATCHED clone (RED), the patch applied to the clone source only,
    the SAME exploit re-run on the PATCHED clone and observed to FAIL
    (BLUE) — real HTTP against real processes, no simulation."""
    bundle = run_remediation(
        dict(FINDING), target_url=lab["target"].base,
        work_url=lab["clone"].base, clone_dir=lab["clone_dir"],
        gate=gate, credential=SECRET,
        allow_same_host_staging=True,      # the clone IS same-host staging
        restart_workload=lab["clone"].restart)

    assert bundle["status"] == "proposed-and-proved"
    # RED: the exploit really ran and really reflected, on the live clone
    assert bundle["red"]["exploitable"] is True
    assert bundle["red"]["raw_reflection"] is True
    assert "/vuln/xss.php?q=" in bundle["red"]["url"]
    # BLUE: the SAME exploit on the patched clone FAILED
    assert bundle["blue"]["exploitable"] is False
    assert bundle["blue"]["escaped"] is True
    assert bundle["blue"]["url"] == bundle["red"]["url"]
    # the patch: a real unified diff on the clone file only
    diff = bundle["patch"]["diff"]
    assert 'qv = q.get("q", "")' in diff                 # the removed line
    assert 'qv = q.get("q", "").replace("<", "&lt;")' in diff  # the added
    assert diff.startswith("--- a/vulnapp.py")
    assert bundle["patch"]["file"] == "vulnapp.py"
    # 3.3: the delivery is a PR bundle for the CLIENT's review system
    assert bundle["delivery"]["form"] == "pull-request-bundle"
    assert "never merges" in bundle["delivery"]["instructions"]
    # the ORIGINAL fixture source is byte-identical after everything
    assert open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                "rb").read() == lab["original_bytes"]
    # and the scanned target kept serving its unpatched surface throughout
    r = urllib.request.urlopen(
        lab["target"].base + "/vuln/xss.php?q=<probe-x>", timeout=5)
    assert "<probe-x>" in r.read().decode()


def test_hard_rule_enforced_in_code_exact_check(lab, gate):
    """3.1's hard rule, IN CODE: work surface == scanned target
    (host:port equal) -> IsolationViolation naming the exact check; same
    host different port without the explicit flag -> refused too."""
    t = lab["target"].base
    with pytest.raises(IsolationViolation, match="IS the scanned target"):
        run_remediation(dict(FINDING), target_url=t, work_url=t,
                        clone_dir=lab["clone_dir"], gate=gate,
                        credential=SECRET)
    # same host, different port, without the explicit staging flag
    with pytest.raises(IsolationViolation, match="shares the scanned target's host"):
        run_remediation(dict(FINDING), target_url=t,
                        work_url=lab["clone"].base,
                        clone_dir=lab["clone_dir"], gate=gate,
                        credential=SECRET)
    # the direct choke-point check itself (the cited enforcement point)
    with pytest.raises(IsolationViolation):
        assert_isolated(t, t)
    with pytest.raises(IsolationViolation):
        assert_isolated(t, "")
    # different host passes isolation (the standard staging shape)
    assert_isolated("http://prod.example.com",
                    "http://staging.example.com")
    assert_isolated("http://prod.example.com",
                    "http://staging.example.com:8443")


def test_no_clone_means_report_only_fallback_3_4(lab, gate):
    """3.4: no isolated clone/staging available -> the stage is refused
    ENTIRELY and the output is the Part-1 report-only guidance; the live
    target is never a substitute."""
    out = run_remediation(dict(FINDING), target_url=lab["target"].base,
                          work_url="", clone_dir="", gate=gate,
                          credential=SECRET)
    assert out["status"] == "refused-report-only"
    fb = out["fallback"]
    assert fb["mode"] == "report-only-fallback"
    assert fb["remediation_ar"] and fb["remediation_en"]
    assert "CWE-79" in fb["guidance_source"]
    assert "refused ENTIRELY" in fb["note"]


def test_stepup_gate_wired_into_remediation(lab, gate):
    """2.1(b) wired: patch generation without the step-up credential is
    refused (and logged) even with perfect isolation; with it, the
    pipeline proceeds to the RED check."""
    with pytest.raises(StepUpRequired):
        run_remediation(dict(FINDING), target_url=lab["target"].base,
                        work_url=lab["clone"].base,
                        clone_dir=lab["clone_dir"], gate=gate,
                        credential=None,
                        allow_same_host_staging=True,
                        restart_workload=lab["clone"].restart)
    ev = gate._load()["events"]
    assert ev[-1]["purpose"] == "patch_generation" and ev[-1]["ok"] is False


def test_unsupported_class_refused_with_fallback(lab, gate):
    """A finding class with no patch strategy: refused loudly with the
    report-only fallback — never a best-effort guess-patch."""
    csrf = dict(FINDING, type="csrf")
    out = run_remediation(
        csrf, target_url=lab["target"].base, work_url=lab["clone"].base,
        clone_dir=lab["clone_dir"], gate=gate, credential=SECRET,
        allow_same_host_staging=True, restart_workload=lab["clone"].restart)
    assert out["status"] == "refused-report-only"
    assert "no probe strategy" in out["fallback"]["reason"]
    # and directly: build_patch refuses the unsupported class
    with pytest.raises(RemediationRefused, match="no patch strategy"):
        build_patch({"type": "csrf"}, lab["clone_dir"])


def test_no_merge_or_deploy_code_path_exists():
    """3.3's guarantee asserted at module level: burhan.remediation has NO
    merge/push/deploy function — the tool structurally cannot merge or
    deploy to a client system, master-password or not."""
    import burhan.remediation as r
    for name in ("merge", "merge_pr", "push", "deploy", "apply_to_target",
                 "write_target", "commit_and_push"):
        assert not hasattr(r, name), f"remediation must not expose {name!r}"
    src = open(r.__file__, encoding="utf-8").read()
    assert "git push" not in src and "merge_pull" not in src


def test_patch_applies_only_to_the_clone_file(lab, gate):
    """The patch lands ONLY on the clone's file; apply_patch's signature
    takes a local clone directory — it has no URL parameter at all."""
    import inspect
    from burhan.remediation import apply_patch
    sig = inspect.signature(apply_patch)
    assert list(sig.parameters) == ["patch", "clone_dir"]
    patch = build_patch(dict(FINDING), lab["clone_dir"])
    patched = apply_patch(patch, lab["clone_dir"])
    assert patched.startswith(lab["clone_dir"])
    assert open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                "rb").read() == lab["original_bytes"]
    # the clone file now carries the fixed line
    body = open(os.path.join(lab["clone_dir"], "vulnapp.py"),
                encoding="utf-8").read()
    assert '.replace("<", "&lt;")' in body
    # and re-patching the already-patched clone refuses (no blind apply)
    with pytest.raises(RemediationRefused, match="not found|already"):
        build_patch(dict(FINDING), lab["clone_dir"])

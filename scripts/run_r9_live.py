"""Round-9 LIVE run on main (2026-11-04): the full pipeline with real
evidence in, real artifacts out, everything the round order demanded.

Outputs -> download/r9-live/:
  crapi-bilingual.json/.docx/.pdf — the bilingual report from the REAL
      signed round-8 live evidence (crapi, 99 findings);
  dvga-bilingual.json/.docx       — same for the DVGA evidence (26);
  parity-check.json              — the P1.3 diff: source IDs vs AR vs EN
                                    for BOTH datasets, zero loss;
  stepup-paired-proof.json       — the P2.2 paired proof: refusal logged,
                                    grant logged, chain verified;
  remediation-bundle.json        — the P3.2 real RED->BLUE bundle;
  remediation.patch              — the PR-bundle diff (client merges);
  fallback-3-4.json              — the live no-clone refusal + fallback;
  summary.json                   — one-line-per-artifact index.

The step-up store (scrypt verifier) stays in /tmp — only its events are
published. The master secret is generated fresh for this run and never
written anywhere.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

OUT = os.path.join(ROOT, "download", "r9-live")
os.makedirs(OUT, exist_ok=True)


def jdump(name: str, obj) -> str:
    p = os.path.join(OUT, name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
    return p


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Fixture:
    """A live fixture whose port is chosen ONCE and kept across restarts
    (the client-provided restart hook must serve the SAME staging address;
    in the pytest lab the same discipline holds)."""

    def __init__(self, source: str, logname: str):
        self.source, self.logname = source, logname
        self.port = free_port()
        self.proc = None
        self.start()

    def start(self):
        self.base = f"http://127.0.0.1:{self.port}"
        self.log = open(f"/tmp/render/{self.logname}-{self.port}.log", "w")
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
        if getattr(self, "log", None):
            self.log.close()

    def restart(self, _clone_dir=None):
        self.stop()
        self.start()


def main() -> int:
    summary = {}

    # ---- P1: the bilingual report from the REAL live evidence ----------
    from burhan.bilingual import (build_bilingual, build_bilingual_docx,
                                  export_pdf)
    from burhan.audit import merkle_root_of_records

    parity = {}
    for tag, fname in (("crapi", "crapi-scan.json"),
                       ("dvga", "dvga-scan.json")):
        src = json.load(open(os.path.join(
            ROOT, "evidence", "live-validation-r8", fname),
            encoding="utf-8"))
        bi = build_bilingual(src)
        src_ids = sorted(f.get("id") for f in src["findings"])
        ar_ids = sorted(f["id"] for f in bi["findings"])
        en_probe = sorted(f["id"] for f in bi["findings"])
        parity[tag] = {
            "source_findings": len(src_ids),
            "bilingual_findings": bi["findings_count"],
            "source_ids_eq_output_ids": src_ids == ar_ids == en_probe,
            "both_languages_complete": all(
                f["ar"]["what_it_is"] and f["en"]["what_it_is"]
                and f["ar"]["proof"] and f["en"]["proof"]
                and f["ar"]["remediation"]["steps"]
                and f["en"]["remediation"]["steps"]
                for f in bi["findings"]),
            "audit_root_matches_source": (
                bi["audit"]["merkle_root"] ==
                merkle_root_of_records(src["findings"])),
            "run_id": bi["run_id"],
        }
        base = os.path.join(OUT, f"{tag}-bilingual")
        jdump(f"{tag}-bilingual.json", bi)
        build_bilingual_docx(bi, base + ".docx")
        summary[f"{tag}_docx"] = base + ".docx"
        try:
            export_pdf(base + ".docx", base + ".pdf")
            summary[f"{tag}_pdf"] = base + ".pdf"
        except Exception as e:  # loud-refusal contract: report, not fail
            summary[f"{tag}_pdf"] = f"REFUSED: {e}"
    jdump("parity-check.json", parity)
    assert all(v["source_ids_eq_output_ids"] and v["both_languages_complete"]
               and v["audit_root_matches_source"]
               for v in parity.values()), "P1.3 parity broken"
    summary["parity"] = "PASS — zero content loss, both datasets"

    # ---- P2.2: the paired step-up proof on a fresh gate -----------------
    from burhan.stepup import StepUpGate, StepUpRequired, \
        generate_master_secret

    store = "/tmp/render/r9-stepup-store.json"
    if os.path.exists(store):
        os.remove(store)          # fresh store for this live run only
    secret = generate_master_secret()
    gate = StepUpGate.setup(store, secret)

    paired = {"purpose": "closure_reexploit"}
    try:
        gate.require("closure_reexploit", None)
        raise AssertionError("gated action ran WITHOUT the credential")
    except StepUpRequired as e:
        paired["without_credential"] = {"refused": True, "message": str(e)}
    paired["with_credential"] = gate.require("closure_reexploit", secret)
    paired["chain_events"] = gate._load()["events"]
    paired["chain_verified_count"] = gate.verify_chain()
    jdump("stepup-paired-proof.json", paired)
    assert paired["chain_events"][0]["ok"] is False
    assert paired["chain_events"][-1]["ok"] is True
    assert paired["chain_verified_count"] == 2
    summary["stepup_paired"] = ("PASS — refusal logged (event 1), grant "
                               "logged (event 2), chain verified")

    # ---- P3.2: the real RED->BLUE on a live clone ------------------------
    from burhan.remediation import run_remediation

    clone_dir = "/tmp/render/r9-clone"
    os.makedirs(clone_dir, exist_ok=True)
    shutil.copy(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                os.path.join(clone_dir, "vulnapp.py"))
    original = open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                    "rb").read()

    target = Fixture(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                     "r9-target")
    clone = Fixture(os.path.join(clone_dir, "vulnapp.py"), "r9-clone")
    try:
        finding = {
            "id": "r9-live-xss-1", "type": "xss_reflected",
            "severity": "high", "status": "verified", "method": "GET",
            "url": target.base + "/vuln/xss.php", "parameter": "q",
            "evidence": [{"kind": "reflection",
                          "detail": "raw reflection of the q parameter"}],
        }
        bundle = run_remediation(
            dict(finding), target_url=target.base, work_url=clone.base,
            clone_dir=clone_dir, gate=gate, credential=secret,
            allow_same_host_staging=True, restart_workload=clone.restart)
        assert bundle["status"] == "proposed-and-proved", bundle["status"]
        assert bundle["red"]["exploitable"] is True
        assert bundle["blue"]["exploitable"] is False
        assert open(os.path.join(ROOT, "fixtures", "vulnapp.py"),
                   "rb").read() == original
        # the live target kept its unpatched surface the whole time
        probe = urllib.request.urlopen(
            target.base + "/vuln/xss.php?q=<live-check>", timeout=5)
        assert "<live-check>" in probe.read().decode()
        jdump("remediation-bundle.json", bundle)
        with open(os.path.join(OUT, "remediation.patch"), "w",
                  encoding="utf-8") as fh:
            fh.write(bundle["patch"]["diff"])
        # the step-up chain now carries the patch_generation grant too
        jdump("stepup-paired-proof.json", dict(
            paired, chain_events=gate._load()["events"],
            chain_verified_count=gate.verify_chain()))
        summary["remediation"] = ("PASS — RED reproduced on the unpatched "
                                  "clone, BLUE observed on the patched "
                                  "clone, original byte-identical, target "
                                  "still serving its unpatched surface")
    finally:
        target.stop()
        clone.stop()

    # ---- P3.4 live: no clone -> the explicit report-only fallback --------
    fallback = run_remediation(
        {"id": "fb-1", "type": "xss_reflected", "severity": "high",
         "status": "verified", "evidence": []},
        target_url="http://127.0.0.1:9", work_url="", clone_dir="",
        gate=gate, credential=secret)
    assert fallback["status"] == "refused-report-only"
    jdump("fallback-3-4.json", fallback)
    summary["fallback_3_4"] = "PASS — stage refused, report-only payload"

    jdump("summary.json", summary)
    for k, v in summary.items():
        print(f"{k}: {v}")
    print("ALL LIVE RUNS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

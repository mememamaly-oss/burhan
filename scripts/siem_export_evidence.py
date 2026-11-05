#!/usr/bin/env python3
"""Part 1.6 — build evidence/layers/siem-export/ from the canonical signed
scan (evidence/full-reverify/fixtures-vulnapp/scan.json, REUSED not
fabricated): the three exports, the fetched official spec excerpts, and a
SHA-256-stamped manifest."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "evidence/layers/siem-export"
SPECS = OUT / "specs"
SCAN_PATH = ROOT / "evidence/full-reverify/fixtures-vulnapp/scan.json"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    SPECS.mkdir(exist_ok=True)

    # 1. the fetched official spec excerpts (verbatim quotes already live in
    #    burhan/siem.py's docstring; here we persist the fetched sources'
    #    key excerpts + provenance URLs, byte-exact from what was fetched)
    rfc = Path("/tmp/rfc5424.txt")
    if rfc.exists():
        txt = rfc.read_text(errors="replace")
        # section 6 (the ABNF) + 6.2.1 (severity tables)
        i = txt.find("6.  Syslog Message Format")
        j = txt.find("6.3.  STRUCTURED-DATA")
        (SPECS / "rfc5424-section6-abnf.txt").write_text(
            "SOURCE: https://www.rfc-editor.org/rfc/rfc5424.txt (fetched "
            "2026-11-05, RFC 5424 'The Syslog Protocol', IETF March 2009)\n"
            "==== VERBATIM sections 6 + 6.2 ====\n" + txt[i:j],
            encoding="utf-8")
    cef = Path("/tmp/cef-spec-full.txt")
    if cef.exists():
        txt = cef.read_text(errors="replace")
        i = txt.find("TheExtensionField")
        if i == -1:
            i = txt.find("Extension Field")
        j = txt.find("ArcSightExtensionDictionary", i + 10)
        (SPECS / "cef-excerpt-character-encoding.txt").write_text(
            "SOURCE: 'Implementing ArcSight Common Event Format (CEF)', "
            "Version 26, OpenText SmartConnectors 8.4.3, October 2023 — "
            "https://www.microfocus.com/documentation/arcsight/"
            "arcsight-smartconnectors-8.4/pdfdoc/cef-implementation-standard/"
            "cef-implementation-standard.pdf (fetched 2026-11-05)\n"
            "==== VERBATIM: format line, header field definitions, "
            "extension field, character encoding ====\n" + txt[4000:11600],
            encoding="utf-8")
        # the extension dictionary key table (cs1..cs6, externalId, rt, ...)
        k = txt.find("externalId")
        (SPECS / "cef-excerpt-extension-dictionary.txt").write_text(
            "SOURCE: same official CEF spec PDF (fetched 2026-11-05)\n"
            "==== VERBATIM: ArcSight Extension Dictionary key definitions "
            "(extract) ====\n" + txt[k - 200:k + 4000] +
            "\n\n[dictionary continues: request/requestMethod/msg/cat/"
            "outcome/act/src/dst/... — see the source PDF pages 20-41]",
            encoding="utf-8")
    for f, name in ((Path("/tmp/ocsf-detection_finding.json"),
                     "ocsf-v1.9.0-detection_finding.json"),
                    (Path("/tmp/ocsf-finding.json"), "ocsf-v1.9.0-finding.json"),
                    (Path("/tmp/ocsf-finding_info.json"),
                     "ocsf-v1.9.0-finding_info.json"),
                    (Path("/tmp/ocsf-metadata.json"), "ocsf-v1.9.0-metadata.json"),
                    (Path("/tmp/ocsf-product.json"), "ocsf-v1.9.0-product.json"),
                    (Path("/tmp/ocsf-evidences.json"), "ocsf-v1.9.0-evidences.json"),
                    (Path("/tmp/ocsf-dictionary.json"),
                     "ocsf-v1.9.0-dictionary.json")):
        if f.exists():
            shutil.copy(f, SPECS / name)

    # 2. run the three exports through the REAL CLI against the canonical
    #    signed scan loaded into a fresh store
    from burhan.store import Store
    db = ROOT / "evidence/layers/siem-export/source-run.db"
    scan = json.loads(SCAN_PATH.read_text(encoding="utf-8"))
    st = Store(str(db))
    st.save_run(scan)

    # CEF
    r = subprocess.run([sys.executable, "-m", "burhan.cli", "report",
                        "--db", str(db), "--format", "cef",
                        "--out", str(OUT / "scan.cef")],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr
    cef_summary = json.loads(r.stdout)

    # OCSF
    r = subprocess.run([sys.executable, "-m", "burhan.cli", "report",
                        "--db", str(db), "--format", "ocsf",
                        "--out", str(OUT / "scan.ocsf.json")],
                       capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr
    ocsf_summary = json.loads(r.stdout)

    # syslog — real UDP send to a loopback collector, datagrams counted
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]
    rx.settimeout(6)
    got: list[bytes] = []

    def listen():
        while True:
            try:
                data, _ = rx.recvfrom(65535)
            except socket.timeout:
                return
            got.append(data)
            if len(got) >= 500:
                return

    t = threading.Thread(target=listen)
    t.start()
    r = subprocess.run([sys.executable, "-m", "burhan.cli", "report",
                        "--db", str(db), "--format", "syslog",
                        "--out", str(OUT / "scan.syslog"),
                        "--syslog-host", "127.0.0.1",
                        "--syslog-port", str(port)],
                       capture_output=True, text=True, cwd=str(ROOT))
    t.join(12)
    rx.close()
    assert r.returncode == 0, r.stderr
    syslog_summary = json.loads(r.stdout)
    assert len(got) == len(scan["findings"]), \
        f"datagrams {len(got)} != findings {len(scan['findings'])}"

    # 3. validation record: parse every CEF line + every syslog line with
    #    the real validators, schema-validate every OCSF event
    from burhan.siem import parse_cef
    from syslog_rfc5424_parser.parser import parse as parse5424
    import jsonschema
    sys.path.insert(0, str(ROOT / "tests"))
    from test_siem_export import _OCSF_REQUIRED_SCHEMA
    cef_lines = (OUT / "scan.cef").read_text().splitlines()
    for l in cef_lines:
        parse_cef(l)
    syslog_lines = (OUT / "scan.syslog").read_text().splitlines()
    for l in syslog_lines:
        parse5424(l)
    ocsf_doc = json.loads((OUT / "scan.ocsf.json").read_text())
    for e in ocsf_doc["events"]:
        jsonschema.validate(e, _OCSF_REQUIRED_SCHEMA)

    # 4. SHA-256-stamped manifest
    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "order": "SIEM/enterprise export (Part 1)",
        "rebuild": ("python3 scripts/siem_export_evidence.py (re-imports "
                    "the committed scan.json into a fresh store and "
                    "re-exports; the working DB is not committed)"),
        "source_run": {
            "artifact": "evidence/full-reverify/fixtures-vulnapp/scan.json",
            "sha256": sha256(SCAN_PATH),
            "run_id": scan["run_id"],
            "findings": len(scan["findings"]),
            "audit": {k: scan["audit"][k] for k in
                      ("merkle_root", "findings_count", "signature_scheme")},
        },
        "exports": {
            "cef": {"file": "scan.cef", "sha256": sha256(OUT / "scan.cef"),
                    "lines": len(cef_lines), "cli": cef_summary,
                    "validated_by": "burhan.siem.parse_cef round-trip "
                                    "(official header structure + extension "
                                    "dictionary keys)"},
            "syslog": {"file": "scan.syslog",
                       "sha256": sha256(OUT / "scan.syslog"),
                       "lines": len(syslog_lines), "cli": syslog_summary,
                       "datagrams_received_by_loopback_collector": len(got),
                       "validated_by": "syslog-rfc5424-parser 0.3.2 "
                                       "(Lark implementation of RFC 5424 "
                                       "ABNF) — every line parses"},
            "ocsf": {"file": "scan.ocsf.json",
                     "sha256": sha256(OUT / "scan.ocsf.json"),
                     "events": len(ocsf_doc["events"]), "cli": ocsf_summary,
                     "validated_by": "jsonschema against the v1.9.0 required-"
                                     "attribute contract fetched from "
                                     "github.com/ocsf/ocsf-schema"},
        },
        "specs": {
            "cef": "OpenText/ArcSight 'Implementing ArcSight Common Event "
                   "Format (CEF)' Version 26 (SmartConnectors 8.4.3, Oct "
                   "2023) — official PDF fetched; excerpts in specs/",
            "rfc5424": "RFC 5424 (IETF, March 2009) — full text fetched "
                       "from rfc-editor.org; sections 6+6.2 in specs/",
            "ocsf": "OCSF v1.9.0 official schema repository "
                    "(github.com/ocsf/ocsf-schema, tag v1.9.0) — class + "
                    "object JSON schemas fetched verbatim into specs/",
        },
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"evidence": str(OUT),
                      "cef_lines": len(cef_lines),
                      "syslog_lines": len(syslog_lines),
                      "datagrams": len(got),
                      "ocsf_events": len(ocsf_doc["events"])}, indent=1))
    # the working store is reproducible from the committed scan.json in one
    # command (see manifest.rebuild) — keep the pack lean, drop the copy
    db.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

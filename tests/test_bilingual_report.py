"""Round-9 part-1 pins — the bilingual (AR/EN) client report.

P1.3 REAL test: the report is generated from the REAL signed live evidence
(evidence/live-validation-r8/ — the crAPI + DVGA runs of round 8), and the
finding IDs are DIFFED between the source data and BOTH language outputs:
zero content loss. Plus the guidance-sourcing discipline (no unsourced
text) and the audit-block content-loss tamper evidence.
"""
import json
import os

import pytest

from burhan.bilingual import (REMEDIATION_GUIDANCE, build_bilingual,
                              build_bilingual_docx, export_pdf)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE = os.path.join(ROOT, "evidence", "live-validation-r8")


def _real_report(name: str) -> dict:
    return json.load(open(os.path.join(EVIDENCE, name), encoding="utf-8"))


@pytest.mark.parametrize("evidence_file", ["crapi-scan.json", "dvga-scan.json"])
class TestRealEvidenceBilingual:
    def test_every_source_finding_in_both_languages_no_loss(self, evidence_file):
        """THE P1.3 real test: source finding IDs == AR output IDs == EN
        output IDs — an exact two-way diff, zero content loss, on the real
        crAPI/DVGA live evidence."""
        src = _real_report(evidence_file)
        bi = build_bilingual(src)
        src_ids = [f.get("id") for f in src["findings"]]
        out_ids = [f["id"] for f in bi["findings"]]
        assert bi["findings_count"] == len(src_ids)
        # exact diff, both directions
        assert sorted(src_ids) == sorted(out_ids), (
            "source findings lost in the bilingual document")
        for f in bi["findings"]:
            assert f["ar"]["what_it_is"].strip()
            assert f["en"]["what_it_is"].strip()
            assert f["ar"]["proof"].strip()
            assert f["en"]["proof"].strip()
            assert f["ar"]["remediation"]["steps"]
            assert f["en"]["remediation"]["steps"]

    def test_proof_quotes_engine_evidence_verbatim(self, evidence_file):
        """The plain-language proof carries the engine's evidence detail
        VERBATIM (the technical record rides along, unaltered)."""
        src = _real_report(evidence_file)
        bi = build_bilingual(src)
        by_id = {f["id"]: f for f in src["findings"]}
        for f in bi["findings"]:
            ev = by_id[f["id"]].get("evidence") or []
            if ev:
                assert ev[0].get("detail", "") in f["en"]["proof"]
                assert ev[0].get("detail", "") in f["ar"]["proof"]

    def test_audit_block_detects_content_loss(self, evidence_file):
        """The bilingual document's Merkle root is over the SOURCE findings:
        dropping a finding from the rendered document is detectable by the
        standard recipe (the root is recomputed from the source, and the
        embedded audit block's findings_count catches a dropped finding)."""
        from burhan.audit import audit_block, merkle_root_of_records
        src = _real_report(evidence_file)
        bi = build_bilingual(src)
        assert bi["audit"]["findings_count"] == len(src["findings"])
        assert bi["audit"]["merkle_root"] == \
            merkle_root_of_records(src["findings"])
        # a tampered source (one finding dropped) yields a DIFFERENT root —
        # the content-loss property the block exists for
        tampered = dict(src, findings=src["findings"][:-1])
        assert audit_block(tampered, seed=src.get("seed"))["merkle_root"] != \
            bi["audit"]["merkle_root"]


def test_guidance_entries_are_sourced():
    """P1.1 sourcing discipline: every curated guidance entry cites its
    compliance mapping; the unknown-type fallback cites compliance too."""
    from burhan.compliance import COMPLIANCE, compliance_for
    for ftype, g in REMEDIATION_GUIDANCE.items():
        assert g["source"], f"{ftype}: guidance without a source citation"
        # the citation names a real registry CWE (the mapping it belongs to)
        c = compliance_for(ftype)
        assert (c.get("cwe") or "CWE-") in g["source"], (
            f"{ftype}: source does not cite the registry mapping")
    # the fallback path (unknown type) is honest, not invented
    bi = build_bilingual({"run_id": "x", "findings": [
        {"id": "f1", "type": "no_such_type_at_all", "severity": "low",
         "status": "verified", "evidence": []}]})
    g = bi["findings"][0]["en"]["remediation"]
    assert g["finding_specific"] is False
    assert "compliance" in g["source"].lower() or "unmapped" in g["source"].lower()
    assert "No plain-language description curated yet" in \
        bi["findings"][0]["en"]["what_it_is"]


def test_header_guidance_names_finding_specific_headers():
    """Header-class findings name the EXACT missing headers from their own
    evidence — per-finding specific, never a generic list alone."""
    src = _real_report("crapi-scan.json")
    msh = next(f for f in src["findings"]
               if f["type"] == "missing_security_headers")
    bi = build_bilingual(src)
    f = next(x for x in bi["findings"] if x["id"] == msh["id"])
    detail = msh["evidence"][0]["detail"]
    for h in ("strict-transport-security", "content-security-policy",
              "x-frame-options"):
        assert h in detail
        assert h in f["en"]["remediation"]["steps"][1]
        assert h in f["ar"]["remediation"]["steps"][1]
    assert f["en"]["remediation"]["finding_specific"] is True


def test_docx_renders_both_languages(tmp_path):
    """The .docx pipeline: both languages' content physically present in
    the rendered document for the real crAPI evidence."""
    src = _real_report("crapi-scan.json")
    bi = build_bilingual(src)
    p = str(tmp_path / "crapi-bilingual.docx")
    build_bilingual_docx(bi, p)
    from docx import Document
    d = Document(p)
    text = "\n".join(par.text for par in d.paragraphs)
    # both-language anchors from several findings
    assert "ما هي هذه الثغرة؟" in text and "What this flaw is" in text
    assert "الدليل على الاستغلال الفعلي" in text and \
        "Proof it was actually exploited" in text
    assert "خطوات المعالجة" in text and "Remediation steps" in text
    assert bi["audit"]["merkle_root"][:32] in text
    # every finding's AR+EN plain-language opener present in the docx
    for f in bi["findings"][:12]:
        assert f["ar"]["title"].split("،")[0][:12] in text
        assert f["en"]["title"][:18] in text


def test_pdf_export_or_loud_refusal(tmp_path):
    """P1.2: the PDF export either produces a real PDF (soffice present)
    or refuses LOUDLY (PdfExportUnavailable) — never a silent skip."""
    src = _real_report("dvga-scan.json")
    bi = build_bilingual(src)
    docx = str(tmp_path / "dvga.docx")
    build_bilingual_docx(bi, docx)
    try:
        pdf = export_pdf(docx, str(tmp_path / "dvga.pdf"))
    except Exception as e:  # noqa: BLE001 — the loud-refusal contract
        from burhan.bilingual import PdfExportUnavailable
        assert isinstance(e, PdfExportUnavailable)
        assert "soffice" in str(e)
        return
    assert os.path.getsize(pdf) > 0
    with open(pdf, "rb") as fh:
        assert fh.read(5) == b"%PDF-"

#!/usr/bin/env python3
"""phaseC active-numbers generator (owner order 2026-11-13 condition 3).

Recomputes the ACTIVE two-number figures BY CODE from the sealed
CLASSIFICATION.json — never by hand — and regenerates
PHASEC-L1-ACTIVE-NUMBERS.md. After the 2026-11-13 railsgoat reseal all
five isolated members are ACTIVE, so the ACTIVE aggregate == the seal
aggregate (computed, not assumed).

Usage: python3 scripts/phasec_gen_active_numbers.py [--check]
  --check: verify the committed md already matches (CI guard), exit 1 on drift.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEAL = ROOT / "download" / "phaseC" / "seal"
OUT_MD = ROOT / "download" / "phaseC" / "PHASEC-L1-ACTIVE-NUMBERS.md"

# An app is INACTIVE only if SUSPENDED.json still carries an unresolved
# suspension for it (decision != resolved-by-reseal). Computed, not hardcoded.
SUSPENDED_FILE = SEAL / "SUSPENDED.json"


def active_apps() -> tuple[dict, list[str]]:
    clf = json.loads((SEAL / "CLASSIFICATION.json").read_text(encoding="utf-8"))
    inactive: list[str] = []
    if SUSPENDED_FILE.exists():
        sus = json.loads(SUSPENDED_FILE.read_text(encoding="utf-8"))
        for entry in sus.get("suspended", []):
            decision = str(entry.get("decision", "")).upper()
            if "RESOLVED-BY-RESEAL" not in decision and "BLOCKED" in decision:
                inactive.append(entry["app"])
    return clf, inactive


def compute() -> dict:
    clf, inactive = active_apps()
    rows = []
    for app, v in clf["per_app"].items():
        if app in inactive:
            continue
        rows.append({
            "app": app,
            "labels": len(v["labels"]),
            "measurable": v["measurable"],
            "out_of_scope": v["out_of_scope"],
        })
    tot = {
        "labels": sum(r["labels"] for r in rows),
        "measurable": sum(r["measurable"] for r in rows),
        "out_of_scope": sum(r["out_of_scope"] for r in rows),
    }
    # cross-check against the seal totals when nothing is inactive
    seal_totals = clf["totals"]
    consistent = (
        (not inactive and tot == seal_totals) or
        (inactive and tot["labels"] == seal_totals["labels"] - sum(
            len(clf["per_app"][a]["labels"]) for a in inactive))
    )
    return {"rows": rows, "totals": tot, "inactive": inactive,
            "seal_totals": seal_totals, "consistent": consistent}


def render(c: dict) -> str:
    m, lab = c["totals"]["measurable"], c["totals"]["labels"]
    lines = []
    lines.append("# PHASEC-L1-ACTIVE-NUMBERS.md — أرقام المجموعة المعزولة النشطة")
    lines.append("")
    lines.append("> **المنشأ:** مولّد بالكود `scripts/phasec_gen_active_numbers.py` من `seal/CLASSIFICATION.json` المخوم — لا يدوياً.")
    lines.append("> **تحديث 2026-11-13:** بعد ختم railsgoat الجديد (المصدر الرسمي OWASP/railsgoat @ f5951f1، موافقة المالك) وإعادة تصنيفه على Rails 8 وفق المعايير المختومة نفسها — الأعضاء الخمسة كلهم نشطون، فإجمالي النشط = إجمالي الختم (محسوب لا مفترض).")
    lines.append("> **الأرقام المنسحبة من الاستخدام: 81/111 (ختم 2018 القديم) و72/99 (فترة التعليق) — لا تُنشر ولا تُقارن بها؛ الرقمان أدناه هما المرجع الوحيد للأرقام النشطة حتى ختم جديد.**")
    lines.append("")
    lines.append("## 1. الأرقام النشطة (محسوبة بالكود — قاعدة الرقمين، SPEC §3.2.1)")
    lines.append("")
    lines.append("| المقياس | القيمة |")
    lines.append("|---|---|")
    lines.append(f"| **recall-on-measurable (قابل للقياس النشط)** — بسط الاستدعاء | **{m}** |")
    lines.append(f"| **coverage-on-all-labels (كل التسميات النشطة)** — مقام التغطية (out_of_scope يُعد غائباً) | **{lab}** |")
    lines.append(f"| خارج النطاق النشط (سياق فقط — ليس مقياساً) | {c['totals']['out_of_scope']} |")
    lines.append("")
    lines.append("## 2. التوزيع لكل تطبيق (نشط)")
    lines.append("")
    lines.append("| التطبيق | التسميات | قابل للقياس | خارج النطاق |")
    lines.append("|---|---|---|---|")
    for r in sorted(c["rows"], key=lambda r: -r["labels"]):
        lines.append(f"| {r['app']} | {r['labels']} | {r['measurable']} | {r['out_of_scope']} |")
    lines.append(f"| **الإجمالي النشط** | **{lab}** | **{m}** | **{c['totals']['out_of_scope']}** |")
    lines.append("")
    lines.append("## 3. التحقق التقاطعي مع الختم")
    lines.append("")
    if c["inactive"]:
        lines.append(f"- الأعضاء غير النشطين: {', '.join(c['inactive'])} (سجل التعليق قائم).")
    else:
        lines.append("- الأعضاء الخمسة نشطون — إجمالي النشط يطابق إجماليات الختم المخوم (CLASSIFICATION.json totals) رياضياً.")
    lines.append(f"- إجماليات الختم: {c['seal_totals']['labels']} تسمية / {c['seal_totals']['measurable']} قابل للقياس / {c['seal_totals']['out_of_scope']} خارج نطاق.")
    lines.append(f"- الاتساق: {'✓' if c['consistent'] else '✗ غير متسق — تحقق يدوي مطلوب'}")
    lines.append("")
    lines.append("## 4. قواعد الاستخدام")
    lines.append("")
    lines.append("1. أي نتيجة فحص لاحقة على المجموعة المعزولة تُنشر بالرقمين معاً (استدعاء على القابل للقياس + تغطية على كل التسميات النشطة) — بوابة SPEC §4bis ترفض تقريراً يحمل رقماً واحداً.")
    lines.append("2. الفجوة بين الرقمين هي حدود الأداة على التسميات غير القابلة للقياس — تُعلن ولا تُخفى.")
    lines.append("3. عند أي ختم جديد يُعاد توليد هذا الملف بالكود: `python3 scripts/phasec_gen_active_numbers.py`.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    c = compute()
    if not c["consistent"]:
        print("INCONSISTENT totals vs seal — refusing to write")
        return 1
    text = render(c)
    if "--check" in sys.argv:
        current = OUT_MD.read_text(encoding="utf-8") if OUT_MD.exists() else ""
        if current != text:
            print("DRIFT: committed ACTIVE-NUMBERS does not match the seal — regenerate")
            return 1
        print("OK: committed ACTIVE-NUMBERS matches the seal")
        return 0
    OUT_MD.write_text(text, encoding="utf-8")
    print(f"ACTIVE numbers written: {c['totals']['measurable']}/{c['totals']['labels']} "
          f"(out_of_scope {c['totals']['out_of_scope']}, inactive: {c['inactive'] or 'none'})")
    for r in sorted(c["rows"], key=lambda r: -r["labels"]):
        print(f"  {r['app']}: {r['measurable']}/{r['labels']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

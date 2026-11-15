#!/usr/bin/env python3
"""Impact of CLASSIFICATION-DEFINITION v2 (engine-independent measurable)
on the numbers, per app — owner review BEFORE any reseal.

Reads:
  - the official Juice Shop challenges.yml (v20.3.0, 116)
  - the v1-generated ground truth (gen-rule-v1)
  - the sealed ISOLATED-SET classification (111 labels, 5 apps)

Applies the v2 decision rule (independent of OUR engine):
  order: mobile/tls/non-http -> auth -> multi-step -> client-only -> dos
  else measurable.

For Juice Shop we re-decide each challenge from its official text with a
DECLARED, reviewable evidence table (same keyword-regex approach as v1's
rule (b) — but rule (a), the engine-battery requirement, is GONE; the
'battery-family' column is kept only as an ANNOTATION for what our engine
could plausibly match, never as a gate).

For the 5 sealed apps we do not have official challenge text in-tree; we
re-decide from the sealed per-label 'reason' strings + the engine_types
annotation, flagging every label whose ONLY exclusion ground was the
battery/class-gap (circular) for owner spot-check.

Output: download/phaseC/CLASSIFICATION-DEFINITION-IMPACT.md (the owner's
review table) + prints the summary.
"""
import json
import pathlib
import re
import yaml

WT = pathlib.Path("/tmp/wt9")
GT = json.load(open("/home/z/my-project/download/phaseC/step1-generator/labeled-ground-truth.json"))
CHS = {c["key"]: c for c in yaml.safe_load(open(WT / "download/phaseC/step1-generator/challenges-v20.3.0.yml", encoding="utf-8"))}
SEAL = json.load(open(WT / "download/phaseC/seal/CLASSIFICATION.json"))

# ── v2 evidence table (declared, reviewable) ────────────────────────────────
# Each regex runs over official name+description+tags+category. The FIRST
# matching ground in the FIXED ORDER wins (order = decision rule §2.1).
V2_GROUNDS: list[tuple[str, str, re.Pattern]] = [
    ("non-http", "outside HTTP entirely (blockchain/ftp/filesystem/steganography)",
     re.compile(r"\bblockchain\b|\bnft\b|\bwallet\b|\bweb3\b|\bsoul bound token\b|\bsteganograph|\bftp\b|\bdirectory listing\b|\bfile system\b|\bfolder\b", re.I)),
    ("auth", "requires login / authenticated session / registered account",
     re.compile(r"\blog ?in\b|\blogged[- ]in\b|\bsign ?in\b|\bauthenticat|\bregistered (user|account|customer)\b|\byour account\b|\ban account\b|\bregister as\b|\bsign ?up\b|\bcreating an? account\b|\bchange\b.{0,30}\bpassword\b|\breset\b.{0,30}\bpassword\b|\bpassword\b.{0,30}\bchange\b", re.I)),
    ("multi-step", "multi-step / multi-account attacker actions or victim interaction",
     re.compile(r"\bas (another|a different|the admin|an admin)\b|\bsomeone else'?s?\b|\bon behalf of\b|\bupload\b.*\bthen\b|\bafter (uploading|posting)\b|\bcsrf\b|\bcross[- ]site request forgery\b|\breview of (a|the) product you\b|\bfive[- ]star\b|\bstar review\b|\btake over\b|\btakeover\b|\bhijack\b|\bgather\b|\bcollect\b.{0,30}\bfrom\b", re.I)),
    ("client-only", "evidence only in browser/JS, not in a raw HTTP response",
     re.compile(r"\bbrowser\b|\bjavascript\b|\bclient[- ]side\b|\bdevtools\b|\bdom\b(?!.{0,20}(inject|xss|html))", re.I)),
    ("dos", "denial-of-service class — measuring it harms the target",
     re.compile(r"\bdos\b|\bdenial of service\b|\brepeat\w* request|\bslammer\b|\brepeate?d\b.{0,20}(request|query)|\bmemory bomb\b", re.I)),
    ("business-logic", "side-effectful business flow (payment/order/basket) — not a response-observable flaw",
     re.compile(r"\bpay(ment|ing)\b|\border\b.{0,20}\bplaced\b|\bshopping cart\b|\bbasket\b", re.I)),
]

# Annotation only — NEVER a gate in v2 (this is the circularity fix):
ENGINE_ANNOTATION = re.compile(
    r"vulnerable components|supply chain|typosquat|observability|metrics|access log|signature file|deserialization", re.I)

def v2_decide(ch: dict) -> tuple[str, str]:
    """(classification, ground/reason) — engine-independent."""
    blob = " ".join([ch.get("name", ""), ch.get("description", ""),
                     " ".join(ch.get("tags") or []), ch.get("category", "")])
    for code, human, rx in V2_GROUNDS:
        if rx.search(blob):
            if code in ("auth",):
                # auth ground -> needs_attacker_action, NOT out_of_scope (v2 split)
                return "needs_attacker_action", f"{code}: {human}"
            return "out_of_scope", f"{code}: {human}"
    return "measurable", "http-observable in principle by an unauthenticated DAST"

def engine_annotation(ch: dict) -> str:
    blob = " ".join([ch.get("name", ""), ch.get("category", "")])
    return "annotation: battery gap (dev roadmap), NOT excluded" if ENGINE_ANNOTATION.search(blob) else ""

# ── Juice Shop: re-decide all 116 ───────────────────────────────────────────
rows = []
flips = {"oos_to_meas": [], "oos_to_naa": [], "meas_to_oos": [], "meas_to_naa": [], "stays": 0}
for l in GT["labels"]:
    ch = CHS[l["challenge_id"]]
    ch["name"] = ch["name"].replace("''", "'")
    cls2, reason2 = v2_decide(ch)
    cls1 = l["classification"]
    note = engine_annotation(ch)
    rows.append({
        "challenge_id": l["challenge_id"],
        "name": ch["name"],
        "category": ch["category"],
        "v1": cls1,
        "v2": cls2,
        "v2_reason": reason2,
        "annotation": note,
    })
    if cls1 == "out_of_scope_reason" and cls2 == "measurable": flips["oos_to_meas"].append(l["challenge_id"])
    elif cls1 == "out_of_scope_reason" and cls2 == "needs_attacker_action": flips["oos_to_naa"].append(l["challenge_id"])
    elif cls1 == "measurable" and cls2 != "measurable": flips["meas_to_oos" if cls2 == "out_of_scope" else "meas_to_naa"].append(l["challenge_id"])
    else: flips["stays"] += 1

v1_counts = {"measurable": sum(1 for r in rows if r["v1"] == "measurable"),
             "out_of_scope": sum(1 for r in rows if r["v1"] == "out_of_scope_reason")}
v2_counts = {}
for r in rows: v2_counts[r["v2"]] = v2_counts.get(r["v2"], 0) + 1

# ── Sealed 111 (5 apps): flag circular exclusions for owner spot-check ──────
seal_flags = {}
for app, v in SEAL["per_app"].items():
    flags = []
    for lbl in v["labels"]:
        if lbl["classification"] == "out_of_scope":
            # circular ground: exclusion justified ONLY by battery/class-gap wording
            if re.search(r"no engine|battery|class.?gap|not an HTTP-response-observable|not in the (engine|19)", (lbl.get("reason") or ""), re.I):
                # does an independent ground also appear in the reason?
                indep = re.search(r"authenticat|login|session|mobile|tls|dos|multi.?step|client.?side", (lbl.get("reason") or ""), re.I)
                flags.append({"label": lbl["label"], "reason": lbl.get("reason", "")[:120],
                              "independent_ground_also": bool(indep)})
    seal_flags[app] = flags

# ── write the owner review file ─────────────────────────────────────────────
OUT = pathlib.Path("/home/z/my-project/download/phaseC/CLASSIFICATION-DEFINITION-IMPACT.md")
md = []
md.append("# أثر تعريف التصنيف v2 على الأرقام — للمراجعة قبل أي ختم")
md.append("")
md.append("**أمر المالك 2026-11-15، البند 3. لا ختم جديد قبل الموافقة.** المصدر: `docs/process/CLASSIFICATION-DEFINITION.md`.")
md.append("")
md.append("## 1. Juice Shop (مرجع الـ116) — القرار معاد من النص الرسمي بقاعدة v2")
md.append("")
md.append(f"- **v1:** measurable = **{v1_counts['measurable']}** · out_of_scope = **{v1_counts['out_of_scope']}** (لا فئة ثالثة مستخدمة)")
md.append(f"- **v2:** " + " · ".join(f"{k} = **{v}**" for k, v in sorted(v2_counts.items())))
md.append("")
md.append("### التحوّلات ولماذا")
md.append("")
md.append(f"- **out_of_scope → measurable: {len(flips['oos_to_meas'])}** — كانت مستبعدة بسبب «لا عائلة بطارية» (الدائري) ولا ينطبق عليها أي سبب مستقل:")
for cid in flips["oos_to_meas"]:
    r = next(x for x in rows if x["challenge_id"] == cid)
    md.append(f"  - `{r['name']}` [{r['category']}] — {r['annotation'] or 'HTTP-observable in principle'}")
md.append(f"- **out_of_scope → needs_attacker_action: {len(flips['oos_to_naa'])}** — سبب الاستبعاد الوحيد كان auth (فُصلت الفئة في v2):")
for cid in flips["oos_to_naa"]:
    r = next(x for x in rows if x["challenge_id"] == cid)
    md.append(f"  - `{r['name']}` — {r['v2_reason']}")
md.append(f"- **measurable → خارج measurable: {len(flips['meas_to_oos']) + len(flips['meas_to_naa'])}** (فحص عكسي — هل يخسر v2 شيئاً ربحه v1؟)")
for cid in flips["meas_to_oos"] + flips["meas_to_naa"]:
    r = next(x for x in rows if x["challenge_id"] == cid)
    md.append(f"  - `{r['name']}` [{r['v1']} → {r['v2']}] — {r['v2_reason']}")
md.append(f"- **باقية بلا تغيير: {flips['stays']}**")
md.append("")
md.append("> **تنبيه الصدق:** المقام (measurable) يرتفع وrecall سينخفض تبعاً — ما لا يجده المحرك الآن يُحسب **فائتاً** لا مستبعداً. رمز كل استبعاد مبيّن أعلاه (auth/mobile/tls/dos/multi-step/client-only/non-http/business-logic).")
md.append("")
md.append("## 2. المجموعة المعزولة المختومة (111، خمسة تطبيقات) — أعلام للفحص البشري")
md.append("")
md.append("النص الرسمي للتحديات غير متوفر في الشجرة لكل التطبيقات، لذا **لا نعيد قرارها آلياً**؛ نرفع بدل ذلك كل تسمية مختومة مستبعدة **سببها الوحيد له صياغة بطارية/فجوة-فئة** (نفس الدائرية) لفحصك اليدوي. أرقام الختم الحالية: 75/111.")
md.append("")
for app, flags in seal_flags.items():
    n_circ = sum(1 for f in flags if not f["independent_ground_also"])
    md.append(f"### {app} — {len(flags)} تسمية بصياغة بطارية، منها **{n_circ} بلا سبب مستقل مذكور**")
    for f in flags:
        mark = "⚠️ فحص" if not f["independent_ground_also"] else "✓ لديه سبب مستقل أيضاً"
        md.append(f"- {f['label']}: {f['reason']} — {mark}")
    md.append("")
md.append("## 3. التوصية")
md.append("")
md.append("1. اعتماد التعريف v2 (الوثيقة) وأمر إعادة الختم بالسبب الموثق «مراجعة خارجية وجدت دائرية منهجية».")
md.append("2. Juice Shop: الأرقام الجديدة أعلاه (measurable " + str(v2_counts.get('measurable', 0)) + "/116).")
md.append("3. المجموعة المعزولة: فحص الـ⚠️ أعلاه (خاصة Security Shepherd وVAmPI) ثم إعادة ختم بجدول أسباب برموز.")
md.append("4. تحديث SPEC §1 للإحالة إلى الوثيقة الموحدة؛ SPEC الحالي يذكر three-way لكن الختم يستخدم two-way — هذا هو التناقض الذي وجدته المراجعة المستقلة.")
OUT.write_text("\n".join(md), encoding="utf-8")
print(f"wrote {OUT}")
print(f"v1: {v1_counts}  →  v2: {v2_counts}")
print(f"flips: oos→meas={len(flips['oos_to_meas'])} oos→naa={len(flips['oos_to_naa'])} meas→other={len(flips['meas_to_oos'])+len(flips['meas_to_naa'])} stays={flips['stays']}")
print("seal flags per app:", {a: sum(1 for f in fl if not f['independent_ground_also']) for a, fl in seal_flags.items()})

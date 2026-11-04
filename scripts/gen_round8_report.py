#!/usr/bin/env python3
"""Round-8 closure report (docx) — part by part, real numbers only.

Phrasing discipline (the order's own rule): no claim of absolute
perfection or permanence; every "found/clean" statement is scoped to
"these specific methods, run on this specific date".
"""
import json
import os

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

ROOT = "/home/z/my-project"
OUT = os.path.join(ROOT, "download", "round8-closure-report.docx")

doc = Document()
style = doc.styles["Normal"]
style.font.name = "Arial"
style.font.size = Pt(10.5)
style.element.rPr.rFonts.set(qn("w:cs"), "Arial")
style.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT


def para(text, bold=False, size=None, color=None, align=None):
    p = doc.add_paragraph()
    p.paragraph_format.alignment = align or WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run(text)
    r.bold = bold
    if size:
        r.font.size = Pt(size)
    if color:
        r.font.color.rgb = RGBColor(*color)
    r.font.name = "Arial"
    r._element.rPr.rFonts.set(qn("w:cs"), "Arial")
    return p


def heading(text, level=1):
    sizes = {1: 14.5, 2: 12}
    colors = {1: (0x1F, 0x3A, 0x5F), 2: (0x2E, 0x5A, 0x88)}
    para(text, bold=True, size=sizes[level], color=colors[level])


def bullet(text):
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run("• " + text)
    r.font.size = Pt(10.5)
    r.font.name = "Arial"
    r._element.rPr.rFonts.set(qn("w:cs"), "Arial")


def site(fid, title, desc):
    p = doc.add_paragraph()
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    r = p.add_run(f"{fid} — {title}: ")
    r.bold = True
    r.font.size = Pt(10.5)
    r.font.name = "Arial"
    r._element.rPr.rFonts.set(qn("w:cs"), "Arial")
    r2 = p.add_run(desc)
    r2.font.size = Pt(10.5)
    r2.font.name = "Arial"
    r2._element.rPr.rFonts.set(qn("w:cs"), "Arial")


para("تقرير إغلاق الجولة الثامنة — التقسية المستمرة الصارمة", bold=True,
     size=18, color=(0x1F, 0x3A, 0x5F), align=WD_ALIGN_PARAGRAPH.CENTER)
para("مسح الأنماط المضادة من الطرف الأعلى، سجل الأهداف المرخصة، والتقسية المجدولة",
     size=11.5, align=WD_ALIGN_PARAGRAPH.CENTER)
para("التاريخ: 2026-11-03/04 · الفرع: strict-hardening-r8 (مدمج في main عبر "
     "PR #33، التزام الدمج 8e2effb) · الالتزامات: b85e452 ← ea2027f",
     size=9.5, color=(0x66, 0x66, 0x66), align=WD_ALIGN_PARAGRAPH.CENTER)
para("لغة الأمانة المعتمدة في كل هذا التقرير: «لا عيوب أخرى وجدت في هذه "
     "الجولة، بهذه الطرق المحددة» — لا ادعاء كمال أو ديمومة في أي موضع.",
     size=9.5, color=(0x8A, 0x4A, 0x11), align=WD_ALIGN_PARAGRAPH.CENTER)

heading("الجزء 1 — المسح الساكن من الطرف الأعلى")
para("تحقق الانحدار أولاً: أُعيد تشغيل ماسح «الاختيار الموقعي» من الجولة "
     "السابعة على الشجرة الحالية — صفر مواضع جديدة غير معالجة (دلتا الخام "
     "+1 = مسار احتياطي في jrand.py يجمع بسقف 4 مطابقةً لمسار numpy، وليس "
     "اختياراً أولياً).")
para("ثم الماسح الموسع (scripts/audit_antipatterns.py) فوق فئات أربع جدي��ة: "
     "ابتلاع الاستثناء الصامت، شرط الحافة off-by-one، ترتيب حساب الميزانيات، "
     "ونمط TOCTOU — مع حمل فئات الجولة السابعة كاملة في أداة واحدة. "
     "الأرقام الفعلية لهذه الجولة: 174 ملف بايثون متتبعاً، 345 موقعاً خاماً، "
     "منها 253 داخل المحرك — كل واحد قُرئ سطراً بسطر في ثلاث دفعات مراجعة، "
     "لا تصنيف آلي بلا قراءة. صفر مواضع OFF_BY_ONE في المحرك كله.")
site("R8-AP-01", "العيب الحقيقي الوحيد المكتشف (أُصلح بزوج أحمر→أزرق)",
     "حلّال علاقة uniquifier في jrand كان يبتلع فشل استيراد numpy داخل "
     "«except» ويعيد قائمة فارغة — أي فشل تثبيت حقيقي (عدم توافق ABI مثلاً) "
     "يُقرأ من أي مستدعٍ مباشر كأنه «لا توجد علاقة»: سالب كاذب صامت، وهو "
     "الشكل الذي يحرّمه مذهب المشروع. أُزيل ابتلاع الاستيراد ليتصاعد الفشل "
     "إلى مسجل أعطال الطور؛ غياب numpy يبقى عبر بوابة FM-21d الصوتية أعلى "
     "السلسلة. الإثبات: اختبار التمييز يفشل على الكود القديم (رفضه كان "
     "يتحول إلى [] بلا رفع) ويمر على المصلح؛ 17/17 على المجموعة بعد الإصلاح.")
para("كل موقع من الـ253 حصل على إدخال في دفتر المراجعة "
     "(scripts/antipattern_review_ledger.json) بحكم معلل — العائلات: "
     "probe-until-verdict للكسر عند الحكم (121)، تحليل متسامح لمدخلات الهدف "
     "الممسوح ذاته (60)، اختيار-استشهادي للفهرسة (26)، فشل-مغلق كافتراض آمن، "
     "قراءة سباق حالة محلية تنهار للمعالج المجاور، تنظيف أفضل-جهد، وحلقات "
     "تقارب رياضية. البوابة --ci-gate ترفض أي موقع محرك بلا إدخال دفتر — "
     "وقد أثبتت نفسها على كود هذه الجولة نفسها: موضعا authorized_targets.py "
     "الجديد اكتُشفا بواسطتها ثم دُوّنا. البوابة أصبحت خطوة في جدار CI عند "
     "كل push، فأي كود جديد يحمل نمطاً غير مدوّن يفشل البناء.")

heading("الجزء 2 — سجل الأهداف المرخصة")
para("authorized-targets.json في جذر المستودع هو الآن المصدر الوحيد للحقيقة "
     "لما يجوز مسحه حياً. بوابة burhan/authorized_targets.py تعمل قبل أول "
     "طلب في كلتا نقطتي الدخول الحيتين (سكربت التحقق الحي وسكربت الهدف "
     "الحقيقي في CI): هدف غير مدرج = لافتة رفض كاملة + رمز خروج 2 + صفر "
     "طلبات مسح — مثبت end-to-end على السكربت الفعلي نفسه (اللافتة على "
     "stdout وstderr، ولا ملف نتيجة يُكتب).")
para("أنواع الإثبات الثلاثة المطلوبة، تُتحقق وقت المسح لا مرة واحدة: "
     "(أ) سجل DNS TXT عبر استعلام حي؛ (ب) خطاب تفويض موقّع مخزّن في "
     "المستودع يُعاد حساب sha256 له عند كل مسح؛ (ج) صفحة الترخيص المنشورة "
     "للهدف نفسه تُجلب حية وتُطابق حرفياً مع اقتباس مثبّت في السجل — "
     "اختفاء الاقتباس عن الصفحة = رفض (سياسة الهدف قد تغيّرت).")
bullet("ginandjuice.shop: الاقتباس المثبّت جُلب حياً بتاريخ 2026-11-03 من "
       "الصفحة («This is a deliberately vulnerable web application designed "
       "for testing web vulnerability scanners» — PortSwigger Ltd.).")
bullet("vulnweb.com: الحالة pending-quote-pin — الاقتباس الحرفي لم يكن "
       "قابلاً للجلب من صندوق هذه الجولة (الخروج للشبكة محجوب) ولم يُخترع: "
       "البوابة ترفض كل مسح vulnweb حتى يثبّت المالك الاقتباس المُلاحظ "
       "(الرفض يطبع الجملة المرشحة التي رصدها الجلب كي يثبّتها المالك).")
para("12 اختباراً تثبت: رفض الهدف غير المدرج (على الدالة وعلى السكربت "
     "الفعلي end-to-end)، السماح الذاتي للحاويات المحلية، السماح عند "
     "تطابق الاقتباس، الرفض عند اختفائه، الرفض عند فشل الجلب، الرفض "
     "pending-pin، تحقق/رفض DNS TXT، تحقق/رفض الخطاب عند العبث، ورفض "
     "السجل التالف/المفقود صوتاً. لم تُضف أهداف جديدة بأمر هذه الجولة — "
     "الآلية فقط.")

heading("الجزء 3 — التقسية المستمرة في CI")
para("سكربت scheduled_hardening.py يشغّل بوابات الجدار نفسها عند الطلب أو "
     "أسبوعياً (سير العمل continuous-hardening.yml، الاثنين 04:23 UTC): "
     "بوابة الماسح، فحوص doctor التسعة عشر، مجموعة pytest كاملة، بوابة "
     "البنشمارك بالسجل الملتزم (F1=1.0، TP=38، FP=0)، وقابلية الإعادة "
     "(تنفيذان مستقلان بمخرجات متطابقة بايت-ببايت).")
para("آلية تتبع الفشل (لا فشل صامت أبداً): عند أي فشل يفتح السكربت issue "
     "متتبعاً واحداً لكل فحص فاشل عبر API برمز الجري (صلاحية issues:write "
     "فقط)، مع منع التكرار بالبحث عن issue مفتوح يحمل نفس بادئة العنوان "
     "وشارة scheduled-hardening — وجد: يُضاف الحدوث الجديد كتعليق؛ لم "
     "يوجد: يُفتح issue جديد. الجري الأحمر نفسه يبقى السجل المرئي.")
para("إثبات المسار السعيد المحلي بتاريخ 2026-11-03: 5/5 فحوص خضراء "
     "(بوابة الماسح 1.3 ث، doctor 8.1 ث، pytest 102.6 ث، البنشمارك 102.7 ث "
     "بالأرقام الحرفية P/R/F1 = 1.0/1.0/1.0 و TP=38 FP=0 FN=0 TN=37، "
     "وقابلية الإعادة 103.6+104.4 ث). صنف حادثة numpy السابقة هو بالضبط "
     "ما يلتقطه هذا الجدول: الاعتماديات تنزلق بين الدفعات.")

heading("الجزء 4 — التحقق الحي على الأهداف المرخصة الحالية")
para("أُعيد إطلاق التحقق الحي الكامل (كل طبقات الكشف بما فيها BFLA ومسبار "
     "السباق وshadow/zombie وجميع عائلات JWT) على crAPI v1.1.5 + DVGA "
     "بالمحرك المصلح على main المدمج (8e2effb، التشغيلة 41750687823، "
     "2026-11-04T01:01Z) بعد دمج PR #33. بوابة الترخيص سمحت بالحاويات "
     "الذاتية المبنية داخل الجري نفسه (إدخال self-hosted-fixtures).")

# ---- live comparison numbers (filled from the downloaded artifact)
try:
    live = json.load(open(os.path.join(
        ROOT, "download", "r8-live", "live", "live-validation.json")))
    base = json.load(open(os.path.join(
        ROOT, "download", "baseline-live-r7", "live", "live-validation.json")))
    for t in ("crapi", "dvga"):
        ln = live["results"][t]
        bs = base["results"][t]
        para(f"{t}: {ln['wall_seconds']} ث، {ln['requests']} طلباً، "
             f"{ln['findings_total']} نتيجة (خط الأساس: {bs['requests']} "
             f"طلباً، {bs['findings_total']} نتيجة).", bold=False)
        lkm = {(f["type"], f["url"]): f["sha256"] for f in ln["modern2_findings"]}
        bkm = {(f["type"], f["url"]): f["sha256"] for f in bs["modern2_findings"]}
        same = [k for k in bkm if k in lkm and lkm[k] == bkm[k]]
        regressed = [k for k in bkm if k not in lkm]
        newf = [k for k in lkm if k not in bkm]
        if same:
            para("أُعيد إنتاجها بـ SHA-256 مطابق حرفياً: " + "; ".join(
                f"{k[0]} @ {k[1].split(':8888')[-1]}" for k in same))
        if newf:
            para("نتائج جديدة في هذه الجولة: " + "; ".join(
                f"{k[0]} @ {k[1]}" for k in newf))
        if regressed:
            para("انحدار (نتائج خط الأساس لم تتكرر): " + "; ".join(
                f"{k[0]} @ {k[1]}" for k in regressed))
        if not newf and not regressed:
            para("لا نتائج جديدة ولا انحدار في هذه الجولة، بهذه الطرق "
                 "وعلى هذين الهدفين وتاريخهما — نتيجة الاستنساخ أعلاه هي "
                 "الأمانة الكاملة.")
except FileNotFoundError as e:
    para(f"[أدلة التشغيل الحي تُدرج عند توفرها في download/r8-live/ — {e}]",
         color=(0x8A, 0x4A, 0x11))

heading("النظافة المصرح بها والحالات الجزئية")
para("بإذن «حذف غير المهم والمكرر»: 87 ملف pyc متتبعاً أُزيل من التتبع مع "
     ".gitignore؛ stash قديمان محتواهما pyc فقط (تحقق قبل الإسقاط) أُسقطا؛ "
     "ثلاثة سكربتات مساعدة للجولة السابعة غير متتبعة ومكررة حُذفت. حادثة "
     "تُسجَّل بأمانة: حذفتُ خطأً scripts/ci_fixture_run.py المتتبع "
     "(مرجعيّ مرتين في الجدار) أثناء تلك التمرير — استُعاد فوراً عند "
     "اكتشافه وتدوينه في STATE.md.")
para("المتبقي لجولات قادمة، تسميةً صريحة: (1) تثبيت اقتباس ترخيص vulnweb "
     "الحي من قبل المالك — كل مسح vulnweb يبقى مرفوضاً حتى ذلك الحين؛ "
     "(2) مرشح الجولة 7 (b) في STATE.md (فئة حكم 404-اللاتناظر + تجسيد "
     "معرفات الكائن لنسخ التفاضل) لا يزال موثقاً دون تنفيذ — قراءة سطح "
     "جديدة خارج نطاق هذه الجولة؛ (3) أول تشغيل مجدول فعلي ليوم الاثنين "
     "سيشغّل الآلية في بيئة GitHub الحية — أُثبت مسارها السعيد محلياً "
     "5/5 وبإطلاق يدوي على main، لكن الجدولة ذاتها لا تُختبر إلا بمرور "
     "موعد الفحص الأول؛ (4) الماسح يغطي بايثون المتتبعة فقط — أنماط TS "
     "في src/ خارج هذا المسح.")

heading("الأرقام الختامية لهذه الجولة")
para("الاختبارات: 281 ← 296 خضراء (3 pins مضادات الأنماط + 12 اختبار "
     "بوابة الترخيص). الماسح: 174 ملفاً، 345 موقعاً خاماً، 253 موقع محرك "
     "مدوّن، بوابة --ci-gate = PASS. عيب حقيقي واحد أُصلح بزوج RED→BLUE "
     "مثبت. سجل الأهداف: آلية كاملة مع 12 اختباراً، صفر أهداف جديدة "
     "بأمر هذه الجولة. الجدار: 9/9 فحوص إلزامية خضراء على رأس الدمج. "
     "سير التقية المجدول على main المدموج: 5/5 خضراء (التشغيلة "
     "41750691170، تقرير scheduled-hardening-report عند 8e2effb). "
     "الاستنساخ الحي: النتيجتان المؤكدتان على crAPI عادتا بـSHA-256 "
     "متطابق حرفياً مع خط الأساس. كل ما في هذا التقرير محصور بطرق هذه "
     "الجولة وتاريخها وأهدافها — لا ادعاء كمال أو ديمومة في أي موضع.")

doc.save(OUT)
print("saved:", OUT)

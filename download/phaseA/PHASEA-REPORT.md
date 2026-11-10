# تقرير المرحلة A — خط الأساس والسلامة (2026-11-10)

**الحالة الإجمالية: PENDING** — كل بنود A منجزة عدا فحص خضرة CI على main بعد الدمج (الإيداع `45d2f4d2d8`، ذيل macOS ينتهي ~00:40Z بعد قطع الجلسة). فحص واحد في الجلسة القادمة يغلق المرحلة.

## A.1 النسخة الاحتياطية — DONE
- `git bundle create --all` → `/home/z/my-project/backups/burhan-phaseA-2026-11-10T22-03.bundle` (442,571,768 بايت)
- sha256: `cb0ab9a433c6a232fc40c8cbbb322b7f2d326432df0b8de43f5fb916e1c676ba` (ملف `.sha256` بجانبه)
- `git bundle verify`: «records a complete history»، ويحتوي `refs/remotes/origin/main = 025caa64bf`

## A.2 خط الأساس — DONE (أرقام من أوامر حرفياً)
- الملفات المتتبَّعة على `origin/main`: **761** (`git ls-tree -r origin/main --name-only | wc -l`)
- دوال الاختبار في `tests/`: **458** (`git grep -c "def test_" origin/main -- tests/` مجموعاً)
- عناصر الجذر: **45** — أبرز الملفات الكبيرة: `evidence/independent-verification/juice-shop-20.3.0/scan_pre_gates.json` (18,558,446 بايت) و`scan.json` (18,542,448) و`evidence/full-reverify/fixtures-vulnapp/scan.json` (10,062,008)
- حجم المستودع: `size-pack: 423.15 MiB` (`git count-objects -vH`)
- CI على main وقتها: تشغيل #555 `in_progress` على `025caa64bf` (والذي حُسم بالفعل في #554 `completed/success` على نفس الإيداع)

## A.3a فحص الأسرار في كامل التاريخ — DONE، **صفر أسرار حقيقية**
- الأداة: `scripts/phaseA_secrets_scan.py` (بثّ سطر-بسطر بعد أن قتل OOM بالتقاط فرق 18MB كاملة) على **628 إيداعاً** (`git rev-list --all --reflog --topo-order`)
- **2415** مطابقة خام، كلها وهمية موثّقة:
  - jwt ×2359: توكنات ديمو من Juice Shop/crAPI/DVGA داخل ملفات evidence (توكنات مولّدة لأهداف فحص معروفة)
  - aws_access_key ×20: `AKIAUNITTESTKEY00001` حرفياً في ملفات `tests/run_tests.py` عبر نسخ build-v4xx/readiness التاريخية
  - rsa_privkey ×24: ترويسات fixtures مبتورة (`-----BEGIN RSA PRIVATE KEY-----\nMIIE...`) ومفتاح Juice Shop الديمو المعلن في مستودعهم
  - generic_high_entropy ×12: `users.yml` وكلمات مرور اختبارات Juice Shop
- **أنماط التوكنات الحقيقية (ghp_/github_pat/xox/npm/gcp/bearer/aws_secret): صفر مطابقات**
- ملف `.env` الوحيد في التاريخ (35 إيداعاً حاملاً، أُضيف `9e9037c` 2026-10-03 وحُذف `88fa11c` 2026-10-17): قيمته `DATABASE_URL=file:/home/z/my-project/db/custom.db` — مسار sqlite محلي، والتوثيق المعاصر في worklog يؤكد مرتين «no secret leak»
- **القرار: لا filter-repo، لا تنظيف تاريخ** — لا يوجد ما يُنظَّف

## A.3b حماية البوابة — DONE (PR #93 مدموج)
- الفرع `phaseA/secrets-guard` من `origin/main`/`025caa64bf`؛ worktree نظيف (`/home/z/my-project/burhan-phaseA`)
- `scripts/audit_tree_hygiene.py`: قواعد DENY جديدة لملفات بيانات الاعتماد (`.secrets/`، `.env`/`.env.*`، `*.pat|*.pem|*.key`، `id_rsa`/`id_ed25519`) + `CREDENTIAL_ALLOWLIST` مراجَع لـ`.env.example` (القالب، placeholder فقط)
- `.gitignore` امتُدح بالتوازي (`.secrets/`, `.env`, `.env.*`, `!.env.example`, `*.pat`, `*.pem`, `*.key`, `id_rsa*`)
- **الأحمر**: الاختبار الجديد على الأساس `025caa64bf` (بوابة غير معدلة): **4 failed, 1 passed** (الخامس فحص الشجرة الحية — ثابت ينجح قبل وبعد)
- **الأخضر**: 5/5 + انحدارات r16/r17 خضراء + البوابة على الشجرة الحية `rc=0` + **الحزمة المحلية كاملة: 588 passed, 1 skipped (494.90s)**
- **طفرات M1-M5 كلها قُتلت**: نقلب نمط `.secrets` → فشل 1؛ إسقاط ed25519 → فشل 1؛ إسقاط `.key` → فشل 1؛ إسقاط `.env.local` → فشل 1؛ تحويل allowlist إلى `.env.local` → فشل 3. البوابة أُعيدت بايت-ببايت بعد كل طفرة
- **PR #93**: 31/31 أخضر على الرأس `d02fa7e` (شاملة macOS ×2 ومهمة Tree hygiene ×2 success) → دُمج **`45d2f4d2d8`**

## ما لم يكتمل ولماذا
1. **فحص خضرة main على `45d2f4d2d8`**: ذيل macOS يحتاج ~65 دقيقة من الدمج (23:57Z) — بعد قطع الجلسة. فحص واحد يحسمه (`GET /commits/45d2f4d2d8.../check-runs`).
2. تقريرك: ملف الاستئناف `download/phaseA/PHASEA-RESUME.json` محفوظ **داخل الفرع** (إيداعا `49b21af`, `d02fa7e`, `1beedac`) — لا في /tmp.

## ملاحظات بيئية
- نسخة `/home/z/my-project/burhan` الرئيسية كانت قديمة (فرع r15، رأس `217ce0b`، 580 تعديل وضع-فقط) — لم تُمَس؛ كل عمل المرحلة في worktree نظيف
- `.env*` في .gitignore يسمح لملف التطوير المحلي بالبقاء على القرص دون أن يلتقطه `add -A` يوماً ما

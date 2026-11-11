# Burhan — DAST Platform (axes 1-18, final build v5.0.0 — the Burhan rename release)

[![CI](https://github.com/mememamaly-oss/burhan/actions/workflows/ci.yml/badge.svg)](https://github.com/mememamaly-oss/burhan/actions/workflows/ci.yml)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm--Shield--1.0.0-orange)](LICENSE)
[![Release](https://img.shields.io/badge/release-v5.2.0-blue)](https://github.com/mememamaly-oss/burhan/releases)

منصة فحص اختراق تطبيقات الويب الآلي (DAST) — المحرك (Python stdlib نقي) + تطبيق
إدارة SaaS (Next.js). هذا المستودع مُنظّف تشغيلياً: كود المحاور 1-18 فقط.

كل نتيجة فحص موقّعة (Ed25519 فوق جذر Merkle فوق النتائج) وقابلة للتحقق
المستقل بلا أي كود من هذا المشروع — انظر «سجل الشفافية» أدناه.

## أثبت نتيجة واحدة

التحقق لا يستورد كود المحرك. التقرير الموقّع هو مخرجات أمر `report`، لا ملف `--out` الخام.

```bash
python3 -m burhan.cli scan http://127.0.0.1:PORT --db store.db --allow-private --seed demo
python3 -m burhan.cli report --db store.db --format json --out report.json
pip install cryptography
python3 tools/independent_verify.py verify-report report.json
```

الأمر الأخير يخرج 0 إذا طابق جذر Merkle والتوقيع النتائج. غيّر حرفاً واحداً داخل `findings` في `report.json` وأعد الأمر: يخرج 1. هذا هو العقد، بلا مقارنة بأدوات أخرى.

معاملات الاستعلام المخبأة في قوالب SPA (`/rest/products/search?q=${criteria}`) تُسجَّل دائماً ولا تُفحَص إلا مع `--spa-query`. العلم مطفأ افتراضياً حتى تبقى أرضية Juice Shop المنشورة ثابتة تحت ميزانية الطلبات.

ترخيص تجاري منفصل عن PolyForm Shield: [COMMERCIAL.md](COMMERCIAL.md).

## بنية المستودع

| المسار | الوصف |
|--------|-------|
| `burhan/` | محرك الفحص الكامل — كل المحاور 1-18 (بما فيها `race/` و`symbolic/`) |
| `perf/` | طبقة أداء المحور-10 (actors / aio / columnar) — يستوردها `burhan/infra.py` |
| `src/` | تطبيق SaaS (Next.js 16 + Prisma) — الواجهة والإدارة |
| `prisma/` | مخطط قاعدة بيانات التطبيق |
| `scripts/` | سكربتات التشغيل (بدء الخادم + بيانات العرض) |
| `Caddyfile` | بروكسي الإنتاج |

## تشغيل المحرك مباشرة (CLI)

```bash
python3 -m burhan.cli scan <url> --out result.json --db store.db [opts]
python3 -m burhan.cli reproduce --db store.db --finding F-xxx
python3 -m burhan.cli report --db store.db --run-id <run> --format html --out report.html
python3 -m burhan.cli compliance [--json]   # سجل خرائط OWASP/CWE/PCI لكل مكتشف
python3 -m burhan.cli doctor
```

أعلام المحور-17/18 (اختيارية): `--race`, `--symbolic` (افتراضياً OFF).

كل مكتشف يحمل خريطة الامتثال الخاصة به (`compliance` في كل نتيجة داخل
result.json وفي كل تقرير — HTML/JSON/SARIF/EXECUTIVE/GLASS): OWASP Top 10
(2021 + النسخة النهائية 2025)، CWE، ومتطلب PCI DSS 6.4.2 (= 6.6 في
v3.2.1). وسم المصدر مصاحب لكل خريطة: `official` (الـCWE مذكور في قائمة
الفئة الرسمية — top10.owasp.org) أو `scope` (تصنيف تحريري معلن).

## تشغيل تطبيق SaaS

```bash
bun install
cp .env.example .env                       # + NEXTAUTH_SECRET = openssl rand -base64 32
bash scripts/pg_dev_start.sh               # عنقود PostgreSQL محلي (127.0.0.1:55432، بلا جذر وبلا docker)
bunx prisma migrate deploy               # ترحيلات حقيقية (ليست db push)
bash scripts/run_integration_tests.sh     # الجناح الكامل عبر الخادم الحقيقي
bun run dev                                # خادم تطوير :3000
# أو الإنتاج:
bun run build && bash scripts/start_prod_server.sh
python3 scripts/bootstrap_demo_data.py   # (اختياري) بيانات عرض عبر التدفق الحقيقي
```

قاعدة المنصة PostgreSQL (P2-D)؛ مخازن المحرك لكل هدف تبقى SQLite عمداً
(حتمية، ملف لكل هدف تحت `saas-data/stores`). للنشر: `docker-compose.yml`
(postgres:17) + `bash scripts/verify_postgres.sh`.

الصفحات العامة: `/` (هبوط) و`/docs` و`/docs/compliance` و`/demo` (فحص حقيقي
واحد ضد الـfixture المُدار) — المنصة نفسها خلف تسجيل الدخول مع حرس
جانب الخادم (`src/app/(app)/layout.tsx`).

CI: ملف واحد `.github/workflows/ci.yml` (تسع وظائف: التطبيق على PostgreSQL
حقيقي، المحرك، فحص الأسرار، فحص fixture حقيقي على إعدادات الحملة نفسها +
بوابة F1==1.0/TP==38/FP==0، حارس انجراف سجل الامتثال، هدف حقيقي
OWASP Juice Shop بأرضية مُلزِمة، شهادة قابلية إعادة الإنتاج بتشغيلين
مستقلين، سجل الشفافية، وتجربة الـAction كمستهلك خارجي) وقالب GitLab
`integrations/gitlab-ci/sen-scan.gitlab-ci.yml`، إضافة إلى فحص CodeQL
(يعمل عند التحول للعامة).

المحرك يُستدعى من التطبيق عبر `src/lib/engine.ts` (subprocess CLI — `ENGINE_DIR`
افتراضياً جذر المستودع، قابل للتغيير بمتغير `BURHAN_ENGINE_DIR`).

## فحص الأسرار قبل الالتزام

`pre-commit install` مرة واحدة — خطاف gitleaks (`.pre-commit-config.yaml`)
يفحص كل تغييرات staged قبل الالتزام.

## استخدام المحرك كـ GitHub Action (سطر واحد في أي CI)

```yaml
- uses: mememamaly-oss/burhan@v4.5.0
  with:
    target: http://127.0.0.1:8080
    fail-on: high          # افشل المهمة عند وجود نتائج high فأعلى
```

المدخلات والمخرجات الكاملة وقيود المتصفح (Playwright): `docs/github-action.md`.

## سجل الشفافية والتحقق المستقل

كل نتيجة فحص غنيّة تحمل قسماً موقّعاً (`audit`): جذر Merkle فوق النتائج
(مع استبعاد الحقول الطائرة المعلنة) + توقيع Ed25519 فوق الهضم المركب.
سجل `transparency-log/log.jsonl` يضيف طبقة المشروع: سلاسل هاش مترابطة
موقعة بمفتاح المستودع المعلن `transparency-log/pubkey.hex`.

التحقق لا يحتاج أي كود من المشروع:

```bash
pip install cryptography
python3 tools/independent_verify.py verify-report result.json
python3 tools/independent_verify.py verify-log transparency-log/log.jsonl \
    --pubkey transparency-log/pubkey.hex
```

المحقق `tools/independent_verify.py` لا يستورد شيئاً من المحرك — أي خلل في
الموقّع لا يمكن أن يختبئ في محقق يشاركه الكود. المواصفة الكاملة:
`docs/transparency-log-format.md`.

## دعم ويندوز (Windows)

خضع المستودع في 2026-11-07 لتدقيق حي على ويندوز (الجولة 17) أصلح ثمانية
اكتشافات عابرة للمنصات، وكلها مدمجة مع اختبارات RED→BLUE دائمة:

- **يعمل الآن**: تشغيل المحرك والسويت الكاملة على ويندوز — تعليق الإصلاحات
  على مسارات الفواصل المعكوسة (`\`) ومحركات الأقراص (`C:`)، وترميز UTF-8
  صريح في كل مواقع الكتابة الخمسة عشر (نصوص عربية في التقارير تُكتب
  سليمة)، وامتداد البيئة الموروثة عند إطلاق الـfixtures (متغيرات Winsock
  مثل `SYSTEMROOT` تصل إلى العملية)، وخروج `doctor` برمز 1 عند فشل أي فحص.
- **خزنة الأسرار (vault) على ويندوز — مغلقة بصرامة ومرتفعة الصوت**: وضع
  الخزنة يتعطل على ويندوز لغياب `keyring` صالح، والسلوك الآن فشل مغلق
  (fail-closed) مع رسالة واضحة ومسار المعالجة، ويؤثر فقط على أوضاع
  الإخراج التي تطلب الخزنة صراحة. التنفيذ الفعلي لخلفية ويندوز متتبع في
  [الissue #61](https://github.com/mememamaly-oss/burhan/issues/61).
- **الإسناد**: تدقيق ويندوز وإصلاحات الجولة 17 تمّ عبر وكيل Qoder بعد
  16 جولة سابقة مع GLM.

## خارطة طريق الامتثال والنضج الأمني

يوجد مسار نضج أمني ومتطلبات امتثال (تقييم اختراق خارجي، وجهوزية SOC 2 عند
الحاجة التجارية) يُدار ويُحدَّث خارج هذا المستودع العام؛ تُعلن هنا نتائجه
الناضجة (تقارير ملخصة بعد المعالجة) عندما تكتمل.

## الترخيص

ترخيص **PolyForm Shield 1.0.0** — النص الكامل في `LICENSE` (منسوخ حرفياً من
[polyformproject.org](https://polyformproject.org/licenses/shield/1.0.0)).

بلغة مباشرة، دون مصطلحات قانونية:

- **الكود مفتوح للقراءة والدراسة والاستخدام والمساهمة**: يمكنك تشغيله وتعديله
  ودمجه داخل منتجاتك وأدواتك الداخلية، لأي غرض لا ينافس المنتج نفسه.
- **الممنوع الجوهري الوحيد**: تقديم هذا المنتج (أو نسخة منه) لمستخدمين
  خارجيين كخدمة مستضافة (hosted) أو أداة تُباع — أي منتج **ينافس** ما يقدمه
  المالك من خلال هذا البرنامج. هذا الاستخدام يحتاج ترخيصاً تجارياً منفصلاً
  ومكتوباً من المالك.
- **عند توزيع نسخ أو تعديلات**: مرّر نص الترخيص (أو رابطه) مع كل نسخة، مع
  سطر `Required Notice` الموجود أعلى ملف `LICENSE`.

**سجل تغيير الترخيص (للشفافية)**: كان المستودع تحت Apache-2.0 من 2026-10-31
01:38 UTC (الالتزام `ff8af33` الذي أضاف أول ملف LICENSE) حتى هذا التغيير
(2026-10-31). أي نسخة نُسخت (clone/fork) خلال تلك النافذة تبقى محكومة
بترخيص Apache-2.0 لتلك النسخة تحديداً — هذا التغيير لا يسحب ذلك بأثر رجعي.
قبل `ff8af33` لم يكن في المستودع أي ملف ترخيص أصلاً، رغم أن المستودع كان
عاماً منذ إنشائه في 2026-10-02.

## ملفات المجتمع

`CONTRIBUTING.md` · `CODE_OF_CONDUCT.md` · `SECURITY.md` (الإفصاح المسؤول
عن ثغرات في الأداة نفسها) · قوالب Issues/PR تحت `.github/`.

## حذف عمداً في تنظيف 2026-10-23 (قابل للاستعادة من وسم `backup/pre-clean-2026-10-23`)

الاختبارات (tests)، fixtures، benchmarks، نتائج الحملات (campaign, saas-data,
audit-results)، أدلة التحقق (INDEPENDENT_*.md)، نسخ build-v400..v430 القديمة،
وثائق المحاور والأرشيفات (docs, PHASE_02, release-archives)، و~125 سكربت حملات.


## ترحيل الإعدادات من الإصدارات قبل v5.0.0 (إعادة التسمية إلى برهان / Burhan)

أعيدت تسمية المشروع من Sen/SENTINEL إلى **برهان / Burhan** في v5.0.0. هذا تغيير كاسر
للنشرات القائمة. المتغير القديم يظل يعمل مع **تحذير واضح عند الإقلاع** (وليس تجاهلاً
صامتاً)، وسيُزال في إصدار رئيسي لاحق:

| قبل v5.0.0 | اعتباراً من v5.0.0 |
|---|---|
| `SENTINEL_ALLOW_PRIVATE_TARGETS` | `BURHAN_ALLOW_PRIVATE_TARGETS` |
| `SENTINEL_DATA_DIR` | `BURHAN_DATA_DIR` |
| `SENTINEL_PYTHON` | `BURHAN_PYTHON` |
| `SENTINEL_ENGINE_DIR` | `BURHAN_ENGINE_DIR` |
| `SENTINEL_TARGET_URL` | `BURHAN_TARGET_URL` |
| `SENTINEL_TIMEOUT` | `BURHAN_TIMEOUT` |
| `SENTINEL_MAX_PAGES` | `BURHAN_MAX_PAGES` |
| `SENTINEL_TEST_FILTER` | `BURHAN_TEST_FILTER` |

تغييرات كاسرة أخرى في v5.0.0:

- حزمة بايثون `sentinel/` أصبحت `burhan/` — استدعاء CLI: `python3 -m burhan.cli …`
- اسم الحزمة في `package.json` أصبح `burhan-saas`، وواجهة GitHub Action أصبحت
  `Burhan DAST scan` مع ملف نتيجة افتراضي `burhan-result.json`
- خدمة قاعدة البيانات في docker-compose: المستخدم/القاعدة `sentinel` أصبحا `burhan`
  (`POSTGRES_USER`/`POSTGRES_DB`) — أعد إنشاء الحاوية بعد السحب
- وظائف قالب GitLab CI أعيدت تسميتها (`sentinel:scan` → `burhan:scan`) واسم الملف
  أصبح `integrations/gitlab-ci/burhan-scan.gitlab-ci.yml`
- روابط الويب وعمليات git القديمة (`github.com/mememaly-oss/Sen`) تُحوَّل تلقائياً
  إلى `mememamaly-oss/burhan`، ومراجع Action القديمة
  (`uses: mememamaly-oss/Sen@<tag>`) **ظلت تعمل في الاختبار الحي**
  (2026-10-31: `Sen@v4.5.0` اكتمل فحصاً موقّعاً كاملاً عبر التحويل) — لكن
  توثيق GitHub ينص على أنها قد تتوقف، فالتحويل **مُلاحَظ يعمل وليس ضمانة**؛
  يُنصح بالانتقال إلى `mememamaly-oss/burhan@v5.0.0` (وتراقب وظيفة CI
  «LEGACY pre-rename ref» السلوك الفعلي على كل تشغيل يدوي)

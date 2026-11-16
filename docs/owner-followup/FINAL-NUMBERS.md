# الأرقام النهائية لهذه المحطة (كل رقم من ناتج أمر مطبوع في المحادثة)

## فحوص PRs (قراءة check-runs للـSHA الكامل — scripts/check_pr_heads.sh)
| PR | الرأس | النتيجة |
|---|---|---|
| #115 | 2afe5996b0f3693aa7a64f076e114325dde72f7e | 30/30، 26 success + 4 skipped، صفر فشل |
| #120 | e1e6c2cd8e00b587c1b3c6d45c638e7918e | 30/30، ALL GREEN |
| #121 | 711aca54b593d673e93205b7fdefefa046bc8f0d | 30/30، ALL GREEN (يشمل 5.3.0) |
| #122 | a41e8e11feb2a050ba09912725e69c9bf217d6d5 | 30/30، ALL GREEN |
| #119 | 757bb5f... (الحالي) | 28/30 مكتمل، 24 success + 4 skipped، صفر فشل — 2 queued (macOS) عند آخر قراءة |

## الطفرات (السكربت scripts/mutation_ownership.py)
- run5/6: 432 طفرة، 328 قتل، 104 نجا = 75.9% (run6 بصورت صحيحة للإحداثيات)
- **run7: 432 طفرة، 352 قتل، 80 نجا = 81.5% — فوق حد 80%**
- run8 (نهائية على 757bb5f): كانت جارية عند قطع المحطة — النتيجة ستظهر في mutation-results.txt
- المسار: 64.8% → 75.9% → 81.5%
- الناجيات الـ80: كلها تجميلية/توثيقية/فاشلة-نحو-الأمان (صفر انقلاب أمني) — التصنيف في MUTATION-CLASSIFICATION.md

## اختبارات القتل المضافة (كلها خضراء)
- test_mutation_kills.py: 20/20 (K1-K9)
- test_mutation_kills2.py: 11/11 (F1-F4 انقلابات أمنية + L1-L5 منطق)
- مجموعة حكم الطفرات الأساس: 83 passed / 3 deselected

## lab_mode (وضع مختبري صريح)
- الوحدة: burhan/lab_mode.py (متغير BURHAN_LAB_MODE + علم --lab، يسجل stats.lab_mode في كل تقرير)
- اختباراتها: 20/20 (منها: غيابه يرفض الهدف الخاص — خروج 2 وبانر — ووجوده يسمح)
- مواضع التفعيل المصلحة: action.yml (input lab)، dogfood (lab:true)، JuiceShop (env)،
  engine.ts (--lab مع allowPrivate)، route.ts demo (--lab) — المدخل الرابع اكتُشف بفشل CI وأُصلح

## تشخيص فشول #119 التاريخية (كلها بقراءة سجلات)
- d093d54 (6 فشول): الوضع المختبري يعمل كما صمم و3 وظائف CI لا تفعله
- 6f71aa6 (فشلا SaaS): route.ts ينقصه --lab؛ CodeQL ظاهري (نجح في run مستقل)
- b82e9f2 (CodeQL حقيقي): تحذيرا full-ssrf وincomplete-substring — سُددا في 757bb5f
- 757bb5f: صفر فشل حتى آخر قراءة (28/30 مكتمل)

# أثر تعريف التصنيف v2 على الأرقام — للمراجعة قبل أي ختم

**أمر المالك 2026-11-15، البند 3. لا ختم جديد قبل الموافقة.** المصدر: `docs/process/CLASSIFICATION-DEFINITION.md`.

## 1. Juice Shop (مرجع الـ116) — القرار معاد من النص الرسمي بقاعدة v2

- **v1:** measurable = **46** · out_of_scope = **70** (لا فئة ثالثة مستخدمة)
- **v2:** measurable = **65** · needs_attacker_action = **24** · out_of_scope = **27**

### التحوّلات ولماذا

- **out_of_scope → measurable: 21** — كانت مستبعدة بسبب «لا عائلة بطارية» (الدائري) ولا ينطبق عليها أي سبب مستقل:
  - `Access Log` [Observability Failures] — annotation: battery gap (dev roadmap), NOT excluded
  - `CAPTCHA Bypass` [Broken Anti Automation] — HTTP-observable in principle
  - `Extra Language` [Broken Anti Automation] — HTTP-observable in principle
  - `Forged Signed JWT` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Frontend Typosquatting` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Legacy Typosquatting` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Misplaced Signature File` [Observability Failures] — annotation: battery gap (dev roadmap), NOT excluded
  - `Multiple Likes` [Broken Anti Automation] — HTTP-observable in principle
  - `Privacy Policy` [Miscellaneous] — HTTP-observable in principle
  - `Privacy Policy Inspection` [Security through Obscurity] — HTTP-observable in principle
  - `Score Board` [Miscellaneous] — HTTP-observable in principle
  - `Security Policy` [Miscellaneous] — HTTP-observable in principle
  - `Supply Chain Attack` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Unsigned JWT` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Vulnerable Library` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Exposed Metrics` [Observability Failures] — annotation: battery gap (dev roadmap), NOT excluded
  - `Bonus Payload` [XSS] — HTTP-observable in principle
  - `Local File Read` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
  - `Mass Dispel` [Miscellaneous] — HTTP-observable in principle
  - `Security Advisory` [Miscellaneous] — HTTP-observable in principle
  - `Vulnerable Infrastructure` [Vulnerable Components] — annotation: battery gap (dev roadmap), NOT excluded
- **out_of_scope → needs_attacker_action: 24** — سبب الاستبعاد الوحيد كان auth (فُصلت الفئة في v2):
  - `Password Hash Leak` — auth: requires login / authenticated session / registered account
  - `Admin Registration` — auth: requires login / authenticated session / registered account
  - `Bjoern's Favorite Pet` — auth: requires login / authenticated session / registered account
  - `Change Bender's Password` — auth: requires login / authenticated session / registered account
  - `Ephemeral Accountant` — auth: requires login / authenticated session / registered account
  - `GDPR Data Erasure` — auth: requires login / authenticated session / registered account
  - `Leaked Access Logs` — auth: requires login / authenticated session / registered account
  - `Login Admin` — auth: requires login / authenticated session / registered account
  - `Login Amy` — auth: requires login / authenticated session / registered account
  - `Login Bender` — auth: requires login / authenticated session / registered account
  - `Login Bjoern` — auth: requires login / authenticated session / registered account
  - `Login Jim` — auth: requires login / authenticated session / registered account
  - `Login MC SafeSearch` — auth: requires login / authenticated session / registered account
  - `Login Support Team` — auth: requires login / authenticated session / registered account
  - `Password Strength` — auth: requires login / authenticated session / registered account
  - `Reset Bender's Password` — auth: requires login / authenticated session / registered account
  - `Reset Bjoern's Password` — auth: requires login / authenticated session / registered account
  - `Reset Jim's Password` — auth: requires login / authenticated session / registered account
  - `Reset Morty's Password` — auth: requires login / authenticated session / registered account
  - `Two Factor Authentication` — auth: requires login / authenticated session / registered account
  - `Reset Uvogin's Password` — auth: requires login / authenticated session / registered account
  - `Meta Geo Stalking` — auth: requires login / authenticated session / registered account
  - `Visual Geo Stalking` — auth: requires login / authenticated session / registered account
  - `Login Cloud Admin` — auth: requires login / authenticated session / registered account
- **measurable → خارج measurable: 2** (فحص عكسي — هل يخسر v2 شيئاً ربحه v1؟)
  - `NoSQL DoS` [measurable → out_of_scope] — dos: denial-of-service class — measuring it harms the target
  - `XXE DoS` [measurable → out_of_scope] — dos: denial-of-service class — measuring it harms the target
- **باقية بلا تغيير: 69**

> **تنبيه الصدق:** المقام (measurable) يرتفع وrecall سينخفض تبعاً — ما لا يجده المحرك الآن يُحسب **فائتاً** لا مستبعداً. رمز كل استبعاد مبيّن أعلاه (auth/mobile/tls/dos/multi-step/client-only/non-http/business-logic).

## 2. المجموعة المعزولة المختومة (111، خمسة تطبيقات) — أعلام للفحص البشري

النص الرسمي للتحديات غير متوفر في الشجرة لكل التطبيقات، لذا **لا نعيد قرارها آلياً**؛ نرفع بدل ذلك كل تسمية مختومة مستبعدة **سببها الوحيد له صياغة بطارية/فجوة-فئة** (نفس الدائرية) لفحصك اليدوي. أرقام الختم الحالية: 75/111.

### security-shepherd — 6 تسمية بصياغة بطارية، منها **6 بلا سبب مستقل مذكور**
- Insecure Cryptographic Storage: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص
- Insecure Cryptographic Storage Challenge 1: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص
- Insecure Cryptographic Storage Challenge 2: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص
- Insecure Cryptographic Storage Challenge 3: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص
- Insecure Cryptographic Storage Challenge 4: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص
- Insecure Cryptographic Storage Home Made Key: weak storage in DB/source, not an HTTP-response-observable class in the engine battery — ⚠️ فحص

### railsgoat — 1 تسمية بصياغة بطارية، منها **1 بلا سبب مستقل مذكور**
- password_complexity_spec.rb: policy weakness, not an HTTP-response-observable class — ⚠️ فحص

### vampi — 0 تسمية بصياغة بطارية، منها **0 بلا سبب مستقل مذكور**

### xvwa — 0 تسمية بصياغة بطارية، منها **0 بلا سبب مستقل مذكور**

### wackopicko — 1 تسمية بصياغة بطارية، منها **1 بلا سبب مستقل مذكور**
- Reflected XSS Behind a Flash Form: Flash client rendering — no engine battery class — ⚠️ فحص

## 3. التوصية

1. اعتماد التعريف v2 (الوثيقة) وأمر إعادة الختم بالسبب الموثق «مراجعة خارجية وجدت دائرية منهجية».
2. Juice Shop: الأرقام الجديدة أعلاه (measurable 65/116).
3. المجموعة المعزولة: فحص الـ⚠️ أعلاه (خاصة Security Shepherd وVAmPI) ثم إعادة ختم بجدول أسباب برموز.
4. تحديث SPEC §1 للإحالة إلى الوثيقة الموحدة؛ SPEC الحالي يذكر three-way لكن الختم يستخدم two-way — هذا هو التناقض الذي وجدته المراجعة المستقلة.
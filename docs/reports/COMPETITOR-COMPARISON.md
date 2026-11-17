# M3: ZAP baseline vs Nuclei vs Burhan proof

## الحالة

تم تنفيذ المقارنة على Juice Shop وcrAPI وWebGoat وDVWA فقط داخل شبكة Docker داخلية معزولة. لم تُستخدم phasec أو seal أو أي هدف من المجموعة المعزولة.

- المقارنة المعيارية الأخيرة: [workflow 44085260732](https://github.com/mememamaly-oss/burhan/actions/runs/44085260732)، SHA التشغيل `ba1f2fb8dcd9941ee6a2bd22ccd7b52d1da95934`.
- ZAP active: [workflow 44082410094](https://github.com/mememamaly-oss/burhan/actions/runs/44082410094)، SHA التشغيل `9069d2a00844bf520ef31eb23af05d046035cf75`.
- نمط ZAP في الجدول الأول هو **baseline**. جدول active منفصل في هذا التقرير يستخدم نفس وحدة القياس.
- قوالب Nuclei هي v10.5.0، مع commit مثبت `f8b8b8dcd70d93826c3767e1829ef8243af9f03b` والتحقق من SHA-256 للأرشيف داخل المهمة.
- كلمة مالك Burhan ولدت داخل المهمة، وأخفيت، واستعملت عبر البيئة فقط، ثم حذفت. لم تُحفظ في artifact.

## وحدة القياس والتطبيع

كل رقم هو عدد المسارات المتميزة داخل النوع المعياري، وليس عدد التنبيهات الخام. جُمعت نتائج Burhan حسب النوع المعياري ثم عُرض عدد المسارات؛ لذلك لا يتكرر النوع بسبب كل مسار. صُنفت `info` منفصلة ولا تدخل في حساب فجوة Burhan. `NO-CWE` تعني أن الأداة لم تقدم CWE صالحًا، ولا يجري اختراع CWE بديل.

`SECURITY_HEADERS` تصنيف مشترك يغطي missing_security_headers في Burhan وتنبيهات CSP وclickjacking وX-Content-Type-Options في ZAP. استُبعدت 3 مسارات مستخرجة تالفة من قياس Burhan: `/static/js/'),B=f('` و`/{{href}}`؛ وعدّ الاستبعاد محفوظ في summary.

## جدول baseline المجمّع

# ZAP baseline vs Nuclei vs Burhan proof

| Target | Severity | Standard type | ZAP paths | Nuclei paths | Burhan paths | Evidence | Gap for Burhan? |
|---|---|---|---:|---:|---:|---|---|
| crapi | high | CWE-330 | 0 | 0 | 1 | weak_random | no |
| crapi | high | CWE-522 | 0 | 1 | 0 | Laravel - Sensitive Information Disclosure | yes |
| crapi | high | CWE-552 | 0 | 1 | 0 | Generic Env File Disclosure | yes |
| crapi | medium | SECURITY_HEADERS | 1 | 0 | 0 | Missing Anti-clickjacking Header | yes |
| crapi | low | CWE-693 | 1 | 0 | 0 | Cross-Origin-Resource-Policy Header Missing or Invalid | yes |
| crapi | low | SECURITY_HEADERS | 1 | 0 | 6 | X-Content-Type-Options Header Missing<br>missing_security_headers | no |
| crapi | low | SERVER_BANNER_DISCLOSURE | 1 | 0 | 6 | Server Leaks Version Information via "Server" HTTP Response Header Field<br>server_banner_disclosure | no |
| crapi | info | CWE-524 | 1 | 0 | 0 | Storable and Cacheable Content | no |
| crapi | info | NO-CWE|NUCLEI:OpenResty detection | 0 | 1 | 0 | OpenResty detection | no |
| crapi | info | NO-CWE|NUCLEI:SOA Record Service - Detection | 0 | 1 | 0 | SOA Record Service - Detection | no |
| crapi | info | NO-CWE|NUCLEI:robots.txt endpoint prober | 0 | 1 | 0 | robots.txt endpoint prober | no |
| crapi | info | NO-CWE|NUCLEI:robots.txt file | 0 | 1 | 0 | robots.txt file | no |
| crapi | info | NO-CWE|ZAP:Modern Web Application | 1 | 0 | 0 | Modern Web Application | no |
| crapi | info | SECURITY_HEADERS | 0 | 1 | 0 | HTTP Missing Security Headers | no |
| dvwa | high | CWE-1395 | 1 | 0 | 0 | Apache HTTP Server Version with Known Vulnerabilities | yes |
| dvwa | medium | CWE-200 | 0 | 1 | 0 | Sensitive Configuration Files Listing - Detect | yes |
| dvwa | medium | SECURITY_HEADERS | 1 | 0 | 0 | Missing Anti-clickjacking Header | yes |
| dvwa | low | CWE-1004 | 1 | 0 | 0 | Cookie No HttpOnly Flag | yes |
| dvwa | low | CWE-1275 | 1 | 0 | 0 | Cookie without SameSite Attribute | yes |
| dvwa | low | CWE-693 | 1 | 0 | 0 | Cross-Origin-Resource-Policy Header Missing or Invalid | yes |
| dvwa | low | SECURITY_HEADERS | 1 | 0 | 7 | X-Content-Type-Options Header Missing<br>missing_security_headers | no |
| dvwa | low | SERVER_BANNER_DISCLOSURE | 1 | 0 | 7 | Server Leaks Version Information via "Server" HTTP Response Header Field<br>server_banner_disclosure | no |
| dvwa | info | CWE-1004 | 0 | 1 | 0 | Cookies without HttpOnly attribute - Detect | no |
| dvwa | info | CWE-200 | 0 | 1 | 0 | WAF Detection | no |
| dvwa | info | CWE-524 | 1 | 0 | 0 | Storable but Non-Cacheable Content | no |
| dvwa | info | CWE-614 | 0 | 1 | 0 | Cookies without Secure attribute - Detect | no |
| dvwa | info | CWE-615 | 1 | 0 | 0 | Information Disclosure - Suspicious Comments | no |
| dvwa | info | CWE-693 | 0 | 1 | 0 | Missing Cookie SameSite Strict | no |
| dvwa | info | NO-CWE|NUCLEI:SOA Record Service - Detection | 0 | 1 | 0 | SOA Record Service - Detection | no |
| dvwa | info | NO-CWE|NUCLEI:Wappalyzer Technology Detection | 0 | 1 | 0 | Wappalyzer Technology Detection | no |
| dvwa | info | NO-CWE|NUCLEI:robots.txt endpoint prober | 0 | 1 | 0 | robots.txt endpoint prober | no |
| dvwa | info | NO-CWE|NUCLEI:robots.txt file | 0 | 1 | 0 | robots.txt file | no |
| dvwa | info | NO-CWE|ZAP:Session Management Response Identified | 1 | 0 | 0 | Session Management Response Identified | no |
| juice-shop | medium | CWE-200 | 0 | 1 | 0 | Prometheus Metrics - Detect | yes |
| juice-shop | medium | CWE-264 | 1 | 0 | 0 | Cross-Domain Misconfiguration | yes |
| juice-shop | medium | SECURITY_HEADERS | 1 | 0 | 0 | Content Security Policy (CSP) Header Not Set | yes |
| juice-shop | low | CWE-16 | 1 | 0 | 0 | Deprecated Feature Policy Header Set | yes |
| juice-shop | low | CWE-693 | 1 | 0 | 0 | Cross-Origin-Embedder-Policy Header Missing or Invalid | yes |
| juice-shop | low | CWE-749 | 1 | 0 | 0 | Dangerous JS Functions | yes |
| juice-shop | low | SECURITY_HEADERS | 1 | 0 | 12 | Cross-Origin-Opener-Policy Header Missing or Invalid<br>missing_security_headers | no |
| juice-shop | info | CWE-200 | 0 | 2 | 0 | FingerprintHub Technology Fingerprint<br>Public Swagger API - Detect | no |
| juice-shop | info | CWE-524 | 1 | 0 | 0 | Storable but Non-Cacheable Content | no |
| juice-shop | info | NO-CWE|NUCLEI:Add DOM EventListener - Detection | 0 | 1 | 0 | Add DOM EventListener - Detection | no |
| juice-shop | info | NO-CWE|NUCLEI:Deprecated Feature-Policy Header - Detection | 0 | 1 | 0 | Deprecated Feature-Policy Header - Detection | no |
| juice-shop | info | NO-CWE|NUCLEI:OWASP Juice Shop | 0 | 1 | 0 | OWASP Juice Shop | no |
| juice-shop | info | NO-CWE|NUCLEI:SOA Record Service - Detection | 0 | 1 | 0 | SOA Record Service - Detection | no |
| juice-shop | info | NO-CWE|NUCLEI:Wappalyzer Technology Detection | 0 | 1 | 0 | Wappalyzer Technology Detection | no |
| juice-shop | info | NO-CWE|NUCLEI:X-Recruiting Header | 0 | 1 | 0 | X-Recruiting Header | no |
| juice-shop | info | NO-CWE|NUCLEI:robots.txt endpoint prober | 0 | 1 | 0 | robots.txt endpoint prober | no |
| juice-shop | info | NO-CWE|NUCLEI:robots.txt file | 0 | 1 | 0 | robots.txt file | no |
| juice-shop | info | NO-CWE|NUCLEI:security.txt File | 0 | 1 | 0 | security.txt File | no |
| juice-shop | info | NO-CWE|ZAP:Modern Web Application | 1 | 0 | 0 | Modern Web Application | no |
| juice-shop | info | SECURITY_HEADERS | 0 | 1 | 0 | HTTP Missing Security Headers | no |
| webgoat | medium | CWE-352 | 1 | 0 | 0 | Absence of Anti-CSRF Tokens | yes |
| webgoat | medium | CWE-598 | 1 | 0 | 0 | Session ID in URL Rewrite | yes |
| webgoat | medium | CWE-644 | 0 | 0 | 2 | host_header_injection | no |
| webgoat | medium | SECURITY_HEADERS | 1 | 0 | 0 | Missing Anti-clickjacking Header | yes |
| webgoat | low | CWE-1004 | 1 | 0 | 0 | Cookie No HttpOnly Flag | yes |
| webgoat | low | CWE-1275 | 1 | 0 | 0 | Cookie without SameSite Attribute | yes |
| webgoat | low | CWE-693 | 1 | 0 | 0 | Cross-Origin-Resource-Policy Header Missing or Invalid | yes |
| webgoat | low | SECURITY_HEADERS | 1 | 0 | 9 | X-Content-Type-Options Header Missing<br>missing_security_headers | no |
| webgoat | info | CWE-1004 | 0 | 1 | 0 | Cookies without HttpOnly attribute - Detect | no |
| webgoat | info | CWE-20 | 1 | 0 | 0 | User Controllable HTML Element Attribute (Potential XSS) | no |
| webgoat | info | CWE-524 | 1 | 0 | 0 | Storable and Cacheable Content | no |
| webgoat | info | CWE-614 | 0 | 1 | 0 | Cookies without Secure attribute - Detect | no |
| webgoat | info | CWE-693 | 0 | 1 | 0 | Missing Cookie SameSite Strict | no |
| webgoat | info | NO-CWE|NUCLEI:Allowed Options Method | 0 | 1 | 0 | Allowed Options Method | no |
| webgoat | info | NO-CWE|NUCLEI:Form Detection | 0 | 1 | 0 | Form Detection | no |
| webgoat | info | NO-CWE|NUCLEI:Internal IP Disclosure | 0 | 1 | 0 | Internal IP Disclosure | no |
| webgoat | info | NO-CWE|NUCLEI:SOA Record Service - Detection | 0 | 1 | 0 | SOA Record Service - Detection | no |
| webgoat | info | NO-CWE|NUCLEI:Wappalyzer Technology Detection | 0 | 1 | 0 | Wappalyzer Technology Detection | no |
| webgoat | info | NO-CWE|NUCLEI:Wordpress Plugin Detection | 0 | 1 | 0 | Wordpress Plugin Detection (إنذار كاذب مرجّح: مطابق للضابط العشوائي) | no |
| webgoat | info | NO-CWE|ZAP:Authentication Request Identified | 1 | 0 | 0 | Authentication Request Identified | no |
| webgoat | info | NO-CWE|ZAP:Session Management Response Identified | 1 | 0 | 0 | Session Management Response Identified | no |
| webgoat | info | SECURITY_HEADERS | 0 | 1 | 0 | HTTP Missing Security Headers | no |


## ZAP active في نفس القياس

| Target | Duration (s) | Requests | Alerts | Spider timeout | Active timeout | Quality |
|---|---:|---:|---:|---|---|---|
| crapi | 134 | 779 | 77 | no | no | complete |
| dvwa | 185 | 2018 | 177 | no | no | complete |
| juice-shop | 212 | 3944 | 235 | no | yes | partial-time-bounded |
| webgoat | 123 | 2948 | 128 | no | no | complete |

| Target | Severity | Standard type | CWE | Active paths |
|---|---|---|---|---:|
| crapi | info | CWE-215 | 215 | 1 |
| crapi | info | CWE-497 | 497 | 1 |
| crapi | info | NO-CWE|WASC--1 | -1 | 1 |
| crapi | info | NO-CWE|WASC-0 | 0 | 1 |
| crapi | low | CWE-497 | 497 | 1 |
| crapi | low | SECURITY_HEADERS | 693 | 1 |
| crapi | medium | SECURITY_HEADERS | 1021 | 1 |
| crapi | medium | SECURITY_HEADERS | 693 | 1 |
| dvwa | high | CWE-1395 | 1395 | 1 |
| dvwa | info | CWE-1295 | 1295 | 1 |
| dvwa | info | CWE-311 | 311 | 1 |
| dvwa | info | CWE-497 | 497 | 1 |
| dvwa | info | CWE-548 | 548 | 1 |
| dvwa | info | CWE-615 | 615 | 1 |
| dvwa | info | NO-CWE|WASC--1 | -1 | 1 |
| dvwa | info | NO-CWE|WASC-0 | 0 | 1 |
| dvwa | low | CWE-1004 | 1004 | 1 |
| dvwa | low | CWE-1275 | 1275 | 1 |
| dvwa | low | CWE-497 | 497 | 1 |
| dvwa | low | SECURITY_HEADERS | 693 | 1 |
| dvwa | medium | SECURITY_HEADERS | 1021 | 1 |
| dvwa | medium | SECURITY_HEADERS | 693 | 1 |
| juice-shop | info | NO-CWE|WASC--1 | -1 | 1 |
| juice-shop | medium | CWE-264 | 264 | 1 |
| juice-shop | medium | SECURITY_HEADERS | 693 | 1 |
| webgoat | info | CWE-20 | 20 | 1 |
| webgoat | info | NO-CWE|WASC--1 | -1 | 1 |
| webgoat | info | NO-CWE|WASC-0 | 0 | 1 |
| webgoat | low | CWE-1004 | 1004 | 1 |
| webgoat | low | CWE-1275 | 1275 | 1 |
| webgoat | low | SECURITY_HEADERS | 693 | 1 |
| webgoat | medium | CWE-352 | 352 | 1 |
| webgoat | medium | SECURITY_HEADERS | 1021 | 1 |
| webgoat | medium | SECURITY_HEADERS | 693 | 1 |
Juice Shop لم يكتمل active scan خلال نافذة 180 ثانية؛ لذلك وسمت نتيجته جزئية ولم تُقدّم كاكتمال.

## التحقق اليدوي من إنذارات Nuclei المشبوهة

### crAPI `//.env` وLaravel

النتيجة **حقيقية، وليست false positive**. من داخل الحاوية: `GET http://crapi-web:80//.env` أعاد HTTP 200، بطول 201 بايت، وبصمة `7996111d87a20f9c3863f6b778f0d945d280330d53b186fa622f993891f1c48a`. أول 200 بايت بدأت بـ`DB_NAME=crapi`, `DB_PASSWORD=crapi`, وبيانات اتصال Mongo/Postgres. الضابط `//.-burhan-random-env` أعاد HTTP 404 بطول 159 وبصمة `5a41c6b1c3d5061adbd15744312c919ee4a639abc0572a2927b06838bec1a6ed`. لذلك أُبقيت إنذارات `.env` في الجدول كفجوة حقيقية لـBurhan.

### WebGoat وWordPress plugin

النتيجة **إنذار كاذب مرجّح**. المسار المطابق أعاد صفحة WebGoat Login HTTP 200، بطول 1929 وبصمة `61153914d077b9f99ead10a536133564d2988ad5f6eaa74ad2300867dc2249dd`، وأول 200 بايت تبدأ بعنوان `Login Page`. لم توجد مؤشرات WordPress مثل `wp-content/plugins/` أو `wp-includes/` أو كلمة WordPress في جسم الاستجابة. الضابط `/WebGoat/login-burhan-random` أعاد HTTP 302 بجسم فارغ وبصمة `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`؛ اختلاف الضابط يثبت أن المسار موجود، لكنه لا يثبت WordPress. مصدر قالب Nuclei نفسه يصفه بأنه كشف تقني ويبحث عن مسارات `/plugins/...`، وهو غير كافٍ لإثبات WordPress في تطبيق WebGoat.

## أدلة Burhan الفريدة

- `weak_random` على crAPI: الطلب هو `GET http://127.0.0.1:8888/static/js/main.8c78208c.js`. الاستجابة كشفت نصًا يتضمن `Math.random().toFixed(`؛ إعادة الاختبار بعينات جديدة نجحت، فالتصنيف المعياري هو `CWE-330`.
- `host_header_injection` على WebGoat: الطلبان `GET http://127.0.0.1:8080/WebGoat/` و`GET http://127.0.0.1:8080/WebGoat/start.mvc` مع Host عشوائي. الاستجابة عكست Host العشوائي في `Location`، مثل `burhan-vr16-36e373be53.example`؛ إعادة الاختبار نجحت، فالتصنيف المعياري هو `CWE-644`.

## إصدار WebGoat

استُخدم `webgoat/webgoat:v2023.8` ببصمة manifest `sha256:01672eb9aeba60d042ae1131d6de683b98fa64e9da60fa5d3daad2642a6795dd` في المقارنة. مصدر الإصدار هو سجل إصدارات WebGoat الرسمي، ومصدر الصورة هو Docker Hub الرسمي. سُجل v2023.8 أيضًا كإصدار image pinned في سجل المعايرة داخل المستودع؛ أما مجلد `evidence/independent-verification/webgoat-2026.4/` فهو دليل تاريخي مستقل ولم يدخل هذه المقارنة.

## القيود

الـactive scan يقيس ZAP active مع مهلة 120 ثانية للاستكشاف و180 ثانية للفحص لكل هدف. لا تعني أعداد التنبيهات الخام عدد أنواع أو ثغرات مستقلة، ولهذا لم تُستخدم في جدول baseline إلا بعد التجميع المعياري. لا يوجد دمج لـPR #126 في هذا التقرير.

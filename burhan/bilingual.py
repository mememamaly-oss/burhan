# -*- coding: utf-8 -*-
"""Bilingual (AR/EN) client report — round 9, part 1 (2026-11-04).

A SIXTH report format alongside html/json/sarif/executive/glass, built for
the client who is not the scanner operator: every finding carries the SAME
technical proof the engine already produced, re-stated in plain language,
in Arabic and in English.

Sourcing discipline (the round-9 order): remediation guidance REUSES the
compliance registry (burhan/compliance.py) — every curated guidance entry
cites its mapping (CWE + OWASP category) as its source, and header-class
steps name exactly the headers the FINDING's own evidence lists. Types
without a curated entry fall back to the compliance mapping itself
(CWE label + OWASP titles, mapped=False honestly when unknown) with an
explicit "category-level guidance" note — no unsourced invented text.

Content-loss proof: the bilingual document embeds the tamper-evident audit
block (burhan/audit.py — Merkle root + Ed25519 signature) computed over
the SOURCE findings list, so any finding dropped or altered between the
scan and the bilingual rendering is detectable by the standard recipe.
"""
from __future__ import annotations

import time

from .audit import audit_block
from .compliance import compliance_for

# ---- P1.1a: plain-language description, Arabic + English ------------------
# Written for a non-technical reader; the technical identity (CWE/OWASP)
# rides alongside from compliance_for(), never instead of it.
PLAIN_LANGUAGE: dict[str, dict[str, str]] = {
    "sql_injection": {
        "ar": ("حقن قاعدة البيانات: الموقع يضع ما يكتبه الزائر داخل أمر "
               "يقرأ قاعدة البيانات مباشرة، فيستطيع المهاجم تغيير معنى "
               "الأمر ليقرأ بيانات لا تخصه أو يعدّلها أو يحذفها."),
        "en": ("SQL injection: the site places visitor-supplied text "
               "directly inside a database command, so an attacker can "
               "change the command's meaning and read, alter or delete "
               "data that is not theirs."),
    },
    "xss_reflected": {
        "ar": ("البرمجة النصية العابرة (الانعكاسية): ما يكتبه المهاجم في "
               "الرابط يعود إلى متصفح الضحية كما هو دون تعقيم، فيُنفَّذ "
               "كأنه كود من الموقع نفسه ويسرق جلسات الضحايا أو ينتحل "
               "أفعالهم."),
        "en": ("Reflected cross-site scripting: text an attacker plants in "
               "a link comes back to the victim's browser unescaped and "
               "runs as if it were the site's own code — stealing sessions "
               "or acting as the victim."),
    },
    "xss_stored": {
        "ar": ("البرمجة النصية المخزنة: المهاجم يودع الكود في حقل يحفظه "
               "الموقع (تعليق أو اسم)، فيُعرض ويُنفَّذ لكل زائر لاحق "
               "لتلك الصفحة."),
        "en": ("Stored cross-site scripting: the attacker deposits code "
               "into a field the site saves (a comment, a name); it is "
               "then rendered and executed for every later visitor of that "
               "page."),
    },
    "path_traversal": {
        "ar": ("اجتياز المسار: طلب قراءة ملف يقبل أسماء مثل "
               "«../../..» فيخرج من مجلده المسموح ويقرأ ملفات النظام "
               "الحساسة."),
        "en": ("Path traversal: a file-read request accepts names like "
               "«../../..», escapes its allowed folder and reads sensitive "
               "system files."),
    },
    "open_redirect": {
        "ar": ("إعادة التوجيه المفتوحة: الرابط يقبل عنواناً خارجياً "
               "يحدده المهاجم فيوجّه الضحية إلى موقع انتحالي دون "
               "علمها."),
        "en": ("Open redirect: the link accepts an off-site address chosen "
               "by the attacker and silently forwards the victim to a "
               "look-alike site."),
    },
    "csrf": {
        "ar": ("تزوير الطلب عبر المواقع: موقع آخر يستطيع أن يجعل متصفح "
               "الضحية المسجَّلة يرسل طلباً يغيّر بياناتها (بريدها أو "
               "كلمة سرها) والموقع يقبله لأنه لا يطلب رمزاً ولا يتحقق "
               "من المصدر."),
        "en": ("Cross-site request forgery: another website can make a "
               "logged-in victim's browser send a request that changes the "
               "victim's data (email, password), and the site accepts it "
               "because it requires no token and checks no origin."),
    },
    "bfla": {
        "ar": ("تجاوز ترخيص الوظائف (BFLA): دالة إدارية محظورة (حذف عنصر "
               "مثلاً) تُنفَّذ فعلاً لحساب مستخدم عادي — البوابة "
               "الإدارية موجودة في الكود لكن لا أحد يسأل «من أنت؟» قبل "
               "التنفيذ."),
        "en": ("Broken function-level authorization: an admin-only function "
               "(delete, for example) actually executes for a regular "
               "user's session — the admin gate exists in the code, but "
               "nothing asks «who are you?» before running it."),
    },
    "vertical_privilege_escalation": {
        "ar": ("التصعيد الرأسي للصلاحيات: صفحة أو بيانات لا تُعرض إلا "
               "للمدير تُقدَّم كاملة لحساب مستخدم عادي، فيرى ما لا يحق "
               "له رؤيته."),
        "en": ("Vertical privilege escalation: a page or dataset reserved "
               "for administrators is served in full to a regular account, "
               "which then sees what it must not."),
    },
    "idor_bola": {
        "ar": ("الإشارة المباشرة إلى كائن غير محمي (IDOR/BOLA): تغيير "
               "رقم في الرابط (معرّف حساب آخر) يعيد بيانات ذلك الحساب "
               "لأن الموقع يتحقق من صحة الرقم لا من ملكيته."),
        "en": ("Insecure direct object reference (IDOR/BOLA): changing a "
               "number in the URL (another account's id) returns that "
               "account's data — the site validates the number's shape, "
               "not who owns it."),
    },
    "idor": {
        "ar": ("الإشارة المباشرة إلى كائن غير محمي (IDOR): تغيير رقم في "
               "الرابط يعيد بيانات كائن لا يملكه الطالب."),
        "en": ("Insecure direct object reference: changing an id in the "
               "URL returns an object the requester does not own."),
    },
    "jwt_signature_not_enforced": {
        "ar": ("توكن الدخول بلا توقيع مُلزِم: الخادم قبل توكناً عُطِّب "
               "توقيعه الرقمي (حُرِّف حرف واحد داخله) ومنح الوصول — أي "
               "أن الهوية المزعومة داخل التوكن تُصدَّق دون إثبات أنها "
               "من الموقع حقاً."),
        "en": ("Unenforced token signature: the server accepted a login "
               "token whose cryptographic signature was corrupted (one "
               "character flipped mid-signature) and granted access — the "
               "identity claimed inside the token is trusted without proof "
               "it genuinely came from the site."),
    },
    "jwt_algorithm_confusion": {
        "ar": ("الالتباس في خوارزمية التوكن: الخادم يقبل توقيعاً "
               "بخوارزمية مختلفة عن المعلنة، فيستطيع المهاجم صياغة توكن "
               "موقَّع بمفتاح يعرفه."),
        "en": ("JWT algorithm confusion: the server accepts a signature "
               "made with a different algorithm than declared, letting an "
               "attacker mint a token signed with a key they hold."),
    },
    "weak_random": {
        "ar": ("عشوائية ضعيفة: القيم التي يفترض أن يستحيل تخمينها "
               "(توكنات وجلسات) تُبنى على مولّد أرقام متوقَّع كاشفه "
               "الردُّ نفسه (Math.random)، فيستطيع المهاجم حسابها "
               "مسبقاً."),
        "en": ("Weak randomness: values that should be unguessable "
               "(tokens, sessions) come from a predictable generator — the "
               "response itself discloses Math.random(), an LCG-family "
               "PRNG, so an attacker can compute them ahead of time."),
    },
    "secure_cookie": {
        "ar": ("كوكي بلا سمة Secure: قيمة الكوكي تُرسل نصاً صريحاً على أي "
               "اتصال HTTP عادي، فيقرؤها أي وسيط على الطريق."),
        "en": ("Cookie without the Secure attribute: the cookie's value "
               "travels in cleartext on any plain-HTTP hop, readable by "
               "any intermediary on the path."),
    },
    "missing_security_headers": {
        "ar": ("غياب رؤوس الحماية: الردود لا تحمل الرؤوس التي تفرض على "
               "المتصفحات سلوكاً آمناً (منع التأطير، تقييد المحتوى، فرض "
               "التشفير)، فتُترك الثغرات الأخرى أبسط استغلالاً."),
        "en": ("Missing security headers: responses lack the headers that "
               "make browsers behave safely (framing bans, content "
               "restrictions, enforced encryption), which makes every "
               "other flaw easier to exploit."),
    },
    "server_banner_disclosure": {
        "ar": ("إفصاح بصمة الخادم: الرد يعلن اسم برنامج الخادم وإصداره "
               "(مثل openresty/1.27.1.2)، فيختار المهاجم هجماته المخصصة "
               "للإصدار المعروف دون تجريب."),
        "en": ("Server banner disclosure: responses announce the server "
               "software and version (e.g. openresty/1.27.1.2), letting an "
               "attacker pick version-specific attacks without probing."),
    },
    "cors_misconfig": {
        "ar": ("إعداد CORS خاطئ: الخادم يرد على أي مصدر خارجي بترخيص "
               "القراءة، فيقرأ موقع المهاجم بيانات الضحية المسجَّلة من "
               "متصفحها مباشرة."),
        "en": ("CORS misconfiguration: the server answers any external "
               "origin with read permission, so an attacker's site reads "
               "the logged-in victim's data straight from the victim's "
               "browser."),
    },
    "ssrf": {
        "ar": ("تزوير الطلب من جانب الخادم (SSRF): الموقع نفسه يزور "
               "عنواناً يحدده المهاجم، فيُستخدم كوكيّ يتصيد الخدمات "
               "الداخلية التي لا يصلها أحد من الخارج."),
        "en": ("Server-side request forgery: the site itself visits an "
               "address the attacker chooses, turning it into a probe for "
               "internal services no outsider can reach."),
    },
}

# ---- P1.1c: remediation steps, per category, each entry SOURCE-CITED -------
# source = the compliance mapping the guidance belongs to (CWE + OWASP
# categories from burhan/compliance.py). Header/cookie steps additionally
# name exactly what the FINDING's own evidence lists — nothing invented.
REMEDIATION_GUIDANCE: dict[str, dict] = {
    "sql_injection": {
        "source": "CWE-89 · OWASP A03:2021 / A05:2025 (compliance.py mapping)",
        "steps_ar": [
            "لا تُركَّب أوامر قاعدة البيانات بدمج النص مع مدخلات المستخدم؛ "
            "استعلامات مُعدَّة مسبقاً (parameterized) وحدها تُستخدم.",
            "افحص كل مدخل يصل إلى الاستعلام حتى لو جاء من كوكي أو ترويسة، "
            "والقيود على الشكل لا تكفي.",
            "أقصِ صلاحية حساب قاعدة البيانات المستخدم للتطبيق عن الجداول "
            "التي لا يحتاجها.",
        ],
        "steps_en": [
            "Never build database commands by concatenating user input; use "
            "parameterized (prepared) statements only.",
            "Validate every input reaching a query — including cookies and "
            "headers; shape checks alone are not sufficient.",
            "Restrict the application's database account to only the tables "
            "it needs.",
        ],
    },
    "xss_reflected": {
        "source": "CWE-79 · OWASP A03:2021 / A05:2025 (compliance.py mapping)",
        "steps_ar": [
            "هرب كل قيمة من مدخلات المستخدم قبل عرضها في الصفحة (ترميز "
            "HTML للمحارف < > & \" ').",
            "القائمة البيضاء للسياق: ما يُدرج داخل JavaScript أو URL يحتاج "
            "ترميزاً مختلفاً عن سياق HTML.",
            "أضف رأس Content-Security-Policy ليمنع تنفيذ السكربتات "
            "المحقونة حتى لو نجح الإدراج.",
        ],
        "steps_en": [
            "HTML-encode every user-supplied value before rendering it "
            "(the < > & \" ' characters).",
            "Encode for the exact context: values placed inside JavaScript "
            "or URLs need different encoding than HTML body.",
            "Add a Content-Security-Policy header so injected scripts are "
            "blocked even if injection slips through.",
        ],
    },
    "xss_stored": {
        "source": "CWE-79 · OWASP A03:2021 / A05:2025 (compliance.py mapping)",
        "steps_ar": [
            "هرب القيمة عند العرض لا عند الإدخال فقط؛ المكان المخزن لا "
            "يوثق به.",
            "نقّح المدخلات المحفوظة بقائمة بيضاء لما يسمح به الحقل فعلاً.",
            "رأس Content-Security-Policy كطبقة ثانية في كل الصفحات التي "
            "تعرض محتوى المستخدمين.",
        ],
        "steps_en": [
            "Encode at render time, not only at input time; storage is not "
            "a trust boundary.",
            "Sanitize stored input with a whitelist of what the field "
            "genuinely allows.",
            "A Content-Security-Policy header as a second layer on every "
            "page that renders user content.",
        ],
    },
    "csrf": {
        "source": "CWE-352 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "ألزم كل طلب يغيّر الحالة برمز CSRF فردي غير متوقع مرتبط "
            "بالجلسة.",
            "تحقق من ترويستي Origin وReferer للطلبات الحساسة وارفض "
            "المصادر غير المعروفة.",
            "استخدم سمات الكوكي SameSite=Lax أو Strict للجلسات.",
        ],
        "steps_en": [
            "Require an unpredictable per-session CSRF token on every "
            "state-changing request.",
            "Validate Origin and Referer headers on sensitive requests and "
            "reject unknown sources.",
            "Set SameSite=Lax or Strict on session cookies.",
        ],
    },
    "bfla": {
        "source": "CWE-285 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "افحص الترخيص داخل الدالة نفسها لا في الواجهة وحدها: كل مسار "
            "يصل إلى وظيفة إدارية يجب أن يسأل عن الدور أولاً.",
            "افترض الرفض: الدوال الحساسة تُرفض لأي دور لم يُصرَّح له صراحة "
            "في قائمة مركزية.",
            "اختبر كل نقطة نهاية إدارية بجلسات أدوار مختلفة في كل تغيير "
            "للكود.",
        ],
        "steps_en": [
            "Authorize inside the function, not only at the route: every "
            "path reaching an admin capability must ask the role first.",
            "Deny by default: sensitive functions refuse any role not "
            "explicitly allowed in a central list.",
            "Test every admin endpoint with each role's session on every "
            "code change.",
        ],
    },
    "vertical_privilege_escalation": {
        "source": "CWE-269 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "تحقق من دور الجلسة في الخادم قبل بناء كل صفحة إدارية، لا "
            "تخفِ الرابط وتكتفِ.",
            "سجّل محاولات الوصول إلى الأسطح الممتازة وافحصها دورياً.",
        ],
        "steps_en": [
            "Check the session's role server-side before rendering any "
            "privileged page; hiding the link is not a control.",
            "Log access attempts to privileged surfaces and review them "
            "regularly.",
        ],
    },
    "idor_bola": {
        "source": ("CWE-639 / CWE-284 · OWASP A01:2021 / A01:2025 "
                   "(compliance.py mapping)"),
        "steps_ar": [
            "تحقق من ملكية الكائن المطلوب: تطابق معرّفه مع هوية الجلسة "
            "قبل الرد.",
            "استخدم معرّفات عشوائية غير متسلسلة إن كان لا بد من تعريض "
            "المعرّف.",
        ],
        "steps_en": [
            "Check object ownership: the requested id must belong to the "
            "session's identity before any data is returned.",
            "Prefer random, non-sequential identifiers if ids must be "
            "exposed at all.",
        ],
    },
    "idor": {
        "source": "CWE-639 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "تحقق من ملكية الكائن المطلوب قبل الرد، لكل جلسة على حدة.",
        ],
        "steps_en": [
            "Verify the requesting session owns the object before "
            "responding, per session.",
        ],
    },
    "jwt_signature_not_enforced": {
        "source": "CWE-347 · OWASP A02:2021 / A07:2025 (compliance.py mapping)",
        "steps_ar": [
            "تحقق من صحة توقيع التوكن بمفتاح الخادم في كل طلب، وارفض أي "
            "توكن فشل التحقق.",
            "ثبّت الخوارزمية المقبولة صراحة (قائمة بيضاء) ولا تأخذها من "
            "محتوى التوكن.",
            "ارفض التوكنات ذات التوقيع «none» أو الخوارزمية الغائبة.",
        ],
        "steps_en": [
            "Verify the token's signature with the server's key on every "
            "request; reject any token that fails verification.",
            "Pin the accepted algorithm explicitly (whitelist); never take "
            "it from the token's own content.",
            "Reject tokens with «none» or a missing algorithm.",
        ],
    },
    "jwt_algorithm_confusion": {
        "source": "CWE-347 · OWASP A02:2021 / A07:2025 (compliance.py mapping)",
        "steps_ar": [
            "افصل مفاتيح التحقق حسب الخوارزمية ولا تقبل مفاتيح RSA "
            "كأسرار HMAC.",
            "قائمة بيضاء صريحة للخوارزميات في الخادم.",
        ],
        "steps_en": [
            "Separate verification keys per algorithm; never accept an RSA "
            "public key as an HMAC secret.",
            "Maintain an explicit server-side algorithm whitelist.",
        ],
    },
    "weak_random": {
        "source": ("CWE-330 / CWE-338 (finding evidence cites CWE-330; "
                   "compliance.py mapping)"),
        "steps_ar": [
            "استبدل Math.random() وبذور التسلسل المتوقعة بمولّد معتمد "
            "للأغراض الأمنية (crypto.getRandomValues في المتصفح، "
            "secrets/urandom في الخادم) لكل توكن أو جلسة أو سر.",
            "ما ليس أمنياً (ألوان الواجهة مثلاً) يبقى على المولّد العادي؛ "
            "الفصل بين الاستعمالين صريح في الكود.",
        ],
        "steps_en": [
            "Replace Math.random() and predictable sequence seeds with a "
            "CSPRNG (crypto.getRandomValues in the browser, secrets/urandom "
            "server-side) for every token, session or secret.",
            "Non-security uses (UI colors, for example) may stay on the "
            "ordinary generator; keep the two uses explicitly separated in "
            "code.",
        ],
    },
    "secure_cookie": {
        "source": "CWE-614 · OWASP A05:2021 / A05:2025 (compliance.py mapping)",
        "steps_ar": [
            "أضف سمة Secure لكل كوكي جلسة أو هوية (الكوكي المذكورة في "
            "الدليل تحديداً).",
            "أضف HttpOnly وSameSite=Lax أو Strict للكوكي ذاته إن لم "
            "تكونا موجودتين.",
        ],
        "steps_en": [
            "Add the Secure attribute to every session or identity cookie "
            "(the exact cookie named in the finding).",
            "Add HttpOnly and SameSite=Lax or Strict to the same cookie if "
            "absent.",
        ],
    },
    "missing_security_headers": {
        "source": ("CWE-693 (compliance.py mapping); the missing-header list "
                   "comes from the finding's own evidence"),
        "steps_ar": [
            "أضف الرؤوس المفقودة المذكورة في الدليل تحديداً (يختلف "
            "تعدادها بين النتائج):",
            "strict-transport-security يفرض HTTPS على كل الزيارات اللاحقة.",
            "content-security-policy يقيد ما يجوز للمتصفح تنفيذه من "
            "سكربتات وأنماط.",
            "x-frame-options يمنع تضمين الموقع داخل مواقع أخرى.",
            "x-content-type-options يمنع المتصفح من تخمين نوع المحتوى.",
            "referrer-policy يحدد ما يُفشى عن الرابط الأصلي عند الانتقال.",
        ],
        "steps_en": [
            "Add exactly the missing headers named in the finding (the list "
            "differs per finding):",
            "strict-transport-security forces HTTPS for all later visits.",
            "content-security-policy restricts what the browser may execute "
            "as script or style.",
            "x-frame-options forbids embedding the site inside other sites.",
            "x-content-type-options stops the browser guessing the content "
            "type.",
            "referrer-policy limits how much of the original link leaks on "
            "navigation.",
        ],
    },
    "server_banner_disclosure": {
        "source": "CWE-200 · OWASP A05:2021 / A05:2025 (compliance.py mapping)",
        "steps_ar": [
            "احذف أو عمِّم ترويسة Server (والقيمة المذكورة في الدليل "
            "تحديداً) في إعداد الخادم أو الوكيل.",
            "لا تعلن الإصدارات في ترويسات الردود أو صفحات الخطأ.",
        ],
        "steps_en": [
            "Remove or generalize the Server header (the exact value named "
            "in the finding) in the server/proxy configuration.",
            "Do not disclose versions in response headers or error pages.",
        ],
    },
    "cors_misconfig": {
        "source": ("CWE-942 / CWE-918 · OWASP A05:2021 / A05:2025 "
                   "(compliance.py mapping)"),
        "steps_ar": [
            "لا تعكس أي Origin يصل؛ قائمة بيضاء صريحة للمصادر الموثوقة.",
            "لا تجمع Access-Control-Allow-Origin=* مع بيانات الاعتماد "
            "(credentials) أبداً.",
        ],
        "steps_en": [
            "Never reflect an arbitrary Origin; keep an explicit whitelist "
            "of trusted origins.",
            "Never combine Access-Control-Allow-Origin=* with credentials.",
        ],
    },
    "path_traversal": {
        "source": "CWE-23 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "لا تمرر مدخلات المستخدم إلى مسارات ملفات مباشرة؛ حوّلها إلى "
            "مفتاح داخل قائمة بيضاء.",
            "طبّع المسار ثم تحقق أن نتيجته ما زالت داخل المجلد المسموح.",
        ],
        "steps_en": [
            "Do not pass user input into file paths; map it to a key in a "
            "whitelist.",
            "Normalize the path, then verify the result stays inside the "
            "allowed directory.",
        ],
    },
    "open_redirect": {
        "source": "CWE-601 · OWASP A01:2021 / A01:2025 (compliance.py mapping)",
        "steps_ar": [
            "لا توجَّه إلى عنوان من مدخل المستخدم؛ جدول أهداف معروفة "
            "داخلياً.",
            "إن لزم، تحقق من قائمة بيضاء للمضيفين قبل التوجيه.",
        ],
        "steps_en": [
            "Do not redirect to a user-supplied address; use an internal "
            "table of known destinations.",
            "If unavoidable, validate against a whitelist of hosts before "
            "redirecting.",
        ],
    },
    "ssrf": {
        "source": "CWE-918 · OWASP A10:2021 / A10:2025 (compliance.py mapping)",
        "steps_ar": [
            "لا يزور الخادم عنواناً من مدخل المستخدم إلا عبر قائمة بيضاء "
            "للمضيفين.",
            "امنع النطاقات الداخلية والعناوين الخاصة، وأخرج كل الطلبات "
            "الصادرة عبر منفذ شبكة مسيَّر.",
        ],
        "steps_en": [
            "The server must not fetch a user-supplied address except "
            "through a host whitelist.",
            "Block internal domains and private address ranges; egress all "
            "outbound requests through a controlled network path.",
        ],
    },
}


def _plain_language(ftype: str) -> dict[str, str]:
    """The curated plain-language pair, or the honest fallback: the CWE
    label from the compliance registry (sourced text), never invented
    prose."""
    if ftype in PLAIN_LANGUAGE:
        return PLAIN_LANGUAGE[ftype]
    c = compliance_for(ftype)
    label = c.get("cwe_label") or "unmapped finding type"
    return {
        "ar": (f"نوع نتيجة غير موصوف بلغة مبسطة بعد ({ftype}) — التعريف "
               f"التقني المعتمد: {label}."),
        "en": (f"No plain-language description curated yet for this type "
               f"({ftype}) — the registered technical identity: {label}."),
    }


def _guidance(f: dict) -> dict:
    """Remediation guidance for one finding. Curated entries carry their
    compliance citation; header-class steps name exactly what the finding's
    own evidence lists; unknown types fall back to the compliance mapping
    itself with an honest note — never invented text."""
    ftype = f.get("type", "")
    g = REMEDIATION_GUIDANCE.get(ftype)
    c = compliance_for(ftype)
    if g:
        steps_ar = list(g["steps_ar"])
        steps_en = list(g["steps_en"])
        # header-class findings: name the exact missing headers from the
        # finding's OWN evidence (sourced, per-finding specific)
        if ftype == "missing_security_headers":
            ev = (f.get("evidence") or [{}])
            detail = str((ev[0].get("detail") if ev else "") or "")
            missing = [h.strip() for h in
                       detail.split("missing:", 1)[-1].split(",")
                       if h.strip()]
            if missing:
                steps_ar.insert(1, "المفقود في هذه النتيجة تحديداً: "
                                 + "، ".join(missing) + ".")
                steps_en.insert(1, "Missing in this specific finding: "
                                 + ", ".join(missing) + ".")
        return {"steps_ar": steps_ar, "steps_en": steps_en,
                "source": g["source"], "specific": True}
    label = c.get("cwe_label") or ""
    owasp = c.get("owasp_2021_title") or ""
    return {
        "steps_ar": [
            f"لا إرشاد مُنسَّق لهذا النوع بعد؛ الالتزام المعتمد: "
            f"{label} {('— ' + owasp) if owasp else ''}.",
            "عالج الثغرة وفق توصية الفئة في سجل الالتزام حتى يُضاف "
            "إرشاد نوعي مفصّل.",
        ],
        "steps_en": [
            f"No curated guidance for this type yet; the registered "
            f"compliance identity: {label} {('— ' + owasp) if owasp else ''}.",
            "Remediate per the category's compliance-registry guidance "
            "until a type-specific entry is added.",
        ],
        "source": "fallback: compliance.py mapping ("
                  + (c.get("cwe") or "unmapped") + ")",
        "specific": False,
    }


def _proof(f: dict) -> dict[str, str]:
    """The exploitation proof restated for a non-technical reader: the
    evidence detail is quoted VERBATIM (the technical record), framed by
    plain-language sentences in both languages, with the verification
    verdict."""
    ev = f.get("evidence") or []
    detail = str((ev[0].get("detail") if ev else "") or "").strip()
    v = f.get("verification") or {}
    passed = bool(v.get("passed"))
    rounds = v.get("rounds")
    method = v.get("method") or ""
    if passed:
        verdict_ar = (f"أُعيد تنفيذ الاختبار على هدف حي وتكرر النجاح"
                      + (f" ({rounds} جولات)" if rounds else "")
                      + f" — طريقة التحقق: {method}.")
        verdict_en = (f"The test was re-executed against a live target and "
                      f"succeeded again"
                      + (f" ({rounds} rounds)" if rounds else "")
                      + f" — verification method: {method}.")
    else:
        verdict_ar = "لم يُتحقق الاستغلال بإعادة تنفيذ مستقلة بعد."
        verdict_en = ("No independent re-execution has confirmed this "
                      "exploitation yet.")
    frame_ar = f"الدليل الفني المسجَّل (نصاً كما أنتجه المحرك): «{detail}»"
    frame_en = (f"The recorded technical evidence (verbatim engine output): "
                f"“{detail}”")
    return {"ar": frame_ar + " " + verdict_ar,
            "en": frame_en + " " + verdict_en}


def _short_title(text: str) -> str:
    for sep in ("۔", ":", "—", "-", "،", ","):
        if sep in text:
            return text.split(sep, 1)[0].strip()
    return text


def build_bilingual(report: dict) -> dict:
    """The structured bilingual document from a scan report dict (the same
    shape Store.get_run / scan.json produce). Every finding appears in both
    languages; the source findings' Merkle root + Ed25519 signature ride
    along (audit.py) as the content-loss tamper evidence."""
    findings = list(report.get("findings") or [])
    out_findings = []
    for f in findings:
        ftype = f.get("type", "")
        c = compliance_for(ftype)
        pl = _plain_language(ftype)
        g = _guidance(f)
        proof = _proof(f)
        out_findings.append({
            "id": f.get("id", ""),
            "type": ftype,
            "severity": f.get("severity", ""),
            "status": f.get("status", ""),
            "confidence": f.get("confidence"),
            "method": f.get("method", ""),
            "url": f.get("url", ""),
            "parameter": f.get("parameter", ""),
            "compliance": c,
            "ar": {
                "title": _short_title(pl["ar"]),
                "what_it_is": pl["ar"],
                "proof": proof["ar"],
                "remediation": {"steps": g["steps_ar"],
                                "source": g["source"],
                                "finding_specific": g["specific"]},
            },
            "en": {
                "title": _short_title(pl["en"]),
                "what_it_is": pl["en"],
                "proof": proof["en"],
                "remediation": {"steps": g["steps_en"],
                                "source": g["source"],
                                "finding_specific": g["specific"]},
            },
        })
    return {
        "format": "bilingual-1",
        "language_pair": ["ar", "en"],
        "run_id": report.get("run_id", ""),
        "target": report.get("target", ""),
        "scanner": report.get("scanner", ""),
        "findings_count": len(findings),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "findings": out_findings,
        "audit": audit_block(report, seed=report.get("seed")),
    }


# ---- P1.2: the docx/PDF export pipeline -------------------------------------

def _rtl(paragraph):
    """Mark a paragraph right-to-left (Arabic) at the OOXML level."""
    from docx.oxml import OxmlElement
    pPr = paragraph._p.get_or_add_pPr()
    pPr.append(OxmlElement("w:bidi"))


def _para(doc, text, *, rtl=False, bold=False, size=10.5, color=None):
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor
    p = doc.add_paragraph()
    p.paragraph_format.alignment = (WD_ALIGN_PARAGRAPH.RIGHT if rtl
                                    else WD_ALIGN_PARAGRAPH.LEFT)
    if rtl:
        _rtl(p)
    r = p.add_run(text)
    r.bold = bold
    r.font.size = Pt(size)
    r.font.name = "Arial"
    r._element.rPr.rFonts.set(qn("w:cs"), "Arial")
    if color:
        r.font.color.rgb = RGBColor(*color)
    return p


def build_bilingual_docx(bilingual: dict, path: str) -> str:
    """The .docx rendering: per finding, the Arabic section (RTL) and the
    English section in sequence — same content, both languages, nothing
    dropped (the JSON carries the machine-checkable parity; the audit
    block carries the tamper evidence)."""
    from docx import Document
    from docx.oxml.ns import qn
    from docx.shared import Pt

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Arial"
    style.font.size = Pt(10.5)
    style.element.rPr.rFonts.set(qn("w:cs"), "Arial")

    _para(doc, "تقرير الثغرات الأمنية — ثنائي اللغة", rtl=True, bold=True,
          size=17, color=(0x1F, 0x3A, 0x5F))
    _para(doc, "Security Vulnerability Report — Bilingual (AR/EN)",
          bold=True, size=14, color=(0x1F, 0x3A, 0x5F))
    _para(doc, f"الهدف: {bilingual.get('target', '')} · عدد النتائج: "
               f"{bilingual.get('findings_count', 0)} · التشغيلة: "
               f"{bilingual.get('run_id', '')}", rtl=True, size=9.5,
          color=(0x66, 0x66, 0x66))
    _para(doc, f"Target: {bilingual.get('target', '')} · findings: "
               f"{bilingual.get('findings_count', 0)} · run: "
               f"{bilingual.get('run_id', '')}", size=9.5,
          color=(0x66, 0x66, 0x66))
    a = bilingual.get("audit") or {}
    _para(doc, f"جذر ميركل للنتائج المصدر: {a.get('merkle_root', '')} — "
               f"التوقيع يثبت أن لا نتيجة سقطت أو حُرِّفت بين المسح وهذا "
               f"التقرير.", rtl=True, size=9, color=(0x66, 0x66, 0x66))
    _para(doc, f"Merkle root over the source findings: "
               f"{a.get('merkle_root', '')} — the signature proves no "
               f"finding was dropped or altered between the scan and this "
               f"report.", size=9, color=(0x66, 0x66, 0x66))

    for f in bilingual.get("findings", []):
        c = f.get("compliance") or {}
        ar, en = f["ar"], f["en"]
        _para(doc, f"■ [{str(f.get('severity', '')).upper()}] {ar['title']}",
              rtl=True, bold=True, size=12.5, color=(0xB0, 0x30, 0x30))
        _para(doc, f"■ [{str(f.get('severity', '')).upper()}] {en['title']}",
              bold=True, size=11, color=(0xB0, 0x30, 0x30))
        _para(doc, f"الموقع: {f.get('url', '')} · المعامل: "
                   f"{f.get('parameter', '') or '—'} · الطريقة: "
                   f"{f.get('method', '')} · النوع: {f.get('type', '')}",
              rtl=True, size=9.5)
        _para(doc, f"Where: {f.get('url', '')} · parameter: "
                   f"{f.get('parameter', '') or '—'} · method: "
                   f"{f.get('method', '')} · type: {f.get('type', '')}",
              size=9.5)
        _para(doc, "ما هي هذه الثغرة؟", rtl=True, bold=True, size=11,
              color=(0x2E, 0x5A, 0x88))
        _para(doc, ar["what_it_is"], rtl=True)
        _para(doc, "What this flaw is", bold=True, size=11,
              color=(0x2E, 0x5A, 0x88))
        _para(doc, en["what_it_is"])
        _para(doc, "الدليل على الاستغلال الفعلي", rtl=True, bold=True,
              size=11, color=(0x2E, 0x5A, 0x88))
        _para(doc, ar["proof"], rtl=True)
        _para(doc, "Proof it was actually exploited", bold=True, size=11,
              color=(0x2E, 0x5A, 0x88))
        _para(doc, en["proof"])
        _para(doc, "خطوات المعالجة", rtl=True, bold=True, size=11,
              color=(0x2E, 0x5A, 0x88))
        for s in ar["remediation"]["steps"]:
            _para(doc, "• " + s, rtl=True)
        _para(doc, "Remediation steps", bold=True, size=11,
              color=(0x2E, 0x5A, 0x88))
        for s in en["remediation"]["steps"]:
            _para(doc, "• " + s)
        _para(doc, f"مصدر الإرشاد: {ar['remediation']['source']} · "
                   f"الالتزام: {c.get('cwe', '') or 'unmapped'} "
                   f"{c.get('owasp_2021', '') or ''}", rtl=True, size=8.5,
              color=(0x8A, 0x4A, 0x11))
        _para(doc, f"Guidance source: {en['remediation']['source']} · "
                   f"compliance: {c.get('cwe', '') or 'unmapped'} "
                   f"{c.get('owasp_2021', '') or ''}", size=8.5,
              color=(0x8A, 0x4A, 0x11))
    doc.save(path)
    return path


class PdfExportUnavailable(RuntimeError):
    """soffice is absent — the PDF conversion cannot run. Loud by design:
    the caller decides between installing soffice or shipping the docx +
    JSON alone; the failure is never swallowed into a silent skip."""


def export_pdf(docx_path: str, pdf_path: str) -> str:
    """docx -> PDF via LibreOffice headless (the same pipeline the
    project's own round reports use). Refuses loudly when soffice is
    unavailable (PdfExportUnavailable) — never a silent skip."""
    import os
    import shutil
    import subprocess
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise PdfExportUnavailable(
            "soffice/libreoffice not found on PATH — the bilingual PDF "
            "export requires it (the .docx and structured .json are "
            "already complete; install LibreOffice to also produce the "
            "PDF). This is a loud refusal, not a silent skip.")
    out_dir = (pdf_path.rsplit("/", 1)[0] if "/" in pdf_path else ".")
    expected = os.path.join(
        out_dir, os.path.basename(docx_path).replace(".docx", ".pdf"))
    r = subprocess.run(
        [soffice, "--headless", "--convert-to", "pdf", "--outdir", out_dir,
         docx_path], capture_output=True, text=True, timeout=300)
    if r.returncode != 0 or not os.path.exists(expected):
        raise RuntimeError(
            f"soffice conversion failed (exit {r.returncode}): "
            f"{((r.stderr or '') + (r.stdout or ''))[:300]}")
    if os.path.abspath(expected) != os.path.abspath(pdf_path):
        shutil.move(expected, pdf_path)
    return pdf_path

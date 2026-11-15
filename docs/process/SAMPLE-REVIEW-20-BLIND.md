> ⛔ **أُهدرت هذه العينة للعمى** — نُشرت على main ضمن حزمةٍ كشفت قرارات المولّد (labeled-ground-truth / REVIEW-PACKAGE) فيقع من فتحها قبل التصنيف على الإجابة. لا تُستخدم للمراجعة العمياء؛ بديلها عينة جديدة ببذرة جديدة تُسلّم نصاً لا رابطاً.

# عينة المراجعة العشرين — النسخة العمياء

**أمر المالك 2026-11-14 (البند 4):** نسخة عمياء من عينة المراجعة العشرين، لمراجع مستقل.
لكل تسمية: **رقم عشوائي جديد** + النص الرسمي للتحدّي (الاسم والوصف والتلميحان) **فقط** —
بلا قرار المولّد، وبلا سببه، وبلا فئته، وبلا oracle، وبلا أي حقل يمكن أن يرسي المراجع
على تصنيف المولّد. الترتيب مخلوط (seeded) كي لا تُخمَن بنية 10+10 من المواضع.

## المطلوب من المراجع المستقل

لكل تسمية: صنّفها إلى واحدة من الفئات الثلاث أدناه (تعريف SPEC §1 **حرفياً** كما في المواصفة)،
مع سطر تعليل قصير. لا يوجد تصنيف صحيح معلن مسبقاً؛ جدول المطابقة السرّي (مفتاح التصحيح)
يُفتح فقط بعد ردّ المراجع.

## تعريف الفئات — نص SPEC §1 حرفياً

| الفئة | المعنى |
|-------|--------|
| **measurable** | مسح DAST غير مصادق يمكن أن يطابقها بـoracle آلية |
| **out_of_scope_reason** | خارج مقدور مسح DAST غير مصادق أصلاً (منطق أعمال، صيد موارد بشرية،…) |
| **needs_attacker_action** | الثغرة موجودة لكن إثباتها يتطلب إجراء مهاجم (مصادقة، حسابات متعددة، رفع طلبات) |

**قواعد حاكمة (نص SPEC §1 حرفياً):** (1) المصدر حصراً القائمة الرسمية — لا إدخال يدوي لأي ثغرة؛ (2) التصنيف بقاعدة معلنة في كود المولّد (قابل لمراجعتك) لا بتقدير لحظي؛ (3) أي تحدٍ لا تُشتق له oracle آلية = out_of_scope_reason تلقائياً — **فشل مُغلق: النزاهة قبل التغطية**؛ (4) حقل `auth_required` موجود من اليوم الأول تحضيراً لتوسعة لاحقة.

## التسميات العشرون

### 1. BL-921310

**الاسم الرسمي:** Blockchain Hype

**النص الرسمي:** Learn about the Token Sale before its official announcement.

**التلميح 1:** The developers truly believe in "Security through Obscurity" over actual access restrictions.

**التلميح 2:** Guessing or brute forcing the URL of the token sale page is very unlikely to succeed.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 2. BL-167186

**الاسم الرسمي:** Forged Coupon

**النص الرسمي:** Forge a coupon code that gives you a discount of at least 80%.

**التلميح 1:** Try either a) a knowledgeable brute force attack or b) reverse engineering or c) some research in the cloud.

**التلميح 2:** One viable solution would be to reverse-engineer how coupon codes are generated and craft your own 80% coupon by using the same (or at least similar) implementation.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 3. BL-261273

**الاسم الرسمي:** Admin Registration

**النص الرسمي:** Register as a user with administrator privileges.

**التلميح 1:** You have to assign the unassignable.

**التلميح 2:** Register as an ordinary user to learn what API endpoints are involved in this use case.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 4. BL-607877

**الاسم الرسمي:** Poison Null Byte

**النص الرسمي:** Bypass a security control with a <a href="https://hakipedia.com/index.php/Poison_Null_Byte">Poison Null Byte</a> to access a file not meant for your eyes.

**التلميح 1:** Analyze and tamper with links in the application until you get to an unprotected directory listing.

**التلميح 2:** Some files in there are not directly accessible because a security mechanism prevents access.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 5. BL-125751

**الاسم الرسمي:** Greedy Chatbot Manipulation

**النص الرسمي:** Convince the chatbot to give you a coupon of 50% or more. Because apparently a 10% max policy is just a suggestion when you ask nicely enough.

**التلميح 1:** The chatbot's system prompt says the maximum discount is 10%. But system prompts are more like guidelines than actual rules, right?

**التلميح 2:** You already know how to make the chatbot generate a coupon. Now make it go way beyond the allowed maximum.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 6. BL-352609

**الاسم الرسمي:** Christmas Special

**النص الرسمي:** Order the Christmas special offer of 2014.

**التلميح 1:** Find out how the application handles unavailable products and try to find a loophole.

**التلميح 2:** Find out how the application hides deleted products from its customers.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 7. BL-901608

**الاسم الرسمي:** Upload Type

**النص الرسمي:** Upload a file that has no .pdf or .zip extension.

**التلميح 1:** You can attach a PDF or ZIP file to the "Complaint" form. Investigate how this upload actually works.

**التلميح 2:** If you solved the "Upload a file larger than 100 kB" challenge, you should try to apply the same solution here

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 8. BL-629927

**الاسم الرسمي:** Admin Section

**النص الرسمي:** Access the administration section of the store.

**التلميح 1:** It is just slightly harder to find than the score board link.

**التلميح 2:** Knowing it exists, you can simply guess what URL the admin section might have.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 9. BL-347868

**الاسم الرسمي:** Login Cloud Admin

**النص الرسمي:** Log in with the cloud admin's user account <i>without</i> using SQL Injection.

**التلميح 1:** Brute forcing the password will not work. The password is too strong.

**التلميح 2:** There might be another way to authenticate besides using the correct password.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 10. BL-876039

**الاسم الرسمي:** Privacy Policy

**النص الرسمي:** Read our privacy policy.

**التلميح 1:** We won't even ask you to confirm that you did. Just read it. Please. Pretty please.

**التلميح 2:** When you work with the application you will most likely solve this challenge in the process.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 11. BL-558839

**الاسم الرسمي:** CAPTCHA Bypass

**النص الرسمي:** Submit 10 or more customer feedbacks within 20 seconds.

**التلميح 1:** After finding a CAPTCHA bypass, write a script that automates feedback submission. Or open many browser tabs and be really quick.

**التلميح 2:** You could prepare 10 browser tabs, solving every CAPTCHA and filling out the each feedback form. Then you’d need to very quickly switch through the tabs and submit the forms in under 20 seconds total.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 12. BL-680425

**الاسم الرسمي:** Empty User Registration

**النص الرسمي:** Register a user with an empty email and password.

**التلميح 1:** Consider intercepting and playing with the request payload.

**التلميح 2:** (لا يوجد تلميح ثانٍ)

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 13. BL-235227

**الاسم الرسمي:** Database Schema

**النص الرسمي:** Exfiltrate the entire DB schema definition via SQL Injection.

**التلميح 1:** Find out where this information could come from. Then craft an attack string against an endpoint that offers an unnecessary way to filter data.

**التلميح 2:** Find out which database system is in use and where it would usually store its schema definitions.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 14. BL-550757

**الاسم الرسمي:** Client-side XSS Protection

**النص الرسمي:** Perform a <i>persisted</i> XSS attack with <code>&lt;iframe src="javascript:alert(`xss`)"&gt;</code> bypassing a <i>client-side</i> security mechanism.

**التلميح 1:** There are only some input fields in the Juice Shop forms that validate their input.

**التلميح 2:** Even less of these fields are persisted in a way where their content is shown on another screen.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 15. BL-715463

**الاسم الرسمي:** Product Tampering

**النص الرسمي:** Change the <code>href</code> of the link within the <a href="/#/search?q=OWASP SSL Advanced Forensic Tool (O-Saft)">OWASP SSL Advanced Forensic Tool (O-Saft)</a> product description into <i>https://owasp.slack.com</i>.

**التلميح 1:** Theoretically there are three possible ways to beat this challenge: a) broken admin functionality, b) holes in RESTful API or c) possibility for SQL Injection.

**التلميح 2:** In practice two of these three ways should turn out to be dead ends.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 16. BL-621340

**الاسم الرسمي:** Weird Crypto

**النص الرسمي:** <a href="/#/contact">Inform the shop</a> about an algorithm or library it should definitely not use the way it does.

**التلميح 1:** Report one of five possible answers via the "Customer Feedback" form.

**التلميح 2:** Cryptographic functions only used in the "Apply some advanced cryptanalysis to find the real easter egg" challenge do not count as they are only a developer’s prank and not a serious security problem.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 17. BL-990041

**الاسم الرسمي:** Memory Bomb

**النص الرسمي:** Drop some explosive data into a vulnerable file-handling endpoint.

**التلميح 1:** This one is actually similar to the XXE DoS challenge in every way except the data format being (ab)used.

**التلميح 2:** You can only solve this challenge by keeping the server busy for >2sec with your attack.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 18. BL-985633

**الاسم الرسمي:** Successful RCE DoS

**النص الرسمي:** Perform a Remote Code Execution that occupies the server for a while without using infinite loops.

**التلميح 1:** Your attack payload must not trigger the protection against too many iterations and infinite loops.

**التلميح 2:** This challenge uses the same leverage point as the "Perform a Remote Code Execution that would keep a less hardened application busy forever" challenge.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 19. BL-127806

**الاسم الرسمي:** Forged Review

**النص الرسمي:** Post a product review as another user or edit any user's existing review.

**التلميح 1:** Observe the flow of product review posting and editing and see if you can exploit it.

**التلميح 2:** This challenge can be solved by using developers tool of your browser or with tools like postman.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

### 20. BL-541114

**الاسم الرسمي:** Login Jim

**النص الرسمي:** Log in with Jim's user account.

**التلميح 1:** The challenge description probably gave away what form you should attack.

**التلميح 2:** You need to know (or smart-guess) Jim’s email address so you can launch a targeted attack.

**تصنيف المراجع:** ☐ measurable ☐ out_of_scope_reason ☐ needs_attacker_action

**تعليل المراجع (سطر):** ______________________________________________

---

*تُردّ هذه الورقة كما هي بعد التصنيف؛ المطابقة تجري لاحقاً بالمفتاح السرّي المنفصل.*
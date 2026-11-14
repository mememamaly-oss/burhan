# عينة مراجعة مستقلة — 20 تسمية من المرجع المولَّد (قرار المالك 1، 2026-11-13)

> **الغرض:** مراجعة مستقلة لقرارات المولّد قبل أي اعتماد للمرجع. **المرجع غير معتمد حتى ردك.**
> **البذرة:** 20261113 (قابلة لإعادة الإنتاج حرفياً: `random.Random(20261113)` ثم `sample` بنفس الترتيب) · العينة: 10 قابلة للقياس (من 46) + 10 خارج النطاق (من 70) من أصل 116.
> لكل تسمية: نص التحدي الرسمي (من challenges.yml @ v20.3.0) ثم قرار المولّد وسببه المولَّد آلياً. أول تلميحين رسميين مرفقان للاستزادة.

## 1. Forged Coupon  —  *measurable*

- **الفئة الرسمية:** Cryptographic Issues · **الصعوبة الرسمية:** 6 · **المعرّف:** `forgedCouponChallenge`
- **النص الرسمي للتحدي:** Forge a coupon code that gives you a discount of at least 80%.
- **الوسوم الرسمية:** Good for Demos, Code Analysis
- **تلميحان رسميان (من ثلاثة):** Try either a) a knowledgeable brute force attack or b) reverse engineering or c) some research in the cloud. | One viable solution would be to reverse-engineer how coupon codes are generated and craft your own 80% coupon by using the same (or at least similar) implementa
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Cryptographic Issues' maps to battery family 'jwt_security'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:jwt_security)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`jwt_security` · oracle=`finding_type_match:jwt_security` · auth_required=False

## 2. Christmas Special  —  *measurable*

- **الفئة الرسمية:** Injection · **الصعوبة الرسمية:** 4 · **المعرّف:** `christmasSpecialChallenge`
- **النص الرسمي للتحدي:** Order the Christmas special offer of 2014.
- **تلميحان رسميان (من ثلاثة):** Find out how the application handles unavailable products and try to find a loophole. | Find out how the application hides deleted products from its customers.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Injection' maps to battery family 'sql_injection'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:sql_injection)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`sql_injection` · oracle=`finding_type_match:sql_injection` · auth_required=False

## 3. Empty User Registration  —  *measurable*

- **الفئة الرسمية:** Improper Input Validation · **الصعوبة الرسمية:** 2 · **المعرّف:** `emptyUserRegistration`
- **النص الرسمي للتحدي:** Register a user with an empty email and password.
- **تلميحان رسميان (من ثلاثة):** Consider intercepting and playing with the request payload.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Improper Input Validation' maps to battery family 'xss_reflected'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:xss_reflected)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`xss_reflected` · oracle=`finding_type_match:xss_reflected` · auth_required=False

## 4. Product Tampering  —  *measurable*

- **الفئة الرسمية:** Broken Access Control · **الصعوبة الرسمية:** 3 · **المعرّف:** `changeProductChallenge`
- **النص الرسمي للتحدي:** Change the <code>href</code> of the link within the <a href="/#/search?q=OWASP SSL Advanced Forensic Tool (O-Saft)">OWASP SSL Advanced Forensic Tool (O-Saft)</a> product description into <i>https://owasp.slack.com</i>.
- **تلميحان رسميان (من ثلاثة):** Theoretically there are three possible ways to beat this challenge: a) broken admin functionality, b) holes in RESTful API or c) possibility for SQL Injection. | In practice two of these three ways should turn out to be dead ends.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Broken Access Control' maps to battery family 'idor_bola'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:idor_bola)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`idor_bola` · oracle=`finding_type_match:idor_bola` · auth_required=False

## 5. Poison Null Byte  —  *measurable*

- **الفئة الرسمية:** Improper Input Validation · **الصعوبة الرسمية:** 4 · **المعرّف:** `nullByteChallenge`
- **النص الرسمي للتحدي:** Bypass a security control with a <a href="https://hakipedia.com/index.php/Poison_Null_Byte">Poison Null Byte</a> to access a file not meant for your eyes.
- **الوسوم الرسمية:** Prerequisite
- **تلميحان رسميان (من ثلاثة):** Analyze and tamper with links in the application until you get to an unprotected directory listing. | Some files in there are not directly accessible because a security mechanism prevents access.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Improper Input Validation' maps to battery family 'xss_reflected'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:xss_reflected)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`xss_reflected` · oracle=`finding_type_match:xss_reflected` · auth_required=False

## 6. Admin Section  —  *measurable*

- **الفئة الرسمية:** Broken Access Control · **الصعوبة الرسمية:** 2 · **المعرّف:** `adminSectionChallenge`
- **النص الرسمي للتحدي:** Access the administration section of the store.
- **الوسوم الرسمية:** Good for Demos
- **تلميحان رسميان (من ثلاثة):** It is just slightly harder to find than the score board link. | Knowing it exists, you can simply guess what URL the admin section might have.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Broken Access Control' maps to battery family 'idor_bola'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:idor_bola)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`idor_bola` · oracle=`finding_type_match:idor_bola` · auth_required=False

## 7. Upload Type  —  *measurable*

- **الفئة الرسمية:** Improper Input Validation · **الصعوبة الرسمية:** 3 · **المعرّف:** `uploadTypeChallenge`
- **النص الرسمي للتحدي:** Upload a file that has no .pdf or .zip extension.
- **تلميحان رسميان (من ثلاثة):** You can attach a PDF or ZIP file to the "Complaint" form. Investigate how this upload actually works. | If you solved the "Upload a file larger than 100 kB" challenge, you should try to apply the same solution here
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Improper Input Validation' maps to battery family 'path_traversal'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:path_traversal)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`path_traversal` · oracle=`finding_type_match:path_traversal` · auth_required=False

## 8. Database Schema  —  *measurable*

- **الفئة الرسمية:** Injection · **الصعوبة الرسمية:** 3 · **المعرّف:** `dbSchemaChallenge`
- **النص الرسمي للتحدي:** Exfiltrate the entire DB schema definition via SQL Injection.
- **تلميحان رسميان (من ثلاثة):** Find out where this information could come from. Then craft an attack string against an endpoint that offers an unnecessary way to filter data. | Find out which database system is in use and where it would usually store its schema definitions.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Injection' maps to battery family 'sql_injection'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:sql_injection)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`sql_injection` · oracle=`finding_type_match:sql_injection` · auth_required=False

## 9. Weird Crypto  —  *measurable*

- **الفئة الرسمية:** Cryptographic Issues · **الصعوبة الرسمية:** 2 · **المعرّف:** `weirdCryptoChallenge`
- **النص الرسمي للتحدي:** <a href="/#/contact">Inform the shop</a> about an algorithm or library it should definitely not use the way it does.
- **تلميحان رسميان (من ثلاثة):** Report one of five possible answers via the "Customer Feedback" form. | Cryptographic functions only used in the "Apply some advanced cryptanalysis to find the real easter egg" challenge do not count as they are only a developer’s p
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Cryptographic Issues' maps to battery family 'jwt_security'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:jwt_security)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`jwt_security` · oracle=`finding_type_match:jwt_security` · auth_required=False

## 10. Greedy Chatbot Manipulation  —  *measurable*

- **الفئة الرسمية:** Injection · **الصعوبة الرسمية:** 3 · **المعرّف:** `chatbotGreedyInjectionChallenge`
- **النص الرسمي للتحدي:** Convince the chatbot to give you a coupon of 50% or more. Because apparently a 10% max policy is just a suggestion when you ask nicely enough.
- **الوسوم الرسمية:** AI/LLM
- **تلميحان رسميان (من ثلاثة):** The chatbot's system prompt says the maximum discount is 10%. But system prompts are more like guidelines than actual rules, right? | You already know how to make the chatbot generate a coupon. Now make it go way beyond the allowed maximum.
- **قرار المولّد:** `measurable`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** category 'Injection' maps to battery family 'sql_injection'; official definition shows no attacker-action/auth/client-side evidence (rule b keywords); automatic oracle derivable (finding_type_match:sql_injection)
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`sql_injection` · oracle=`finding_type_match:sql_injection` · auth_required=False

## 11. CAPTCHA Bypass  —  *out_of_scope_reason*

- **الفئة الرسمية:** Broken Anti Automation · **الصعوبة الرسمية:** 3 · **المعرّف:** `captchaBypassChallenge`
- **النص الرسمي للتحدي:** Submit 10 or more customer feedbacks within 20 seconds.
- **الوسوم الرسمية:** Brute Force
- **تلميحان رسميان (من ثلاثة):** After finding a CAPTCHA bypass, write a script that automates feedback submission. Or open many browser tabs and be really quick. | You could prepare 10 browser tabs, solving every CAPTCHA and filling out the each feedback form. Then you’d need to very quickly switch through the tabs and sub
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official category 'Broken Anti Automation' has no engine battery family (declared CATEGORY_TO_FAMILY table) — class gap
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`none` · oracle=`no automatic oracle derivable` · auth_required=False

## 12. Blockchain Hype  —  *out_of_scope_reason*

- **الفئة الرسمية:** Security through Obscurity · **الصعوبة الرسمية:** 5 · **المعرّف:** `tokenSaleChallenge`
- **النص الرسمي للتحدي:** Learn about the Token Sale before its official announcement.
- **الوسوم الرسمية:** Contraption, Code Analysis, Web3
- **تلميحان رسميان (من ثلاثة):** The developers truly believe in "Security through Obscurity" over actual access restrictions. | Guessing or brute forcing the URL of the token sale page is very unlikely to succeed.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official category 'Security through Obscurity' has no engine battery family (declared CATEGORY_TO_FAMILY table) — class gap
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`none` · oracle=`no automatic oracle derivable` · auth_required=False

## 13. Successful RCE DoS  —  *out_of_scope_reason*

- **الفئة الرسمية:** Insecure Deserialization · **الصعوبة الرسمية:** 6 · **المعرّف:** `rceOccupyChallenge`
- **النص الرسمي للتحدي:** Perform a Remote Code Execution that occupies the server for a while without using infinite loops.
- **الوسوم الرسمية:** Danger Zone
- **تلميحان رسميان (من ثلاثة):** Your attack payload must not trigger the protection against too many iterations and infinite loops. | This challenge uses the same leverage point as the "Perform a Remote Code Execution that would keep a less hardened application busy forever" challenge.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official category 'Insecure Deserialization' has no engine battery family (declared CATEGORY_TO_FAMILY table) — class gap
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`none` · oracle=`no automatic oracle derivable` · auth_required=False

## 14. Login Cloud Admin  —  *out_of_scope_reason*

- **الفئة الرسمية:** Sensitive Data Exposure · **الصعوبة الرسمية:** 4 · **المعرّف:** `iacLeakedKeyChallenge`
- **النص الرسمي للتحدي:** Log in with the cloud admin's user account <i>without</i> using SQL Injection.
- **تلميحان رسميان (من ثلاثة):** Brute forcing the password will not work. The password is too strong. | There might be another way to authenticate besides using the correct password.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official definition requires: requires login/authenticated session
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`credential_exposure` · oracle=`outside unauthenticated DAST reach` · auth_required=True

## 15. Client-side XSS Protection  —  *out_of_scope_reason*

- **الفئة الرسمية:** XSS · **الصعوبة الرسمية:** 3 · **المعرّف:** `persistedXssUserChallenge`
- **النص الرسمي للتحدي:** Perform a <i>persisted</i> XSS attack with <code>&lt;iframe src="javascript:alert(`xss`)"&gt;</code> bypassing a <i>client-side</i> security mechanism.
- **الوسوم الرسمية:** Danger Zone
- **تلميحان رسميان (من ثلاثة):** There are only some input fields in the Juice Shop forms that validate their input. | Even less of these fields are persisted in a way where their content is shown on another screen.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official definition requires: client-side rendering/inspection required
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`xss_reflected` · oracle=`outside unauthenticated DAST reach` · auth_required=False

## 16. Privacy Policy  —  *out_of_scope_reason*

- **الفئة الرسمية:** Miscellaneous · **الصعوبة الرسمية:** 1 · **المعرّف:** `privacyPolicyChallenge`
- **النص الرسمي للتحدي:** Read our privacy policy.
- **الوسوم الرسمية:** Good Practice, Tutorial, Good for Demos
- **تلميحان رسميان (من ثلاثة):** We won't even ask you to confirm that you did. Just read it. Please. Pretty please. | When you work with the application you will most likely solve this challenge in the process.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official category 'Miscellaneous' has no engine battery family (declared CATEGORY_TO_FAMILY table) — class gap
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`none` · oracle=`no automatic oracle derivable` · auth_required=False

## 17. Admin Registration  —  *out_of_scope_reason*

- **الفئة الرسمية:** Improper Input Validation · **الصعوبة الرسمية:** 3 · **المعرّف:** `registerAdminChallenge`
- **النص الرسمي للتحدي:** Register as a user with administrator privileges.
- **تلميحان رسميان (من ثلاثة):** You have to assign the unassignable. | Register as an ordinary user to learn what API endpoints are involved in this use case.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official definition requires: account-creation attacker flow
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`xss_reflected` · oracle=`outside unauthenticated DAST reach` · auth_required=False

## 18. Forged Review  —  *out_of_scope_reason*

- **الفئة الرسمية:** Broken Access Control · **الصعوبة الرسمية:** 3 · **المعرّف:** `forgedReviewChallenge`
- **النص الرسمي للتحدي:** Post a product review as another user or edit any user's existing review.
- **تلميحان رسميان (من ثلاثة):** Observe the flow of product review posting and editing and see if you can exploit it. | This challenge can be solved by using developers tool of your browser or with tools like postman.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official definition requires: multi-account/multi-step attacker action
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`idor_bola` · oracle=`outside unauthenticated DAST reach` · auth_required=False

## 19. Memory Bomb  —  *out_of_scope_reason*

- **الفئة الرسمية:** Insecure Deserialization · **الصعوبة الرسمية:** 5 · **المعرّف:** `yamlBombChallenge`
- **النص الرسمي للتحدي:** Drop some explosive data into a vulnerable file-handling endpoint.
- **الوسوم الرسمية:** Danger Zone
- **تلميحان رسميان (من ثلاثة):** This one is actually similar to the XXE DoS challenge in every way except the data format being (ab)used. | You can only solve this challenge by keeping the server busy for >2sec with your attack.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official category 'Insecure Deserialization' has no engine battery family (declared CATEGORY_TO_FAMILY table) — class gap
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`none` · oracle=`no automatic oracle derivable` · auth_required=False

## 20. Login Jim  —  *out_of_scope_reason*

- **الفئة الرسمية:** Injection · **الصعوبة الرسمية:** 3 · **المعرّف:** `loginJimChallenge`
- **النص الرسمي للتحدي:** Log in with Jim's user account.
- **الوسوم الرسمية:** Tutorial
- **تلميحان رسميان (من ثلاثة):** The challenge description probably gave away what form you should attack. | You need to know (or smart-guess) Jim’s email address so you can launch a targeted attack.
- **قرار المولّد:** `out_of_scope_reason`
- **سبب المولّد (المولَّد آلياً بقاعدة معلنة):** official definition requires: requires login/authenticated session
- **خرائط الفئة/الأوراكل:** vuln_type_mapping=`sql_injection` · oracle=`outside unauthenticated DAST reach` · auth_required=True

---

**أسئلة المراجعة المقترحة:** (1) هل تسمية «قابلة للقياس» صحيحة لكل عينة من العشر؟ (2) هل أسباب خارج النطاق مقنعة أم مبالغ فيها/مفرطة في الحذر؟ (3) أي تسمية تحدها حدود رمادية تستحق نقاشاً؟

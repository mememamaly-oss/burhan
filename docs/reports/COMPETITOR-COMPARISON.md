# M3: ZAP baseline vs Nuclei vs Burhan proof

## Final execution

- Comparison workflow: [43978489296](https://github.com/mememamaly-oss/burhan/actions/runs/43978489296)
- Active-ZAP workflow: [43978493391](https://github.com/mememamaly-oss/burhan/actions/runs/43978493391)
- Commit: `d9edc0aa4b1bb8397fab71e407f60f926387f076`
- Targets: Juice Shop, crAPI, WebGoat, DVWA only; internal Docker network.
- ZAP comparison mode: **baseline**. Active ZAP was a separate workflow/job.
- Nuclei templates: v10.5.0, pinned commit `f8b8b8dcd70d93826c3767e1829ef8243af9f03b`, archive SHA-256 verified in the job.
- Burhan proof: ephemeral owner password generated inside the job with `openssl rand -hex 24`, masked, initialized through `burhan owner init` using environment only, and removed after the job. Artifact grep found no credential.
- Measurement unit: distinct `(standard_type, path)` pairs per severity. `info` is displayed separately and is not a vulnerability or Burhan gap.

## ZAP active results

| Target | Duration (s) | Requests | Alerts | Spider timed out | Active timed out | Quality |
|---|---:|---:|---:|---|---|---|
| crapi | 150 | 781 | 77 | no | no | complete |
| dvwa | 187 | 2015 | 174 | no | no | complete |
| juice-shop | 212 | 3447 | 235 | no | yes | partial-time-bounded |
| webgoat | 135 | 2450 | 131 | no | no | complete |

## Full comparison table

# ZAP baseline vs Nuclei vs Burhan proof

| Target | Severity | Standard type | Path | ZAP | Nuclei | Burhan proof | Evidence | Gap for Burhan? |
|---|---|---|---|---:|---:|---:|---|---|
| crapi | high | CWE-522 | //.env | 0 | 1 | 0 | nuclei: Laravel - Sensitive Information Disclosure | yes |
| crapi | high | CWE-552 | //.env | 0 | 1 | 0 | nuclei: Generic Env File Disclosure | yes |
| crapi | high | NO-CWE|BURHAN:weak_random | /static/js/main.8c78208c.js | 0 | 0 | 1 | burhan: weak_random | no |
| crapi | medium | CWE-1021 | http://crapi-web | 1 | 0 | 0 | zap: Missing Anti-clickjacking Header | yes |
| crapi | medium | CWE-693 | http://crapi-web | 1 | 0 | 0 | zap: Content Security Policy (CSP) Header Not Set | yes |
| crapi | low | CWE-497 | http://crapi-web | 1 | 0 | 0 | zap: Server Leaks Version Information via "Server" HTTP Response Header Field | yes |
| crapi | low | CWE-693 | http://crapi-web | 1 | 0 | 0 | zap: X-Content-Type-Options Header Missing | yes |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | / | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /images/favicon.ico | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /images/logo192.png | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /manifest.json | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /static/css/main.dd33429d.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /static/js/'),B=f(' | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:missing_security_headers | /static/js/main.8c78208c.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | / | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /images/favicon.ico | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /images/logo192.png | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /manifest.json | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /static/css/main.dd33429d.css | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /static/js/'),B=f(' | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | low | NO-CWE|BURHAN:server_banner_disclosure | /static/js/main.8c78208c.js | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| crapi | info | CWE-524 | http://crapi-web | 1 | 0 | 0 | zap: Storable and Cacheable Content | no |
| crapi | info | CWE-693 | / | 0 | 1 | 0 | nuclei: HTTP Missing Security Headers | no |
| crapi | info | NO-CWE|NUCLEI-TAGS:discovery,dns,soa|soa-detect | crapi-web | 0 | 1 | 0 | nuclei: SOA Record Service - Detection | no |
| crapi | info | NO-CWE|NUCLEI-TAGS:discovery,generic,misc,miscellaneous|robots-txt-endpoint | /robots.txt | 0 | 1 | 0 | nuclei: robots.txt endpoint prober | no |
| crapi | info | NO-CWE|NUCLEI-TAGS:discovery,openresty,tech|openresty-detect | / | 0 | 1 | 0 | nuclei: OpenResty detection | no |
| crapi | info | NO-CWE|NUCLEI-TAGS:generic,misc,miscellaneous,vuln|robots-txt | /robots.txt | 0 | 1 | 0 | nuclei: robots.txt file | no |
| crapi | info | NO-CWE|WASC--1 | http://crapi-web | 1 | 0 | 0 | zap: Modern Web Application | no |
| dvwa | high | CWE-1395 | http://dvwa | 1 | 0 | 0 | zap: Apache HTTP Server Version with Known Vulnerabilities | yes |
| dvwa | medium | CWE-1021 | http://dvwa | 1 | 0 | 0 | zap: Missing Anti-clickjacking Header | yes |
| dvwa | medium | CWE-200 | /config/ | 0 | 1 | 0 | nuclei: Sensitive Configuration Files Listing - Detect | yes |
| dvwa | medium | CWE-693 | http://dvwa | 1 | 0 | 0 | zap: Content Security Policy (CSP) Header Not Set | yes |
| dvwa | low | CWE-1004 | http://dvwa | 1 | 0 | 0 | zap: Cookie No HttpOnly Flag | yes |
| dvwa | low | CWE-1275 | http://dvwa | 1 | 0 | 0 | zap: Cookie without SameSite Attribute | yes |
| dvwa | low | CWE-497 | http://dvwa | 1 | 0 | 0 | zap: Server Leaks Version Information via "Server" HTTP Response Header Field | yes |
| dvwa | low | CWE-693 | http://dvwa | 1 | 0 | 0 | zap: X-Content-Type-Options Header Missing | yes |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | / | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /about.php | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /docs/DVWA_v1.3.pdf | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /dvwa/css/main.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /dvwa/js/dvwaPage.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /favicon.ico | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:missing_security_headers | /instructions.php | 0 | 0 | 1 | burhan: missing_security_headers | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | / | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /about.php | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /docs/DVWA_v1.3.pdf | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /dvwa/css/main.css | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /dvwa/js/dvwaPage.js | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /favicon.ico | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | low | NO-CWE|BURHAN:server_banner_disclosure | /instructions.php | 0 | 0 | 1 | burhan: server_banner_disclosure | no |
| dvwa | info | CWE-1004 | 80 | 0 | 1 | 0 | nuclei: Cookies without HttpOnly attribute - Detect | no |
| dvwa | info | CWE-200 | / | 0 | 1 | 0 | nuclei: WAF Detection | no |
| dvwa | info | CWE-524 | http://dvwa | 1 | 0 | 0 | zap: Storable but Non-Cacheable Content | no |
| dvwa | info | CWE-614 | 80 | 0 | 1 | 0 | nuclei: Cookies without Secure attribute - Detect | no |
| dvwa | info | CWE-615 | http://dvwa | 1 | 0 | 0 | zap: Information Disclosure - Suspicious Comments | no |
| dvwa | info | CWE-693 | / | 0 | 1 | 0 | nuclei: Missing Cookie SameSite Strict | no |
| dvwa | info | NO-CWE|NUCLEI-TAGS:discovery,dns,soa|soa-detect | dvwa | 0 | 1 | 0 | nuclei: SOA Record Service - Detection | no |
| dvwa | info | NO-CWE|NUCLEI-TAGS:discovery,generic,misc,miscellaneous|robots-txt-endpoint | /robots.txt | 0 | 1 | 0 | nuclei: robots.txt endpoint prober | no |
| dvwa | info | NO-CWE|NUCLEI-TAGS:discovery,tech|tech-detect | / | 0 | 1 | 0 | nuclei: Wappalyzer Technology Detection | no |
| dvwa | info | NO-CWE|NUCLEI-TAGS:generic,misc,miscellaneous,vuln|robots-txt | /robots.txt | 0 | 1 | 0 | nuclei: robots.txt file | no |
| dvwa | info | NO-CWE|WASC--1 | http://dvwa | 1 | 0 | 0 | zap: Session Management Response Identified | no |
| juice-shop | medium | CWE-264 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Cross-Domain Misconfiguration | yes |
| juice-shop | medium | CWE-693 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Content Security Policy (CSP) Header Not Set | yes |
| juice-shop | low | CWE-16 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Deprecated Feature Policy Header Set | yes |
| juice-shop | low | CWE-693 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Cross-Origin-Opener-Policy Header Missing or Invalid | yes |
| juice-shop | low | CWE-749 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Dangerous JS Functions | yes |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | / | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /assets/public/favicon_js.ico | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /basket | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /chunk-1qQQGal7.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /chunk-Cv2YgWUq.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /chunk-DBPdFzgj.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /main.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /polyfills.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /redirect | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /rolldown-runtime-BoHGiXSq.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /scripts.js | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /styles.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | low | NO-CWE|BURHAN:missing_security_headers | /{{href}} | 0 | 0 | 1 | burhan: missing_security_headers | no |
| juice-shop | info | CWE-200 | //api-docs/swagger.json | 0 | 1 | 0 | nuclei: Public Swagger API - Detect | no |
| juice-shop | info | CWE-524 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Storable but Non-Cacheable Content | no |
| juice-shop | info | NO-CWE|WASC--1 | http://juice-shop:3000 | 1 | 0 | 0 | zap: Modern Web Application | no |
| webgoat | medium | CWE-352 | http://webgoat:8080 | 1 | 0 | 0 | zap: Absence of Anti-CSRF Tokens | yes |
| webgoat | medium | CWE-693 | http://webgoat:8080 | 1 | 0 | 0 | zap: Content Security Policy (CSP) Header Not Set | yes |
| webgoat | medium | NO-CWE|BURHAN:host_header_injection | /WebGoat/ | 0 | 0 | 1 | burhan: host_header_injection | no |
| webgoat | medium | NO-CWE|BURHAN:host_header_injection | /WebGoat/start.mvc | 0 | 0 | 1 | burhan: host_header_injection | no |
| webgoat | low | CWE-1004 | http://webgoat:8080 | 1 | 0 | 0 | zap: Cookie No HttpOnly Flag | yes |
| webgoat | low | CWE-1275 | http://webgoat:8080 | 1 | 0 | 0 | zap: Cookie without SameSite Attribute | yes |
| webgoat | low | CWE-693 | http://webgoat:8080 | 1 | 0 | 0 | zap: Permissions Policy Header Not Set | yes |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/ | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/css/animate.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/css/font-awesome.min.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/css/img/favicon.ico | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/css/main.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/login | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/plugins/bootstrap/css/bootstrap.min.css | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/registration | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|BURHAN:missing_security_headers | /WebGoat/start.mvc | 0 | 0 | 1 | burhan: missing_security_headers | no |
| webgoat | low | NO-CWE|NUCLEI-TAGS:env,exposure,misconfig,springboot,vuln|springboot-env | /WebGoat/actuator/env | 0 | 1 | 0 | nuclei: Springboot Env Actuator - Detect | yes |
| webgoat | low | NO-CWE|NUCLEI-TAGS:exposure,misconfig,springboot,vuln|springboot-configprops | /WebGoat/actuator/configprops | 0 | 1 | 0 | nuclei: Detect Springboot Configprops Actuator | yes |
| webgoat | info | CWE-1004 | 8080 | 0 | 1 | 0 | nuclei: Cookies without HttpOnly attribute - Detect | no |
| webgoat | info | CWE-20 | http://webgoat:8080 | 1 | 0 | 0 | zap: User Controllable HTML Element Attribute (Potential XSS) | no |
| webgoat | info | CWE-200 | /WebGoat/actuator/health | 0 | 1 | 0 | nuclei: Spring Boot Health Actuator Panel - Detect | no |
| webgoat | info | CWE-524 | http://webgoat:8080 | 1 | 0 | 0 | zap: Storable and Cacheable Content | no |
| webgoat | info | CWE-614 | 8080 | 0 | 1 | 0 | nuclei: Cookies without Secure attribute - Detect | no |
| webgoat | info | CWE-693 | /WebGoat/ | 0 | 1 | 0 | nuclei: Missing Cookie SameSite Strict | no |
| webgoat | info | CWE-693 | /WebGoat/login | 0 | 1 | 0 | nuclei: HTTP Missing Security Headers | no |
| webgoat | info | CWE-79 | /WebGoat/ | 0 | 1 | 0 | nuclei: XSS-Protection Header - Cross-Site Scripting | no |
| webgoat | info | NO-CWE|NUCLEI-TAGS:detection,discovery,plugin,tech,wordpress,wp,wp-plugin|wordpress-plugin-detect | /WebGoat/login | 0 | 1 | 0 | nuclei: Wordpress Plugin Detection | no |
| webgoat | info | NO-CWE|NUCLEI-TAGS:disclosure,misconfig,vuln|internal-ip-disclosure | /WebGoat/ | 0 | 1 | 0 | nuclei: Internal IP Disclosure | no |
| webgoat | info | NO-CWE|NUCLEI-TAGS:discovery,dns,soa|soa-detect | webgoat | 0 | 1 | 0 | nuclei: SOA Record Service - Detection | no |
| webgoat | info | NO-CWE|NUCLEI-TAGS:discovery,tech|tech-detect | /WebGoat/login | 0 | 1 | 0 | nuclei: Wappalyzer Technology Detection | no |
| webgoat | info | NO-CWE|NUCLEI-TAGS:form,misc,miscellaneous,vuln|form-detection | /WebGoat/login | 0 | 1 | 0 | nuclei: Form Detection | no |
| webgoat | info | NO-CWE|WASC--1 | http://webgoat:8080 | 1 | 0 | 0 | zap: Session Management Response Identified | no |

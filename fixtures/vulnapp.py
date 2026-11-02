#!/usr/bin/env python3
"""Burhan Benchmark Fixture v1 — locally-hosted intentionally vulnerable app.
GROUND TRUTH (see benchmarks/ground_truth.json):
  /vuln/sqli_error.php?id      -> sql_injection (error-based)
  /vuln/sqli_blind.php?id      -> sql_injection (boolean oracle 200/500)
  /vuln/xss.php?q              -> xss_reflected (raw reflection)
  /vuln/traversal.php?file     -> path_traversal (reads BURHAN-SECRET-FILE)
  /vuln/redirect.php?url       -> open_redirect (Location header)
  /vuln/jsparam.php?cat        -> sql_injection (500-on-quote, no DB string) +
                                  xss_reflected (slash-escaping app: <> raw, / escaped) +
                                  http_response_header_injection (Set-Cookie CRLF)
                                  [param only discoverable via inline <script> URLs — DISC-05]
  /vuln/stock POST XML         -> xxe (JS-transformed request; entity file-read differential)
  /vuln/oob-stock POST XML     -> xxe BLIND (noise response; confirmable ONLY out-of-band)
  /safe/oob-stock POST XML     -> NEGATIVE (DTD rejected — no entity fetch, no callback)
  /vuln/fetch?url              -> ssrf (blind server-side fetch; OOB-confirmed only)
  /safe/fetch?url              -> NEGATIVE (allowlist — no fetch of attacker URLs)
  /vuln/ping?host              -> command_injection (shell=True interpolation; OOB-confirmed)
  /safe/ping?host              -> NEGATIVE (argv list, no shell — injection impossible)
  /vuln/cors                   -> cors_misconfig (arbitrary Origin reflected + credentials)
  /safe/cors                   -> NEGATIVE (fixed allowlisted origin)
  /angular_1-7-7.js            -> vulnerable_js_dependency (passive)
  /safe/search.php?q           -> NEGATIVE (escaped)
  /safe/item.php?id            -> NEGATIVE (parameterized)
  /safe/read.php?file          -> NEGATIVE (basename filter)
  /safe/go.php?url             -> NEGATIVE (allowlist)
  /safe/jsparam.php?cat        -> NEGATIVE (inline-JS-discoverable but safe)
  /safe/stock POST XML         -> NEGATIVE (DTD rejected — no entity resolution)
  all pages                    -> missing_security_headers (positive, passive)

Fixture v8 (Phase 56 — Intelligence Layer ground truth):
  /api/data?user_id            -> idor_bola (no object-level authz: any authed
                                   account reads ANY profile; victim marker oracle)
  /api/secure/data?user_id     -> NEGATIVE (ownership enforced -> 403)
  /api/admin/stats             -> vertical_privilege_escalation (authed, NO role
                                   check: any user gets the admin view)
  /api/secure/admin/stats      -> NEGATIVE (admin role enforced -> 403)
  /vuln/leak-config            -> credential_exposure (AWS key + GitHub token +
                                   credential-bearing DB URI in one config doc)
  /safe/leak-config            -> NEGATIVE (values masked — placeholders, not secrets)
  /api/filter?filter={...}     -> param-intel surface (JSON-object valued param:
                                   string batteries provably skipped, nothing lost)
  Multi-user auth: demo/demo123 (admin), bob/bob123 (user), carol/carol123 (user)
  — the Authorization Engine's login matrix (AUTHZ-01..04).

Fixture v9 (Phase 58 — Workflow / Business-Logic Intelligence ground truth):
  /wf/transfer/{start,select,create,confirm,ledger}
     -> five-step banking wizard, VULNERABLE to all five logic classes:
        business_logic_step_bypass          (create without select)
        business_logic_out_of_order         (confirm without create: unknown tid
                                             executes from POSTed params alone)
        business_logic_value_tamper         (amount overridden at confirm)
        business_logic_duplicate_execution  (confirm replays; ledger shows the
                                             same tid executed twice)
        business_logic_privilege_escalation (mode=wire "admin only" option
                                             executed by a regular user)
  /wf/safe/transfer/{...}  -> NEGATIVE twin: identical shape, every manipulation
                             refused with the right status and NO state change
                             (ledger = the state oracle that proves it either way)
"""
import json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

DELAY_MS = float(os.environ.get("DELAY_MS", "0"))   # for chaos/repair demos: artificial per-request latency

SECRET_FILE = "BURHAN-SECRET-FILE: benchmark-fixture-secret-do-not-leak\n"

# Fake filesystem for the XXE endpoint (entity resolution simulation — the real
# ginandjuice.shop oracle behaved exactly like this: distinct response per readable
# file, failed/unreadable entities equal the nonexistent control).
FAKE_FS = {
    "/etc/hostname": "fixture-host-01",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "/etc/group": "root:x:0:\ndaemon:x:1:\nbin:x:2:\n",
    "/etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\n",
}

HEADER_TMPL = """<!DOCTYPE html><html><head><title>Burhan Fixture</title></head><body>
<div class="menubar"><a href="/">home</a>
 - <a href="/vuln/ssti?name=world">ssti</a> - <a href="/safe/ssti?name=world">safe ssti</a>
 - <a href="/vuln/hostbuild">host header</a> - <a href="/safe/hostbuild">safe host</a>
 - <a href="/lab">lab</a> - <a href="/vuln/sqli_error.php?id=1">sqli err</a>
 - <a href="/vuln/sqli_blind.php?id=1">sqli blind</a> - <a href="/vuln/xss.php?q=test">xss</a>
 - <a href="/vuln/traversal.php?file=notes.txt">traversal</a> - <a href="/vuln/redirect.php?url=https://example.com">redirect</a>
 - <a href="/safe/search.php?q=test">safe search</a> - <a href="/safe/item.php?id=1">safe item</a>
 - <a href="/safe/read.php?file=notes.txt">safe read</a> - <a href="/hidden.php">hidden</a>
 - <a href="/safe/jsparam.php?cat=Books">safe jsparam</a> - <a href="/app.js">app.js</a>
 - <a href="/vuln/dom-write">dom-write</a> - <a href="/safe/dom-text?search=test">safe dom-text</a>
 - <a href="/vuln/divform">divform</a> - <a href="/safe/divform">safe divform</a>
 - <a href="/vuln/csrfdivform">csrf divform</a> - <a href="/vuln/jsform">jsform</a> - <a href="/login">sign in</a>
 - <a href="/vuln/fetch?url=http://api.local/feed">ssrf</a> - <a href="/safe/fetch?url=http://api.local/feed">safe fetch</a>
 - <a href="/vuln/ping?host=localhost">cmdi</a> - <a href="/safe/ping?host=localhost">safe ping</a>
 - <a href="/vuln/cors">cors api</a> - <a href="/safe/cors">safe cors</a>
 - <a href="/vuln/leak-config">debug config</a> - <a href="/safe/leak-config">safe config</a>
 - <a href="/api/filter?filter=%7B%22status%22%3A%22active%22%7D">api filter</a></div>
{body}
</body></html>"""

NOTES = "These are public notes. Nothing secret here.\n"
APP_JS = """
const API_BASE = "/api/";
fetch(API_BASE + "items?id=1");
$.ajax({url: "/api/users?id=2"});
new WebSocket("wss://localhost/ws");
"""

# Mirrors ginandjuice.shop xmlStockCheckPayload.js: JS rebuilds the form POST as XML.
STOCKAPP_JS = """
window.contentType = 'application/xml';
function payload(data) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?>';
    xml += '<stockCheck>';
    for(var pair of data.entries()) { xml += '<' + pair[0] + '>' + pair[1] + '</' + pair[0] + '>'; }
    xml += '</stockCheck>';
    return xml;
}
"""

# The page that hides the /vuln/jsparam.php?cat surface inside an inline <script>
# (only reachable via DISC-05 inline-JS URL extraction) and carries the XML stock forms.
HIDDEN_PAGE = """<h2>Products</h2>
<script type="text/javascript">
    const categories = {"Gin":"/vuln/jsparam.php?cat=Gin","Books":"/vuln/jsparam.php?cat=Books"};
    const selectedCategory = "All";
</script>
<script src="/stockapp.js"></script>
<script src="/angular_1-7-7.js"></script>
<form action="/vuln/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Check stock</button></form>
<form action="/safe/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Safe stock</button></form>
<form action="/blind/stock" method="POST"><input type="hidden" name="productId" value="1"><button>Blind stock</button></form>
<form action="/vuln/oob-stock" method="POST"><input type="hidden" name="productId" value="1"><button>Blind stock (OOB)</button></form>
<form action="/safe/oob-stock" method="POST"><input type="hidden" name="productId" value="1"><button>Safe blind stock</button></form>
"""

ANGULAR_JS = "/* AngularJS v1.7.7 stub — EOL branch served for passive dependency detection */\n"

# ==================== Phase 50 (fixture v4): browser/DOM surfaces ====================
# The server NEVER reflects ?search= on either page below — the param is read
# client-side from URLSearchParams and passed to a sink. /vuln/dom-write uses a
# dangerous sink (mirrors ginandjuice.shop /blog?search: document.write into an
# attribute context); /safe/dom-text uses textContent. ONLY a real browser can
# separate them — the DOM-engine ground truth pair.
DOM_WRITE_PAGE = """<h2>Search tracker</h2>
<form action="/vuln/dom-write" method="GET"><input type="text" name="search" value="test"><button>Track</button></form>
<script>
function trackSearch(query) {
    document.write('<img src="/tracker.gif?searchTerms=' + query + '">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) { trackSearch(query); }
</script>
<div>Search tracked.</div>"""

# Param-less variant: like ginandjuice.shop /blog/ (index) vs /blog?search= (results)
# — the DOM source->sink script is server-side CONDITIONAL, so the param-less page
# carries no script at all. Reaching the script REQUIRES DISC-12 form-target queueing.
DOM_WRITE_PAGE_PLAIN = """<h2>Search tracker</h2>
<form action="/vuln/dom-write" method="GET"><input type="text" name="search" value="test"><button>Track</button></form>
<div>Enter a search term.</div>"""

DOM_TEXT_PAGE = """<h2>Search echo</h2>
<div id="out"></div>
<script>
var q = new URLSearchParams(window.location.search).get('search');
if (q) { document.getElementById('out').textContent = q; }
</script>"""

# Mirrors ginandjuice.shop subscribeNow.js: div-based pseudo-forms are serialized
# as JSON (JSON.stringify + Content-Type application/json) — DISC-10 learns the
# transformation statically from this asset, ENG-04 replays it deterministically.
JSBUILD_JS = """
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('div[data-action]').forEach(function (f) {
        var btn = f.querySelector('button');
        if (!btn) return;
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            var value = {};
            f.querySelectorAll('input').forEach(function (i) { value[i.name] = i.value; });
            var xhr = new XMLHttpRequest();
            xhr.open(f.dataset.method, f.dataset.action);
            xhr.setRequestHeader('Content-Type', 'application/json;charset=UTF-8');
            xhr.send(JSON.stringify(value));
        });
    });
});
"""

DIVFORM_PAGE = """<h2>Subscribe</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/vuln/json-reflect">
<input required type="text" name="name" placeholder="Name">
<button class="button" type="submit">Subscribe</button>
</div>"""

SAFE_DIVFORM_PAGE = """<h2>Subscribe (safe)</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/safe/json-reflect">
<input required type="text" name="name" placeholder="Name">
<button class="button" type="submit">Subscribe</button>
</div>"""

# CSRF-protected flow (ENG-05 ground truth): the page sets a deterministic session
# cookie and embeds the matching token; the POST endpoint rejects requests without
# BOTH. Without the engine cookie jar this surface is unreachable ("Invalid CSRF").
import hashlib as _hl
CSRF_SESSION = "fixedsess123"
CSRF_TOKEN = _hl.sha1((CSRF_SESSION + "|csrf").encode()).hexdigest()[:16]

# ======================= Phase 51 (fixture v5): AUTHENTICATED SURFACE =======================
# Real Altoro-style flow, engineered to exercise every auth capability:
#   GET  /login          -> Set-Cookie SESS=s1 + form with hidden csrfToken (AUTH-01:
#                           the token is session-bound and CHANGES every GET — a
#                           hard-coded-fields login can never pass)
#   POST /doLogin        -> validates SESS+csrf+creds, then ROTATES the session:
#                           Set-Cookie SESS=s2 + AUTH=granted-s2 on a 302 to /home.
#                           The redirect hop itself needs the fresh cookies (ENG-07:
#                           the engine must rebuild the Cookie header per hop).
#   /home                -> authenticated landing ("Sign Off" marker) — the ONLY
#                           page linking the authenticated surface (like Altoro /bank/*)
#   /account?q=          -> auth-gated RAW reflection        [TP xss_reflected]
#   /account?tab=        -> auth-gated ESCAPED reflection    [TN xss_reflected]
#   /vault/transfer?acct -> auth-gated boolean SQLi oracle   [TP sql_injection]
#   AUTH_TTL=<n> env     -> server-side session expiry after n authenticated requests
#                           (AUTH-03 watchdog: mid-scan session loss -> re-auth)
# ==================== Phase 56 (fixture v8): MULTI-USER authorization surface ====================
# Three real accounts with distinct roles and distinct private markers — the
# substrate the Authorization Engine tests (AUTHZ-01..04):
#   demo  / demo123  -> role=admin, object 1001, marker root-admin@…
#   bob   / bob123   -> role=user,  object 2002, marker bob-user@…
#   carol / carol123 -> role=user,  object 3003, marker carol-user@…
# The markers are UNIQUE substrings that appear ONLY in that account's profile
# response — the victim-marker oracle for IDOR (plus a listing guard: a page
# carrying several markers at once is a directory, not object-level access).
AUTH_USERS = {
    "demo":  {"pass": "demo123",  "role": "admin", "uid": "1001",
              "email": "root-admin@burhan-fixture.local"},
    "bob":   {"pass": "bob123",   "role": "user",  "uid": "2002",
              "email": "bob-user@burhan-fixture.local"},
    "carol": {"pass": "carol123", "role": "user",  "uid": "3003",
              "email": "carol-user@burhan-fixture.local"},
}
PROFILES = {u["uid"]: {"user_id": uid, "username": name, "email": u["email"],
                       "role": u["role"]}
            for name, u in AUTH_USERS.items() for uid in [u["uid"]]}
ADMIN_STATS = {"admins": 3, "monthly_revenue": "9137", "flag": "ADMIN-ONLY-VIEW"}
# credential-exposure surfaces: one config doc leaking three REAL-shaped
# secret classes (AWS key / GitHub token / credential-bearing DB URI), and a
# hardened twin whose values are masked placeholders (hygiene, NOT secrets).
LEAK_CONFIG = {"app": "fixture", "env": "prod",
               "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
               "github_token": "ghp_BURHANFIXTUREGHPTOKEN1234567890",
               "database_url": "mysql://app:s3nt1nelDbPw@10.0.0.5:3306/fixture"}
SAFE_LEAK_CONFIG = {"app": "fixture", "env": "prod",
                    "aws_access_key_id": "AKIA********************",
                    "github_token": "ghp_********************",
                    "database_url": "internal-only (credentials vaulted)"}
AUTH_TTL = int(os.environ.get("AUTH_TTL", "0"))   # 0 = never expires
SESSIONS: dict[str, dict] = {}                     # sess_id -> {csrf, authed, hits, user, role, uid}

def _new_session() -> str:
    sid = _hl.sha1((str(time.time()) + str(os.getpid()) + _hl.md5(str(time.time_ns()).encode()).hexdigest()).encode()).hexdigest()[:12]
    SESSIONS[sid] = {"csrf": _hl.sha1((sid + "|csrf").encode()).hexdigest()[:16],
                     "authed": False, "hits": 0}
    return sid

def _sess_authed(self):
    """Resolve the caller's session; None when anonymous/expired. Applies TTL."""
    cookie = self.headers.get("Cookie") or ""
    m = re.search(r"SESS=([0-9a-f]{12})", cookie)
    if not m: return None
    sid = m.group(1)
    s = SESSIONS.get(sid)
    if s is None or not s.get("authed"): return None
    if f"AUTH=granted-{sid}" not in cookie: return None
    if AUTH_TTL and s["hits"] >= AUTH_TTL:
        SESSIONS.pop(sid, None)                    # server-side expiry
        return None
    s["hits"] += 1
    return sid

def _sess_user(self):
    """Resolve the caller's AUTHENTICATED session record (or None)."""
    sid = _sess_authed(self)
    return (sid, SESSIONS[sid]) if sid else None

def _menubar_for(sess: dict) -> str:
    """Role-aware navigation: every authenticated account sees the common
    banking links plus its OWN profile links (own object id); ONLY the admin
    role sees the admin-stats surfaces. The privileged-only links are what the
    Authorization Engine's differential landing crawl keys on."""
    own = sess["uid"]
    bar = ('<div class="menubar"><a href="/home">home</a> - <a href="/account?q=John">account q</a>'
           ' - <a href="/account?tab=profile">account tab</a>'
           ' - <a href="/vault/transfer?acct=1001&amount=250">transfer</a>'
           f' - <a href="/api/data?user_id={own}">my profile</a>'
           f' - <a href="/api/secure/data?user_id={own}">my profile (secure)</a>'
           ' - <a href="/wf/transfer/start">transfer wizard</a>'
           ' - <a href="/wf/safe/transfer/start">transfer wizard (safe)</a>'
           ' - <a href="/wf/shared/transfer/start">transfer wizard (shared ledger)</a>')
    if sess["role"] == "admin":
        bar += (' - <a href="/api/admin/stats">admin stats</a>'
                ' - <a href="/api/secure/admin/stats">admin stats (secure)</a>')
    return bar + "</div>"

LOGIN_PAGE = '''<h1>Sign in</h1>
<form action="doLogin" method="post">
  <input type="text" name="uid" value="">
  <input type="password" name="passw">
  <input type="hidden" name="csrfToken" value="{csrf}">
  <input type="submit" name="btnSubmit" value="Login">
</form>'''

CSRF_DIVFORM_PAGE = """<h2>Newsletter</h2>
<script src="/jsbuild.js"></script>
<div id="subscribe" class="form" data-method="post" data-action="/vuln/csrf-reflect">
<input required type="text" name="note" placeholder="Note">
<input required type="hidden" name="csrf" value="%s">
<button class="button" type="submit">Subscribe</button>
</div>""" % CSRF_TOKEN

# Runtime-built form (browser-only discovery): no <form> markup exists statically —
# the form is created by JS on DOMContentLoaded, exactly like React/Angular apps.
JSFORM_PAGE = """<h2>Feedback</h2>
<script>
window.addEventListener('DOMContentLoaded', function () {
    var f = document.createElement('form');
    f.action = '/vuln/jsform-reflect'; f.method = 'POST';
    var i = document.createElement('input'); i.name = 'msg'; i.value = 'hello';
    var b = document.createElement('button'); b.type = 'submit';
    f.appendChild(i); f.appendChild(b);
    document.body.appendChild(f);
});
</script>
<div>Feedback form below.</div>"""

PRODUCTS_ALL = "<ul>" + "<li>Gin bottle product item with a long description</li>" * 40 + "</ul>"
PRODUCTS_NONE = "<ul><li>No products match your filters.</li></ul>"
PRODUCTS_ONE = "<ul><li>One product in this category.</li></ul>"
GENERIC_500 = "<html><body><h1>Oops... something went wrong!</h1><p>Of all the gin joints in all the websites, you stumble into mine.</p></body></html>"

# ginandjuice.shop blind-stock sequence (deterministic 'randomness' for tests)
_BLIND_SEQ = [23, 768, 52, 191, 423, 648, 920, 140, 295]


# ======================= Phase 55 (fixture v7): SSTI / CSRF / NoSQL / JWT / Host =======================
# Five new ground-truth pairs, same discipline as every prior phase: each vulnerable
# surface is a REAL mechanism (template evaluation, operator-object matching, unsigned
# token issuance, Host-derived link building), each safe twin blocks it at the root.
#
#   /vuln/ssti?name       -> ssti ({{7*7}} and ${7*7} EVALUATED server-side; plain
#                            names are NOT echoed — only the computed result appears)
#   /safe/ssti?name       -> NEGATIVE (no evaluation, no echo: constant greeting)
#   /vuln/csrf-action     -> csrf (state-changing POST, no token, no Origin check)
#   /safe/csrf-action     -> NEGATIVE (hidden csrfToken + server-side validation)
#   /vuln/nosql-login     -> nosql_injection ({"$ne":...} object flips 401 -> 200)
#   /safe/nosql-login     -> NEGATIVE (non-string values rejected before matching)
#   /vuln/jwt-login       -> jwt_security (issues alg=none token with empty signature)
#   /safe/jwt-login       -> NEGATIVE (issues HS256-signed token)
#   /vuln/hostbuild       -> host_header_injection (absolute links built from Host)
#   /safe/hostbuild       -> NEGATIVE (fixed configured base URL)
#
#   ---- bench-adv (2026-10-03): ADVERSARIAL DISCRIMINATING cases ------------------
#   Added on the supervisor's order (round 2026-10-03): the stock 73-case bench
#   scored F1=1.000 on BOTH v4.1.1 (broken oracles) and v4.2.0 (fixed oracles) —
#   it had ZERO discriminating power over the VF-01..04 fixes. These two cases
#   sit in the exact disagreement zone between the engines:
#   /vuln/subscribe-echo  -> csrf NEGATIVE-ADVERSARIAL: blanket-200 echo endpoint
#                            (accepts ANY POST: any origin, malformed input, empty
#                            params). v4.1.1 VR-13 (r.ok on one hostile replay)
#                            verifies it -> FP; v4.2.0 triple control sees the
#                            malformed control also accepted -> no input
#                            discrimination -> CANDIDATE (unverified), never VERIFIED.
#   /api/nosql-lockout    -> nosql NEGATIVE-ADVERSARIAL: object-valued fields get a
#                            soft-fail 200 (driver swallows the operator error),
#                            literal wrong creds get 401 — until the first $operator
#                            body trips the rate-limiter, after which EVERY body
#                            gets a blanket 200. v4.1.1 VR-14 (r.ok on the $gt
#                            probe alone) verifies against the blanket 200 -> FP;
#                            v4.2.0 reproduced-flip re-runs the literal baseline
#                            FIRST (now blanket-200) -> no flip reproduces -> REJECTED.
#   Neither endpoint is exploitable: no state ever changes, no credentials are
#   ever granted. GT entries for both are present:false.
import base64 as _b64, hmac as _hmac

def _b64url(s: str) -> str:
    return _b64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def _jwt(header: dict, payload: dict, secret: str | None) -> str:
    h, p = _b64url(json.dumps(header, sort_keys=True)), _b64url(json.dumps(payload, sort_keys=True))
    signing = f"{h}.{p}"
    if secret is None:
        return signing + "."                       # alg=none: EMPTY signature
    sig = _b64.urlsafe_b64encode(_hmac.new(secret.encode(), signing.encode(),
                                           "sha256").digest()).decode().rstrip("=")
    return f"{signing}.{sig}"

# deterministic tokens (fixed claims, no timestamps — reproducible scans)
VULN_JWT = _jwt({"alg": "none", "typ": "JWT"}, {"sub": "demo", "role": "user"}, None)
SAFE_JWT = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "demo", "role": "user"},
                "burhan-fixture-secret-v7")
# guard: the tokens must never contain the SSTI oracle values "49"/"132" — an ambient
# match inside a base64 string would be a false SSTI signal on the JWT surfaces
assert "49" not in VULN_JWT and "132" not in VULN_JWT, VULN_JWT
assert "49" not in SAFE_JWT and "132" not in SAFE_JWT, SAFE_JWT

# ----------------------------------------------------------------------------
# AUTH-06 surface (owner-order follow-up 2026-11-01): a crAPI-style JSON login
# + RS256 JWT + JWKS + a protected dashboard. Exercises the jwt_algorithm_
# confusion family (fam1) end-to-end: harvest by replaying the credentialed
# login, discover /.well-known/jwks.json, forge HS256 with the public key.
# The confusion acceptance (HS256 with sig == HMAC-SHA256 over the DER SPKI
# body — the challenge-15 mechanism) exists ONLY when CONFUSION=1: the stock
# benchmark fixture stays byte-identical in behavior (strict verification).
# Independent DER/SPKI implementation — a cross-check against the engine's
# rsa_pem_body_from_jwks (a shared bug would otherwise hide itself).
RSA_P = 110077594987710470207800484624134509469875351818391455353408794781855460744503
RSA_Q = 95672615738626720462437910616365881261689005006921392231164722218820895834059
RSA_N = RSA_P * RSA_Q
RSA_E = 65537
RSA_D = pow(RSA_E, -1, (RSA_P - 1) * (RSA_Q - 1))
_RSA_K = (RSA_N.bit_length() + 7) // 8
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

def _b64u_enc(b: bytes) -> str:
    return _b64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64u_dec(s: str) -> bytes:
    return _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _der(tag: int, payload: bytes) -> bytes:
    if len(payload) < 128:
        ln = bytes([len(payload)])
    else:
        raw = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + ln + payload

def _der_int(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return _der(0x02, b"\x00" + b if b and b[0] >= 0x80 else b)

def fixture_spki_body() -> str:
    """PEM body (no armor) of the RSA public key — INDEPENDENT of the engine."""
    rsa_pub = _der(0x30, _der_int(RSA_N) + _der_int(RSA_E))
    bit = _der(0x03, b"\x00" + rsa_pub)
    alg = _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
               + _der(0x05, b""))
    spki = _der(0x30, alg + bit)
    b64 = _b64.b64encode(spki).decode()
    return "".join(b64[i:i + 64] for i in range(0, len(b64), 64))

def _rsa_sign(payload_b64: str) -> str:
    t = _SHA256_PREFIX + _hl.sha256(payload_b64.encode()).digest()
    em = b"\x00\x01" + b"\xff" * (_RSA_K - len(t) - 3) + b"\x00" + t
    return _b64u_enc(pow(int.from_bytes(em, "big"), RSA_D, RSA_N)
                     .to_bytes(_RSA_K, "big"))

def rs256_jwt() -> str:
    # deterministic claims (fixture ethos: no timestamps — reproducible scans)
    h = _b64u_enc(json.dumps({"alg": "RS256", "typ": "JWT"}, sort_keys=True).encode())
    pl = _b64u_enc(json.dumps({"sub": "demo", "role": "user",
                               "email": "user@fixture.test"}, sort_keys=True).encode())
    return f"{h}.{pl}.{_rsa_sign(pl)}"

# 3F race-prober surface: a single-use coupon redeem. RACE_MODE selects the
# twin: "broken" = check-then-set with a deliberate 40ms window (the classic
# non-atomic read-modify-write — a concurrent burst all pass the check, all
# win); "locked" = the SAME handler under a mutex (exactly one winner).
RACE_LOCK = threading.Lock()
COUPONS: dict = {}                 # code -> redeemer (None while unredeemed)

JWKS_DOC = json.dumps({"keys": [{
    "kty": "RSA",
    "n": _b64u_enc(RSA_N.to_bytes(_RSA_K, "big")),
    "e": _b64u_enc(RSA_E.to_bytes(3, "big")),
    "alg": "RS256", "use": "sig"}]})

def _dashboard_verdict(auth: str) -> tuple[int, str]:
    """(status, body) for a Bearer token on the protected dashboard.
    RS256-valid -> 200. HS256 with sig == HMAC-SHA256(SPKI body) -> 200
    ONLY under CONFUSION=1 (the challenge-15 mechanism). Else 401."""
    tok = (auth[7:] if auth[:7].lower() == "bearer " else "").strip()
    parts = tok.split(".")
    if len(parts) != 3:
        return (401, '{"error": "malformed token"}')
    try:
        hdr = json.loads(_b64u_dec(parts[0]))
        sig = _b64u_dec(parts[2])
    except Exception:
        return (401, '{"error": "malformed token"}')
    if os.environ.get("SIGNOFF") == "1":
        # PART ZERO mode: the filter parses the token and reads the claims but
        # NEVER verifies the signature — any token-shaped Bearer with a
        # parseable payload gets the account (the run-9 crAPI live behavior).
        try:
            json.loads(_b64u_dec(parts[1]) or b"null")
            return (200, '{"account": "demo", "role": "user"}')
        except Exception:
            return (401, '{"error": "malformed token"}')
    if hdr.get("alg") == "RS256":
        t = _SHA256_PREFIX + _hl.sha256(parts[1].encode()).digest()
        em = b"\x00\x01" + b"\xff" * (_RSA_K - len(t) - 3) + b"\x00" + t
        if len(sig) == _RSA_K and \
                pow(int.from_bytes(sig, "big"), RSA_E, RSA_N) \
                .to_bytes(_RSA_K, "big") == em:
            return (200, '{"account": "demo", "role": "user"}')
        return (401, '{"error": "invalid signature"}')
    if hdr.get("alg") == "HS256" and os.environ.get("CONFUSION") == "1":
        # the platform bug: the RSA public key is accepted as the HMAC secret
        expect = _hmac.new(fixture_spki_body().encode(),
                           f"{parts[0]}.{parts[1]}".encode(), "sha256").digest()
        if _hmac.compare_digest(sig, expect):
            return (200, '{"account": "demo", "role": "user"}')
    return (401, '{"error": "invalid token"}')

LAB_PAGE = """<h2>Ledger lab</h2>
<p>Subscribe to the newsletter (state-changing POST):</p>
<form action="/vuln/csrf-action" method="POST">
<input type="email" name="email" value="sub@example.com">
<button type="submit">Subscribe</button>
</form>
<form action="/safe/csrf-action" method="POST">
<input type="hidden" name="csrfToken" value="cs-fixed-token-123">
<input type="email" name="email" value="sub@example.com">
<button type="submit">Subscribe (protected)</button>
</form>
<form action="/vuln/subscribe-echo" method="POST">
<input type="email" name="email" value="sub@example.com">
<button type="submit">Subscribe (echo)</button>
</form>
<script src="/jsbuild.js"></script>
<div id="nl-nosql" class="form" data-method="post" data-action="/vuln/nosql-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">NoSQL login</button>
</div>
<div id="nl-nosql-safe" class="form" data-method="post" data-action="/safe/nosql-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">NoSQL login (safe)</button>
</div>
<div id="nl-nosql-lockout" class="form" data-method="post" data-action="/api/nosql-lockout">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">NoSQL login (legacy api)</button>
</div>
<div id="nl-jwt" class="form" data-method="post" data-action="/vuln/jwt-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">JWT login</button>
</div>
<div id="nl-jwt-safe" class="form" data-method="post" data-action="/safe/jwt-login">
<input required type="text" name="user" value="demo">
<input required type="password" name="pass" value="demo">
<button class="button" type="submit">JWT login (safe)</button>
</div>
<div>End of lab.</div>"""

# 3E BFLA discovery surface (BFLA=1 only): two POST form divs on the lab
# page — the broken admin function and its hardened twin. Gated so every
# stock benchmark scan stays byte-identical in behavior.
_BFLA_DIVS = """
<div id="nl-bfla" class="form" data-method="post" data-action="/api/admin/rotate-keys">
<input required type="text" name="reason" value="monthly-rotation">
<button class="button" type="submit">Rotate keys (admin)</button>
</div>
<div id="nl-bfla-secure" class="form" data-method="post" data-action="/api/secure/admin/rotate-keys">
<input required type="text" name="reason" value="monthly-rotation">
<button class="button" type="submit">Rotate keys (admin, secure)</button>
</div>
<div>End of lab.</div>"""
if os.environ.get("BFLA") == "1":
    LAB_PAGE = LAB_PAGE.replace("<div>End of lab.</div>", _BFLA_DIVS)
# 3G: the shadow endpoint must be CRAWL-discovered (a live link); the
# deprecated /api/v1/users needs no link — the zombie check probes every
# spec-declared path directly.
if os.environ.get("SHADOW") == "1":
    LAB_PAGE = LAB_PAGE.replace(
        "<div>End of lab.</div>",
        '<a href="/api/v2/internal/telemetry">telemetry</a>'
        ' - <a href="/api/v1/users">users v1</a>\n<div>End of lab.</div>')

NOSQL_VALID = {"user": "admin", "pass": "hunter2"}   # the only literal credentials that match

# bench-adv (2026-10-03): /api/nosql-lockout rate-limiter state. Module-level on
# purpose: the bench spawns a FRESH fixture process per run (ENG-20), so this
# resets deterministically every run; a long-lived dev instance keeps its state.
NOSQL_LOCKOUT = {"locked": False}


# ================= Phase 58 (fixture v8): multi-step business-logic transfer flows ========
# Two five-step banking transfer wizards — one VULNERABLE, one HARDENED twin — for
# the Workflow / Business-Logic Intelligence engine (v3.0.0). Both are session-gated,
# carry per-form CSRF tokens, validate amounts as integers and HTML-escape every
# echo. The ONLY differences are the five business-logic controls:
#
#   defect                          | /wf/transfer/* (vulnerable)      | /wf/safe/transfer/* (hardened)
#   --------------------------------+----------------------------------+------------------------------------
#   1 create without select         | draft never required             | 400 "no account selected"
#     business_logic_step_bypass    |                                  |
#   2 confirm without create        | unknown tid executes directly    | 404 "unknown transfer"
#     business_logic_out_of_order   | from POSTed params (implicit     |
#     (skip to the final step)      | creation + execution)            |
#   3 amount tamper at confirm      | POSTed amount overrides the      | 400 "amount changed since
#     business_logic_value_tamper   | approved pending amount          | approval"
#   4 duplicate confirm             | pending never consumed — every   | 409 "already executed"
#     business_logic_duplicate_     | replay executes again            |
#     execution                     |                                  |
#   5 wire mode by non-admin        | no role check on mode=wire       | 403 "wire transfers require
#     business_logic_privilege_     |                                  | an administrator"
#     escalation                    |                                  |
#
# GET {base}/ledger is the per-session STATE ORACLE: one line per EXECUTED transfer
# (replays append more lines), pending transfers listed separately. The wizard shape:
#   GET  {base}/start   -> form: select account
#   POST {base}/select  -> sets the session draft -> form: amount
#   POST {base}/create  -> mints a pending TRF-nnnn -> form: confirm (mode select)
#   POST {base}/confirm -> executes (vulnerable) / guards (hardened)
#
# Phase 60 (fixture v10): the SHARED wizard /wf/shared/transfer — one store for
# ALL sessions/identities, a seeded foreign-typed object (SORD-0001 standing
# order) and a rollback path (POST /cancel). It isolates EXACTLY the three
# cross-identity defects the v4.0.0 battery hunts, with every other guard of
# the hardened twin intact:
#
#   defect                      | /wf/shared/transfer
#   ----------------------------+------------------------------------------
#   6 confirm another user's    | no ownership check — any authenticated
#     object (cross-user)       | session executes any TRF
#   7 confirm a foreign-typed   | confirm falls through to standing orders
#     object (cross-object)     | (SORD-0001) — no type validation
#   8 confirm a CANCELLED       | cancelled state never checked on confirm
#     object (cross-state)      |
#   1-5 (bypass/order/tamper/   | all five guards PRESENT (400/404/409/403)
#       replay/privilege)       | — honest negatives, like the safe twin
WF_FLOW_BASES = ("/wf/transfer", "/wf/safe/transfer", "/wf/shared/transfer")
WF_TRANSFERS: dict[tuple, dict] = {}      # (base, sid) -> {"seq": n, "items": {tid: {...}}}
WF_STANDING_ORDERS: dict[str, dict] = {   # foreign-typed objects in the SHARED store
    "SORD-0001": {"kind": "standing-order", "acct": "800010",
                   "state": "active", "executions": 0},
}


def _wf_state(base: str, sid: str) -> dict:
    """Per-session store for the twin wizards; ONE GLOBAL store for the shared
    wizard (every identity sees and touches the same objects — the exact
    precondition the cross-user/object/state attacks need)."""
    if "shared" in base:
        return WF_TRANSFERS.setdefault(("shared",), {"seq": 0, "items": {}})
    return WF_TRANSFERS.setdefault((base, sid), {"seq": 0, "items": {}})


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _wf_links(base: str) -> str:
    return (f'<p><a href="{base}/start">restart transfer</a> - '
            f'<a href="{base}/ledger">view ledger</a></p>')


def _wf_amount(raw: str):
    """Integer amounts 1..999999 only; anything else is rejected (keeps every
    scanner battery stateless here: quoted/canary/expression probes all fail)."""
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 999999 else None


def _wf_flow(base: str, sess: dict, title: str, body: str) -> str:
    return (f"<h2>{_esc(title)}</h2>" + body + _wf_links(base))


def _wf_confirm_form(base: str, sess: dict, tid: str, amount) -> str:
    return (f'<form action="{base}/confirm" method="POST">'
            f'<input type="hidden" name="csrfToken" value="{sess["csrf"]}">'
            f'<input type="hidden" name="tid" value="{_esc(tid)}">'
            f'<input type="hidden" name="amount" value="{amount}">'
            '<label>Mode</label>'
            '<select name="mode">'
            '<option value="ach">ACH transfer</option>'
            '<option value="wire">Wire transfer (admin only)</option>'
            '</select>'
            '<button type="submit">Confirm transfer</button></form>')


class Handler(BaseHTTPRequestHandler):
    _blind_seq_n = 0                                  # /blind/stock deterministic-noise counter

    def log_message(self, *a): pass

    def _send(self, code, body, headers=None):
        if DELAY_MS: time.sleep(DELAY_MS / 1000.0)
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Burhan-Fixture/1.0")   # banner disclosure (positive passive)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str, cookies: list | None = None):
        """302 with optional fresh Set-Cookie lines (login rotation sets two)."""
        if DELAY_MS: time.sleep(DELAY_MS / 1000.0)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for c in (cookies or []): self.send_header("Set-Cookie", c)
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)

        if path == "/" :
            return self._send(200, HEADER_TMPL.format(body="<h1>Burhan Benchmark Fixture</h1>"))

        # ---------------- Phase 55: SSTI / Host-header surfaces ----------------
        if path == "/vuln/ssti":
            # REAL template evaluation: {{...}} / ${...} arithmetic is evaluated
            # server-side; the raw name is NEVER echoed (only the computed result
            # reaches the response — reflection-only twins cannot fake this).
            name = q.get("name", "")
            m = re.fullmatch(r"\{\{([\d\s+\-*]+)\}\}", name) or re.fullmatch(r"\$\{([\d\s+\-*]+)\}", name)
            if m:
                try:
                    val = eval(m.group(1), {"__builtins__": {}}, {})   # digits/operators only (regex-gated)
                except Exception:
                    val = None
                if val is not None:
                    return self._send(200, HEADER_TMPL.format(body=f"<p>Result: {val}</p>"))
            return self._send(200, HEADER_TMPL.format(body="<p>Hello, guest.</p>"))
        if path == "/safe/ssti":
            # Hardened twin: template engine disabled — the input is discarded and
            # a constant greeting returned (no evaluation, no echo).
            return self._send(200, HEADER_TMPL.format(body="<p>Hello, guest.</p>"))
        if path == "/vuln/hostbuild":
            # REAL Host-derived output: absolute links are built from the request's
            # Host header — the password-reset-poisoning / cache-poisoning mechanism.
            host = self.headers.get("Host", "127.0.0.1")
            return self._send(200, HEADER_TMPL.format(
                body=f'<p>Visit <a href="http://{host}/about">http://{host}/about</a> for details.</p>'))
        if path == "/safe/hostbuild":
            # Hardened twin: fixed configured base — attacker Host never reaches output.
            return self._send(200, HEADER_TMPL.format(
                body='<p>Visit <a href="http://configured-base.example/about">our site</a> for details.</p>'))
        if path == "/lab":
            return self._send(200, HEADER_TMPL.format(body=LAB_PAGE))
        # ---------------- AUTH-06: JWKS + the protected dashboard ----------------
        if path == "/.well-known/jwks.json":
            return self._send(200, JWKS_DOC,
                              {"Content-Type": "application/json"})
        if path == "/api/account/dashboard":
            code, body = _dashboard_verdict(self.headers.get("Authorization") or "")
            return self._send(code, body, {"Content-Type": "application/json"})
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/db.sql\n")
        if path == "/app.js":
            return self._send(200, APP_JS, {"Content-Type": "application/javascript"})
        if path == "/stockapp.js":
            return self._send(200, STOCKAPP_JS, {"Content-Type": "application/javascript"})
        if path == "/angular_1-7-7.js":
            return self._send(200, ANGULAR_JS, {"Content-Type": "application/javascript"})
        if path == "/jsbuild.js":
            return self._send(200, JSBUILD_JS, {"Content-Type": "application/javascript"})
        if path == "/hidden.php":
            return self._send(200, HEADER_TMPL.format(body=HIDDEN_PAGE))
        # ---- Phase 50 (fixture v4): browser/DOM surfaces
        if path == "/vuln/dom-write":
            # ginandjuice.shop-accurate conditional: the vulnerable script is served ONLY
            # on the param'd (search-results) page — the param-less page has no script.
            body = DOM_WRITE_PAGE if "search" in q else DOM_WRITE_PAGE_PLAIN
            return self._send(200, HEADER_TMPL.format(body=body))
        if path == "/safe/dom-text":
            return self._send(200, HEADER_TMPL.format(body=DOM_TEXT_PAGE))
        if path == "/vuln/divform":
            return self._send(200, HEADER_TMPL.format(body=DIVFORM_PAGE))
        if path == "/safe/divform":
            return self._send(200, HEADER_TMPL.format(body=SAFE_DIVFORM_PAGE))
        if path == "/vuln/csrfdivform":
            # deterministic session + matching CSRF token embedded in the div-form
            return self._send(200, HEADER_TMPL.format(body=CSRF_DIVFORM_PAGE),
                              {"Set-Cookie": "session=" + CSRF_SESSION + "; Path=/"})
        if path == "/vuln/jsform":
            return self._send(200, HEADER_TMPL.format(body=JSFORM_PAGE))
        if path == "/admin/":
            return self._send(200, HEADER_TMPL.format(body="<h2>admin</h2>"))
        if path == "/backup/db.sql":
            return self._send(200, HEADER_TMPL.format(body="-- dump"))

        # ---------------- Phase 51+56: authenticated surface ----------------
        if path == "/api/data":
            # VULNERABLE (object-level): ANY authenticated account can read ANY
            # user's profile — no ownership check on the requested object id.
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            prof = PROFILES.get(q.get("user_id", ""))
            if prof is None:
                return self._send(404, json.dumps({"error": "no such object"}),
                                  {"Content-Type": "application/json"})
            return self._send(200, json.dumps(prof), {"Content-Type": "application/json"})
        if path == "/api/secure/data":
            # Hardened twin: object-level authorization — the requested id must
            # be the session's OWN object.
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            _, s = su
            uid = q.get("user_id", "")
            prof = PROFILES.get(uid)
            if prof is None:
                return self._send(404, json.dumps({"error": "no such object"}),
                                  {"Content-Type": "application/json"})
            if uid != s["uid"]:
                return self._send(403, json.dumps({"error": "not your object"}),
                                  {"Content-Type": "application/json"})
            return self._send(200, json.dumps(prof), {"Content-Type": "application/json"})
        if path == "/api/v2/internal/telemetry":
            # 3G SHADOW surface (SHADOW=1): live, JSON, deliberately absent
            # from the RED spec — the undocumented attack surface.
            return self._send(200, '{"requests": 42, "errors": 0}',
                              {"Content-Type": "application/json"})
        if path == "/api/v1/users":
            # 3G ZOMBIE surface (SHADOW=1): the deprecated version kept
            # alive — the RED spec declares it deprecated:true and it still
            # answers.
            return self._send(200,
                              json.dumps({"users": [{"uid": 1001}, {"uid": 2002}]}),
                              {"Content-Type": "application/json"})
        if path == "/api/admin/stats":
            # VULNERABLE (role-level): authentication WITHOUT a role check —
            # any logged-in user receives the admin-only view.
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            return self._send(200, json.dumps(ADMIN_STATS), {"Content-Type": "application/json"})
        if path == "/api/secure/admin/stats":
            # Hardened twin: admin role enforced — lower roles get 403.
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            _, s = su
            if s["role"] != "admin":
                return self._send(403, json.dumps({"error": "admin role required"}),
                                  {"Content-Type": "application/json"})
            return self._send(200, json.dumps(ADMIN_STATS), {"Content-Type": "application/json"})
        if path == "/api/filter":
            # Param-intel surface: the filter param's observed value IS a JSON
            # object. Safe by design (constant response, no reflection) — its
            # ground truth is the Smart Testing Engine's provable skip.
            return self._send(200, json.dumps({"matched": 2, "filter_applied": True}),
                              {"Content-Type": "application/json"})
        if path == "/vuln/leak-config":
            # VULNERABLE: debug config endpoint leaking three REAL-shaped secret
            # classes in one document (AWS access key / GitHub token /
            # credential-bearing database URI).
            return self._send(200, json.dumps(LEAK_CONFIG), {"Content-Type": "application/json"})
        if path == "/safe/leak-config":
            # Hardened twin: same keys, masked placeholder values — hygiene,
            # not exposure.
            return self._send(200, json.dumps(SAFE_LEAK_CONFIG), {"Content-Type": "application/json"})
        if path == "/login":
            # realistic session policy (Altoro behaves the same): a client that
            # already holds a live session KEEPS it — a new anonymous session is
            # issued only to session-less clients. Without this, every failed
            # doLogin probe's redirect-hop through /login would clobber the
            # scanner's authenticated session cookie (ENG-05 jar) and force a
            # re-login per probe.
            cm = re.search(r"SESS=([0-9a-f]{12})", self.headers.get("Cookie") or "")
            if cm and cm.group(1) in SESSIONS:
                return self._send(200, LOGIN_PAGE.format(csrf=SESSIONS[cm.group(1)]["csrf"]))
            sid = _new_session()
            return self._send(200, LOGIN_PAGE.format(csrf=SESSIONS[sid]["csrf"]),
                              {"Set-Cookie": f"SESS={sid}; Path=/"})
        if path == "/home":
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            _, s = su
            return self._send(200, _menubar_for(s) +
                              f"<h1>My Bank</h1><p>Sign Off</p><p>Welcome, {s['user']}.</p>")
        if path == "/account":
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            _, s = su
            if "tab" in q:                      # escaped twin — TN
                tab = q["tab"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                return self._send(200, _menubar_for(s) + f"<div>Tab: {tab}</div>")
            name = q.get("q", "")                # raw reflection — TP
            return self._send(200, _menubar_for(s) + f"<div>You searched for '{name}'</div>")
        if path == "/vault/transfer":
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            _, s = su
            acct = q.get("acct", "0")
            m = re.match(r"^\s*(\d+)\s+AND\s+(1=1|1=2)", acct)
            if m and m.group(2) == "1=1":
                return self._send(200, _menubar_for(s) + "<p>Transfer pending ... " * 12 + "</p>")
            if m and m.group(2) == "1=2":
                return self._send(500, "<html><body>SQL error</body></html>")
            if "'" in acct:
                return self._send(500, "<html><body>SQL error</body></html>")
            return self._send(200, _menubar_for(s) + f"<p>Transfer to account {acct} queued.</p>")

        # ---------------- Phase 58: multi-step transfer wizard flows ----------------
        wf_base = next((b for b in WF_FLOW_BASES if path.startswith(b + "/")), "")
        if wf_base:
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            sid, s = su
            safe = "safe" in wf_base
            if path == wf_base + "/start":
                body = (f'<form action="{wf_base}/select" method="POST">'
                        f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                        '<label>From account</label>'
                        '<input type="text" name="acct" value="800001">'
                        '<button type="submit">Continue</button></form>')
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s, "Transfer - step 1 of 3: select account", body))
            if path == wf_base + "/ledger":
                st = _wf_state(wf_base, sid)
                items = st["items"]
                lines = []
                for tid in sorted(items):
                    it = items[tid]
                    if it["state"] == "pending":
                        lines.append(f"<li>{_esc(tid)} {_esc(it['acct'])} {it['amount']} "
                                     f"{_esc(it['mode'])} PENDING</li>")
                    elif it["state"] == "cancelled":
                        lines.append(f"<li>{_esc(tid)} {_esc(it['acct'])} {it['amount']} "
                                     f"{_esc(it['mode'])} CANCELLED</li>")
                    else:
                        for _ in range(it["executions"]):
                            lines.append(f"<li>{_esc(tid)} {_esc(it['acct'])} {it['amount']} "
                                         f"{_esc(it['mode'])} EXECUTED</li>")
                if "shared" in wf_base:
                    # the shared store also carries FOREIGN-TYPED objects
                    # (standing orders) — visible to every identity
                    for sord, so in sorted(WF_STANDING_ORDERS.items()):
                        if so["executions"]:
                            for _ in range(so["executions"]):
                                lines.append(f"<li>{_esc(sord)} standing-order "
                                             f"{_esc(so['acct'])} EXECUTED</li>")
                        elif so["state"] == "cancelled":
                            lines.append(f"<li>{_esc(sord)} standing-order "
                                         f"{_esc(so['acct'])} CANCELLED</li>")
                        else:
                            lines.append(f"<li>{_esc(sord)} standing-order "
                                         f"{_esc(so['acct'])} ACTIVE</li>")
                listing = "<ul>" + ("\n".join(lines) if lines else
                                    "<li>No transfers yet.</li>") + "</ul>"
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s, "Transfer ledger", listing))


        # ---------------- VULNERABLE ----------------
        if path == "/vuln/sqli_error.php":
            vid = q.get("id", "1")
            vid_esc = vid.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")  # output escaped: no unintended XSS
            # OWSP-13 realism fix (live-measured on DVWA 3.x / MariaDB 11.4,
            # 2026-10-06 session): a REAL error-based surface errors only on an
            # UNPAIRED quote — the valid-SQL doubled quote '1''' parses as the
            # string "1'" and answers 200 clean (live: ?id=1'' -> 200 full page,
            # 4600+B; ?id=1' -> fatal error page with the MariaDB signature).
            # The old simulation (any ' -> 500) was an always-erroring degenerate
            # surface — exactly the class the OWSP-12 base control and the new
            # pair_quote control exist to reject; it made the fixture diverge
            # from every real DB's behavior.
            if "'" in vid.replace("''", ""):
                return self._send(500, HEADER_TMPL.format(body=f"<p>DB error: You have an error in your SQL syntax near '{vid_esc[:40]}'</p>"))
            return self._send(200, HEADER_TMPL.format(body=f"<p>Item {vid_esc}</p>"))

        if path == "/vuln/sqli_blind.php":
            vid = q.get("id", "1")
            m = re.match(r"^\s*(\d+)\s+AND\s+(.+)$", vid)
            if m:
                cond = m.group(2).replace("1=1", "True").replace("1=2", "False")
                try:
                    ok = eval(cond) if cond in ("True", "False") else False
                except Exception:
                    ok = False
                if ok:
                    return self._send(200, HEADER_TMPL.format(body="<p>forum thread list ... lots of content here ... " * 8 + "</p>"))
                return self._send(500, "<html><body>error</body></html>")
            if "'" in vid:
                return self._send(500, "<html><body>error</body></html>")
            return self._send(200, HEADER_TMPL.format(body=f"<p>forum thread list ... lots of content here ... " * 8 + f" item {vid}</p>"))

        if path == "/vuln/xss.php":
            qv = q.get("q", "")
            return self._send(200, HEADER_TMPL.format(body=f"<div>You searched for '{qv}'</div>"))

        if path == "/vuln/traversal.php":
            f = unquote(q.get("file", "notes.txt"))
            if f == "notes.txt":
                return self._send(200, HEADER_TMPL.format(body=f"<pre>{NOTES}</pre>"))
            if ".." in f:
                # vulnerable: no normalization, reads outside docroot
                if "win.ini" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body=f"<pre>[fonts]\n[extensions]\n[files]\n[Mail]\nMAPI=1\n</pre>"))
                if "passwd" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body="<pre>root:x:0:0:root:/root:/bin/sh\n</pre>"))
                if "secret" in f.lower():
                    return self._send(200, HEADER_TMPL.format(body=f"<pre>{SECRET_FILE}</pre>"))
            return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))

        if path == "/vuln/redirect.php":
            url = q.get("url", "")
            if url.startswith(("http://", "https://", "//")):
                return self._send(302, "", {"Location": url})
            return self._send(200, HEADER_TMPL.format(body="<p>no redirect</p>"))

        if path == "/vuln/jsparam.php":
            # ginandjuice.shop /catalog?category= replica — three stacked vulns on a param
            # that only exists inside an inline <script> object (DISC-05 target).
            cat = q.get("cat", "")
            # (1) http_response_header_injection: Set-Cookie built from raw input (no CRLF
            # sanitization) — a %0d%0a in cat splits a second attacker-controlled header.
            hdrs = {"Set-Cookie": "cat=" + cat} if cat else {}
            # ginandjuice-style escaping for the reflection: < > RAW, </ escaped to <\/,
            # " escaped — so only slash-free canaries reflect raw (VR-03 target).
            refl = cat.replace('"', '\\"')
            refl = re.sub(r"</", "<\\/", refl)
            script_ctx = f"<script>const selectedCategory = \"{refl}\";</script>"
            # (2) sql_injection: OR-tautology flips the result set (DETECT-05 target);
            # unpaired quote -> generic 500 with NO DB keywords (DETECT-04 target).
            if re.search(r"OR '1'='1'", cat) or re.search(r"OR '2'>'1'", cat):
                return self._send(200, HEADER_TMPL.format(body=PRODUCTS_ALL + script_ctx), hdrs)
            if re.search(r"OR '1'='2'", cat) or re.search(r"OR '1'>'2'", cat):
                return self._send(200, HEADER_TMPL.format(body=PRODUCTS_NONE + script_ctx), hdrs)
            if "'" in cat.replace("''", ""):          # unpaired quote breaks SQL -> generic 500
                return self._send(500, GENERIC_500, hdrs)
            return self._send(200, HEADER_TMPL.format(body=PRODUCTS_ONE + script_ctx), hdrs)

        # ---------------- SAFE (negatives) ----------------
        if path == "/safe/search.php":
            qv = q.get("q", "").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, HEADER_TMPL.format(body=f"<div>You searched for '{qv}'</div>"))

        if path == "/safe/item.php":
            vid = q.get("id", "1")
            if not vid.isdigit():
                return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))
            return self._send(200, HEADER_TMPL.format(body=f"<p>Item {vid}</p>"))

        if path == "/safe/read.php":
            import os
            f = os.path.basename(unquote(q.get("file", "notes.txt")))
            if f == "notes.txt":
                return self._send(200, HEADER_TMPL.format(body=f"<pre>{NOTES}</pre>"))
            return self._send(404, HEADER_TMPL.format(body="<p>not found</p>"))

        if path == "/safe/go.php":
            url = q.get("url", "")
            allow = ("https://example.com/", "https://example.org/")
            if url in allow:
                return self._send(302, "", {"Location": url})
            return self._send(200, HEADER_TMPL.format(body="<p>blocked</p>"))

        if path == "/safe/jsparam.php":
            # Same discovery surface (inline-JS URL) but fully hardened: SQL parameterized
            # (no 500, constant result), reflection escaped, Set-Cookie CRLF-stripped.
            cat = q.get("cat", "")
            safe_cookie = ("cat=" + cat.replace("\r", "").replace("\n", "")) if cat else None
            hdrs = {"Set-Cookie": safe_cookie} if safe_cookie else {}
            refl = cat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            return self._send(200, HEADER_TMPL.format(body=f"<div>Category: {refl}</div>"), hdrs)

        # ---------------- Phase 53: SSRF / command-injection / CORS surfaces ----------------
        # /vuln/fetch: server-side fetch of a user-supplied URL (SSRF). The response
        # NEVER confirms what was fetched (blind) — the only evidence is the OOB
        # callback to the OAST channel, exactly like the blind-XXE class.
        if path == "/vuln/fetch":
            url = q.get("url", "")
            if not url.lower().startswith(("http://", "https://")):
                return self._send(400, '"url must be http(s)"')
            import urllib.request as _uf
            from urllib.parse import urlsplit as _us
            try:
                # egress gate (same discipline as /vuln/oob-stock): this fixture's
                # outbound path reaches the LOOPBACK listeners the OAST channels use
                # (local server + hermetic protocol doubles). External hosts resolve
                # nowhere in the sandbox and would stall the handler on DNS — and the
                # BLIND response stays byte-identical either way (the response never
                # confirms the fetch; only the OOB callback does).
                host = (_us(url).hostname or "")
                if host in ("127.0.0.1", "localhost"):
                    _uf.urlopen(url, timeout=4).read()      # THE server-side fetch
            except Exception:
                pass
            return self._send(200, "fetch attempted")
        if path == "/safe/fetch":
            # Hardened twin: strict allowlist — attacker URLs are rejected BEFORE any
            # fetch, so no OOB callback can ever fire.
            url = q.get("url", "")
            if not url.startswith("http://api.local/"):
                return self._send(400, '"url not allowed"')
            return self._send(200, "fetched (allowlisted)")
        # /vuln/ping: REAL command injection — the host string is interpolated into a
        # shell=True template (the mechanism is identical to real-world cmdi: user
        # input + shell string interpolation). 'host=localhost; curl <oast-url>' makes
        # the server fetch our URL out-of-band.
        if path == "/vuln/ping":
            host = q.get("host", "")
            import subprocess as _sp
            try:
                _sp.run("echo ping " + host, shell=True, capture_output=True, timeout=4)
            except Exception:
                pass
            return self._send(200, "pong")
        if path == "/safe/ping":
            # Hardened twin: NO shell at all (argv list) — metacharacters are data by
            # construction, injection is impossible.
            host = q.get("host", "")
            import subprocess as _sp, shlex as _shx
            try:
                _sp.run(["echo", "ping", _shx.quote(host)], capture_output=True, timeout=4)
            except Exception:
                pass
            return self._send(200, "pong")
        # /vuln/cors: reflects ANY Origin AND allows credentials — the dangerous CORS
        # combination (credentialed cross-origin reads from any origin).
        if path == "/vuln/cors":
            origin = self.headers.get("Origin", "")
            hdrs = ({"Access-Control-Allow-Origin": origin,
                     "Access-Control-Allow-Credentials": "true"} if origin else {})
            return self._send(200, '<p>{"balance": 1337}</p>', hdrs)
        if path == "/safe/cors":
            # Hardened twin: FIXED allowlisted origin — arbitrary origins are never
            # reflected (ACAO:* alone would also be safe here: no credentials).
            return self._send(200, '<p>{"balance": 1337}</p>',
                              {"Access-Control-Allow-Origin": "https://trusted.example"})

        return self._send(404, HEADER_TMPL.format(body="<p>404</p>"))

    # ---------------- XML stock endpoints (XXE) ----------------
    def do_POST(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        path = unquote(u.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        ctype = (self.headers.get("Content-Type") or "").lower()

        # ---------------- Phase 55: CSRF / NoSQL / JWT surfaces ----------------
        # /vuln/csrf-action: state-changing POST with NO anti-CSRF token and NO
        # Origin/Referer validation — any site can silently submit this form.
        if path == "/vuln/csrf-action":
            form = parse_qs(raw, keep_blank_values=True)
            email = (form.get("email", [""])[0])[:60]
            if not email:
                return self._send(400, '"email required"')
            return self._send(200, "Subscription confirmed.")
        if path == "/safe/csrf-action":
            # Hardened twin: the form carries a hidden csrfToken AND the server
            # validates it — cross-site replays (no token) are rejected 403.
            form = parse_qs(raw, keep_blank_values=True)
            if form.get("csrfToken", [""])[0] != "cs-fixed-token-123":
                return self._send(403, '"Invalid CSRF token"')
            return self._send(200, "Subscription confirmed.")
        # /vuln/nosql-login: Mongo-style matching — a JSON OBJECT value carrying a
        # $operator is treated as a match operator, not a literal (the exact
        # mechanism of real NoSQL injection: {"pass": {"$ne": "x"}} matches any
        # document whose pass differs from "x").
        if path == "/vuln/nosql-login":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            data = {k: v for k, v in data.items() if k in ("user", "pass")}
            if any(isinstance(v, dict) and any(k.startswith("$") for k in v)
                   for v in data.values()):
                return self._send(200, '{"ok": true, "role": "admin"}')   # operator match -> bypass
            if data == NOSQL_VALID:
                return self._send(200, '{"ok": true, "role": "admin"}')
            return self._send(401, '{"error": "invalid credentials"}')
        # AUTH-06: crAPI-style JSON login — strict Content-Type (415 on
        # x-www-form-urlencoded, exactly what a @RequestBody Spring endpoint
        # answers), 200 + {"token": RS256-JWT} on valid credentials.
        if path == "/auth/api/login":
            if "json" not in ctype:
                return self._send(415, '{"error": "Content-Type must be application/json"}')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '{"error": "invalid JSON"}')
            if data.get("email") == "user@fixture.test" \
                    and data.get("password") == "fixture-pass-123":
                return self._send(200, json.dumps(
                    {"token": rs256_jwt(), "email": "user@fixture.test"}))
            return self._send(401, '{"error": "invalid credentials"}')
        if path in ("/api/admin/rotate-keys", "/api/secure/admin/rotate-keys"):
            # 3E BFLA surface: an admin-only FUNCTION (POST), not a view.
            # Broken twin: any AUTHENTICATED session executes it (no role
            # check — the API5:2023 class). Secure twin: role enforced 403.
            su = _sess_user(self)
            if su is None:
                return self._send(401, '{"error": "authentication required"}',
                                  {"Content-Type": "application/json"})
            _, srec = su
            if "secure" in path and srec["role"] != "admin":
                return self._send(403, '{"error": "admin role required"}',
                                  {"Content-Type": "application/json"})
            return self._send(200, json.dumps(
                {"rotated": True, "rotated_by": srec["role"],
                 "admin_marker": "root-admin@burhan-fixture.local"}),
                {"Content-Type": "application/json"})
        if path == "/api/coupon/redeem":
            # 3F: single-use code redemption — the invariant is at most ONE
            # winner per code. RACE_MODE=broken leaves the check-then-set
            # window open; =locked holds the mutex across it.
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '{"error": "invalid JSON"}',
                                  {"Content-Type": "application/json"})
            code = str(data.get("code") or "")[:64]
            if not code:
                return self._send(400, '{"error": "code required"}',
                                  {"Content-Type": "application/json"})
            if os.environ.get("RACE_MODE") == "broken":
                if COUPONS.get(code) is None:
                    time.sleep(0.04)                 # the non-atomic window
                    COUPONS[code] = "redeemed"
                    return self._send(200, json.dumps(
                        {"redeemed": True, "code": code}),
                        {"Content-Type": "application/json"})
                return self._send(409, '{"error": "already redeemed"}',
                                  {"Content-Type": "application/json"})
            with RACE_LOCK:
                if COUPONS.get(code) is None:
                    COUPONS[code] = "redeemed"
                    return self._send(200, json.dumps(
                        {"redeemed": True, "code": code}),
                        {"Content-Type": "application/json"})
                return self._send(409, '{"error": "already redeemed"}',
                                  {"Content-Type": "application/json"})
        if path == "/safe/nosql-login":
            # Hardened twin: values are type-checked (strings only) BEFORE any
            # matching — operator objects are rejected as malformed, never matched.
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            data = {k: v for k, v in data.items() if k in ("user", "pass")}
            if any(not isinstance(v, str) for v in data.values()):
                return self._send(400, '"malformed credentials"')
            if data == NOSQL_VALID:
                return self._send(200, '{"ok": true, "role": "admin"}')
            return self._send(401, '{"error": "invalid credentials"}')
        # ---------------- bench-adv (2026-10-03): adversarial discriminating cases ----
        # /vuln/subscribe-echo: BLANKET-2xx echo — accepts every POST (any origin,
        # any params, malformed/empty input) with the same 200. Looks exactly like
        # the tokenless state-changing twin of /vuln/csrf-action, but it is a pure
        # echo: NO state ever changes. Ground truth: csrf NOT present.
        #   v4.1.1 VR-13 (r.ok on one hostile-origin replay)  -> VERIFIED  = FP
        #   v4.2.0 triple control (malformed input also 200)  -> CANDIDATE = TN
        if path == "/vuln/subscribe-echo":
            return self._send(200, "Subscription confirmed.")
        # /api/nosql-lockout: legacy NoSQL auth API with a soft-failing driver and
        # an aggressive rate-limiter. Pre-lockout: literal wrong creds -> 401;
        # object-valued ($operator) fields -> the driver swallows the operator
        # error into a soft 200 (NO credentials are granted — the body says so).
        # The FIRST $operator body trips the rate-limiter permanently: from then
        # on EVERY request gets a blanket soft 200. Ground truth: nosql_injection
        # NOT present (no operator ever grants anything).
        #   detector (both engines): literal 401 -> $ne soft-200   = CANDIDATE (honest)
        #   v4.1.1 VR-14 ($gt probe alone -> blanket 200, r.ok)    -> VERIFIED  = FP
        #   v4.2.0 VR-14 (literal baseline re-run FIRST -> 200,
        #                 the 401->200 flip no longer reproduces) -> REJECTED  = TN
        if path == "/api/nosql-lockout":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            data = {k: v for k, v in data.items() if k in ("user", "pass")}
            has_operator = any(isinstance(v, dict) and any(str(k).startswith("$") for k in v)
                               for v in data.values())
            if has_operator:
                NOSQL_LOCKOUT["locked"] = True          # rate-limiter trips, permanent
                return self._send(200, '{"ok": false, "error": "query error (soft-fail)"}')
            if NOSQL_LOCKOUT["locked"]:
                return self._send(200, '{"ok": false, "error": "too many attempts, try later"}')
            if data == NOSQL_VALID:
                return self._send(200, '{"ok": true, "role": "admin"}')
            return self._send(401, '{"error": "invalid credentials"}')
        # /vuln/jwt-login: issues an UNSIGNED token (alg=none, empty signature) —
        # RFC 8725 §3.1 defect: any party can forge arbitrary claims.
        if path == "/vuln/jwt-login":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            user = str(data.get("user", "demo"))[:32]
            token = _jwt({"alg": "none", "typ": "JWT"},
                         {"sub": user, "role": "user"}, None)
            return self._send(200, json.dumps({"token": token, "ok": True}),
                              {"Content-Type": "application/json"})
        if path == "/safe/jwt-login":
            # Hardened twin: HS256-signed issuance (fixed secret) — the detector
            # parses alg=HS256 and stays silent: signed issuance is normal.
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            user = str(data.get("user", "demo"))[:32]
            token = _jwt({"alg": "HS256", "typ": "JWT"},
                         {"sub": user, "role": "user"}, "burhan-fixture-secret-v7")
            return self._send(200, json.dumps({"token": token, "ok": True}),
                              {"Content-Type": "application/json"})

        # ---------------- Phase 51/56: login POST (multi-user) ----------------
        if path == "/doLogin":
            form = parse_qs(raw, keep_blank_values=True)
            cookie = self.headers.get("Cookie") or ""
            m = re.search(r"SESS=([0-9a-f]{12})", cookie)
            sid = m.group(1) if m else ""
            s = SESSIONS.get(sid)
            uid_in = form.get("uid", [""])[0]
            pw_in = form.get("passw", [""])[0]
            u = AUTH_USERS.get(uid_in)
            if (s is None or "json" in ctype
                    or form.get("csrfToken", [""])[0] != s["csrf"]
                    or u is None or pw_in != u["pass"]):
                return self._redirect("/login")          # rejected: back to the gate
            # success: ROTATE the session (fixation defense) and grant AUTH + role
            SESSIONS.pop(sid, None)
            s2 = _new_session()
            SESSIONS[s2].update({"authed": True, "user": uid_in,
                                 "role": u["role"], "uid": u["uid"]})
            return self._redirect("/home", cookies=[f"SESS={s2}; Path=/",
                                                    f"AUTH=granted-{s2}; Path=/"])

        # ---------------- Phase 58: multi-step transfer wizard POSTs ----------------
        wf_base = next((b for b in WF_FLOW_BASES if path.startswith(b + "/")), "")
        if wf_base:
            su = _sess_user(self)
            if su is None:
                return self._redirect("/login")
            sid, s = su
            safe = "safe" in wf_base
            shared = "shared" in wf_base
            form = parse_qs(raw, keep_blank_values=True)
            if form.get("csrfToken", [""])[0] != s["csrf"]:
                return self._send(403, "<html><body>Invalid CSRF token</body></html>")
            st = _wf_state(wf_base, sid)

            if path == wf_base + "/select":
                acct = form.get("acct", ["800001"])[0] or "800001"
                s["wf_draft" + wf_base] = acct            # session draft (both twins)
                body = (f'<form action="{wf_base}/create" method="POST">'
                        f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                        f'<input type="hidden" name="acct" value="{_esc(acct)}">'
                        '<label>Amount</label>'
                        '<input type="text" name="amount" value="">'
                        '<button type="submit">Create transfer</button></form>')
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s,
                                           f"Transfer - step 2 of 3: amount (account {_esc(acct)} selected)",
                                           body))

            if path == wf_base + "/create":
                amount = _wf_amount(form.get("amount", [""])[0])
                if amount is None:
                    return self._send(400, "<html><body>invalid amount</body></html>")
                if safe or shared:
                    draft = s.get("wf_draft" + wf_base)
                    if not draft:
                        return self._send(400, "<html><body>no account selected - "
                                                     "start at step 1</body></html>")
                    acct = draft                       # server-side draft wins
                else:
                    acct = form.get("acct", ["800001"])[0] or "800001"   # no draft check
                st["seq"] += 1
                tid = "TRF-%04d" % st["seq"]
                # REPRO FIX (2026-10-31, caught by the scanner's own CI
                # reproducibility gate): creates stamped with wfWalkMarker
                # get a CONTENT-ADDRESSED id — the global sequential counter
                # made the minted id depend on concurrent interleaving, which
                # moved the audit Merkle root between identical seeded runs.
                _wfm = form.get("wfWalkMarker", [""])[0]
                if _wfm:
                    tid = "TRF-%04d" % (int(_hl.sha256(
                        _wfm.encode()).hexdigest()[:6], 16) % 900000 + 100000)
                st["items"][tid] = {"acct": acct, "amount": amount, "mode": "ach",
                                    "state": "pending", "executions": 0}
                body = _wf_confirm_form(wf_base, s, tid, amount)
                if shared:
                    # the rollback path rides the SAME landing (after the
                    # confirm form — the guided walk must chain into confirm)
                    body += (f'<form action="{wf_base}/cancel" method="POST">'
                             f'<input type="hidden" name="csrfToken" value="{s["csrf"]}">'
                             f'<input type="hidden" name="tid" value="{_esc(tid)}">'
                             '<button type="submit">Cancel transfer</button></form>')
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s,
                                           f"Transfer - step 3 of 3: confirm {tid}",
                                           body))

            if path == wf_base + "/cancel":
                # shared wizard rollback path: moves a transfer to CANCELLED.
                # No ownership check (any authenticated session may cancel any
                # object in the shared store) — same defect class as confirm.
                if not shared:
                    return self._send(404, "<html><body>no such path</body></html>")
                tid = (form.get("tid", [""])[0] or "").strip()
                if not tid:
                    return self._send(400, "<html><body>missing transfer reference</body></html>")
                it = st["items"].get(tid)
                if it is None:
                    so = WF_STANDING_ORDERS.get(tid)
                    if so is None:
                        return self._send(404, "<html><body>unknown object</body></html>")
                    so["state"] = "cancelled"
                else:
                    it["state"] = "cancelled"
                line = f"<p>Object {tid} cancelled.</p>"
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s, "Transfer cancelled", line))

            if path == wf_base + "/confirm":
                tid = (form.get("tid", [""])[0] or "").strip()
                amt_raw = (form.get("amount", [""])[0] or "").strip()
                mode = (form.get("mode", ["ach"])[0] or "ach")[:24]
                if not tid:
                    return self._send(400, "<html><body>missing transfer reference</body></html>")
                items = st["items"]
                if safe:
                    it = items.get(tid)
                    if it is None:
                        return self._send(404, "<html><body>unknown transfer</body></html>")
                    if it["state"] == "executed":
                        return self._send(409, "<html><body>already executed</body></html>")
                    if amt_raw:
                        amt = _wf_amount(amt_raw)
                        if amt is None:
                            return self._send(400, "<html><body>invalid amount</body></html>")
                        if amt != it["amount"]:
                            return self._send(400, "<html><body>amount changed since approval - "
                                                         "restart the transfer</body></html>")
                    if mode == "wire" and s["role"] != "admin":
                        return self._send(403, "<html><body>wire transfers require an "
                                                     "administrator</body></html>")
                    it["state"], it["executions"], it["mode"] = "executed", 1, mode
                    line = f"<p>Transfer {tid} executed: {it['amount']} ({_esc(mode)}).</p>"
                    return self._send(200, _menubar_for(s) +
                                      _wf_flow(wf_base, s, "Transfer executed", line))
                if shared:
                    # ---- shared wizard: guards 1-5 of the hardened twin are
                    # ALL present; EXACTLY the three cross-identity guards are
                    # missing (ownership / object type / cancelled state).
                    it = items.get(tid)
                    if it is None:
                        so = WF_STANDING_ORDERS.get(tid)
                        if so is None:
                            return self._send(404, "<html><body>unknown object</body></html>")
                        # CROSS-OBJECT: a foreign-typed object (standing order)
                        # executes through the TRANSFER confirm step
                        if so["executions"]:
                            return self._send(409, "<html><body>already executed</body></html>")
                        so["executions"] += 1
                        so["state"] = "executed"
                        line = (f"<p>Object {tid} executed: standing order "
                                f"({so['acct']}).</p>")
                        return self._send(200, _menubar_for(s) +
                                          _wf_flow(wf_base, s, "Object executed", line))
                    # a TRANSFER object: known to ANY session (shared store) —
                    # no ownership check (CROSS-USER), no cancelled-state check
                    # (CROSS-STATE); amount binding, idempotency and the wire
                    # role check are enforced exactly like the hardened twin.
                    if it["state"] == "executed":
                        return self._send(409, "<html><body>already executed</body></html>")
                    if amt_raw:
                        amt = _wf_amount(amt_raw)
                        if amt is None:
                            return self._send(400, "<html><body>invalid amount</body></html>")
                        if amt != it["amount"]:
                            return self._send(400, "<html><body>amount changed since approval - "
                                                         "restart the transfer</body></html>")
                    if mode == "wire" and s["role"] != "admin":
                        return self._send(403, "<html><body>wire transfers require an "
                                                     "administrator</body></html>")
                    it["state"], it["executions"], it["mode"] = "executed", 1, mode
                    line = f"<p>Transfer {tid} executed: {it['amount']} ({_esc(mode)}).</p>"
                    return self._send(200, _menubar_for(s) +
                                      _wf_flow(wf_base, s, "Transfer executed", line))
                # ---- vulnerable twin: every guard above is missing ----
                it = items.get(tid)
                if it is not None:
                    # known transfer: POSTed amount OVERRIDES the approved one, and the
                    # pending state is never consumed (replay executes again)
                    if amt_raw:
                        amt = _wf_amount(amt_raw)
                        if amt is None:
                            return self._send(400, "<html><body>invalid amount</body></html>")
                        it["amount"] = amt
                    it["mode"] = mode
                    it["state"] = "executed"
                    it["executions"] += 1
                    line = f"<p>Transfer {tid} executed: {it['amount']} ({_esc(mode)}).</p>"
                    return self._send(200, _menubar_for(s) +
                                      _wf_flow(wf_base, s, "Transfer executed", line))
                # unknown tid: implicit creation + execution from POSTed params alone
                amt = _wf_amount(amt_raw)
                if amt is None:
                    return self._send(400, "<html><body>invalid amount</body></html>")
                acct = form.get("acct", ["800001"])[0] or "800001"
                items[tid] = {"acct": acct, "amount": amt, "mode": mode,
                              "state": "executed", "executions": 1}
                line = f"<p>Transfer {tid} executed: {amt} ({_esc(mode)}).</p>"
                return self._send(200, _menubar_for(s) +
                                  _wf_flow(wf_base, s, "Transfer executed", line))

        # ---------------- JSON/div-form endpoints (Phase 50) ----------------
        # /vuln/json-reflect: div-form POST whose JS serializes inputs as JSON
        # (DISC-10 + ENG-04 chain); response is text/html and reflects the name
        # field RAW — the subscribe-style XSS.
        if path == "/vuln/json-reflect":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            name = str(data.get("name", ""))
            return self._send(200, f"<div>Hello {name}</div>")
        if path == "/safe/json-reflect":
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            name = str(data.get("name", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return self._send(200, f"<div>Hello {name}</div>")
        # /vuln/csrf-reflect: requires the session cookie AND the matching CSRF
        # token (ENG-05 jar + TOKEN-preservation chain). Without both: 403.
        if path == "/vuln/csrf-reflect":
            cookie = (self.headers.get("Cookie") or "")
            if "json" not in ctype:
                return self._send(400, '"expected application/json"')
            try:
                data = json.loads(raw)
            except Exception:
                return self._send(400, '"invalid JSON"')
            if CSRF_SESSION not in cookie or str(data.get("csrf", "")) != CSRF_TOKEN:
                return self._send(403, '"Invalid CSRF token"')
            note = str(data.get("note", ""))
            return self._send(200, f"<div>Noted: {note}</div>")
        # /vuln/jsform-reflect: standard form POST target of the RUNTIME-built form
        # (browser render-merge discovery; statically invisible — no <form> markup).
        if path == "/vuln/jsform-reflect":
            form = parse_qs(raw, keep_blank_values=True)
            msg = (form.get("msg") or [""])[0]
            return self._send(200, f"<div>Feedback: {msg}</div>")

        # ---- OOB stock pair (Phase 49 / blind-XXE-with-callback): the parser FETCHES
        # http(s) external entities for real (loopback-only in the fixture) but the
        # response is cycling noise — no response oracle exists, ONLY out-of-band
        # evidence can confirm. /safe twin rejects DTD outright.
        if path in ("/vuln/oob-stock", "/safe/oob-stock"):
            if "xml" not in ctype:
                return self._send(400, '"XML parsing error"')
            if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
                if path == "/safe/oob-stock":
                    return self._send(400, '"DTD declarations are not allowed"')   # hardened parser
                import urllib.request as _ur
                for _n, sysid in re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', raw):
                    if sysid.startswith(("http://127.0.0.1:", "http://localhost:")):
                        try:
                            _ur.urlopen(sysid, timeout=3).read()      # THE out-of-band fetch
                        except Exception:
                            pass                                        # fetch failed silently
            fields0 = dict(re.findall(r"<(\w+)>([^<]*)</\1>", raw))
            if "storeId" not in fields0:
                return self._send(400, '"Store ID could not be parsed from XML"')
            Handler._blind_seq_n += 1
            n = _BLIND_SEQ[Handler._blind_seq_n % len(_BLIND_SEQ)]
            return self._send(200, f"{n} units", {"Content-Type": "text/plain"})

        if path not in ("/vuln/stock", "/safe/stock", "/blind/stock"):
            return self._send(404, "<p>404</p>")
        if "xml" not in ctype:
            return self._send(400, '"XML parsing error"')
        if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
            if path == "/safe/stock":
                return self._send(400, '"DTD declarations are not allowed"')   # hardened parser
            # vulnerable parser: resolve external entities against the fake filesystem
            for name, sysid in re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>', raw):
                target = sysid.replace("file://", "")
                content = FAKE_FS.get(target, "")          # unreadable/missing -> empty (control)
                raw = raw.replace(f"&{name};", content)
        fields = dict(re.findall(r"<(\w+)>([^<]*)</\1>", raw))
        pid = fields.get("productId", "")
        if not pid.isdigit():
            return self._send(400, '"Invalid product ID"')
        if "storeId" not in fields:
            # the app's own error names the element it wants (error-driven discovery)
            return self._send(400, '"Store ID could not be parsed from XML"')
        if path == "/blind/stock":
            # ginandjuice.shop REAL live behavior (proven with 5x same-file probes):
            # entities resolve, but the stock number is effectively random per request —
            # the response carries NO entity-content information (blind XXE). Modeled as
            # a deterministic cycling sequence so tests stay reproducible: any two
            # consecutive identical requests differ -> the double-control stability gate
            # must reject the noise (no response-verified finding is possible).
            Handler._blind_seq_n += 1
            n = _BLIND_SEQ[Handler._blind_seq_n % len(_BLIND_SEQ)]
            return self._send(200, f"{n} units", {"Content-Type": "text/plain"})
        sid = fields.get("storeId", "")
        if not sid:
            n = 0                                           # failed entity -> default stock
        else:
            n = sum(ord(c) for c in sid) % 997 + 1          # entity content -> response
        return self._send(200, f"{n} units", {"Content-Type": "text/plain"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8777"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Burhan fixture listening on 127.0.0.1:{port} delay={DELAY_MS}ms")
    srv.serve_forever()

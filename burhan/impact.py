"""Burhan v4.4.0 — L3: Proven Real Impact (الأثر الحقيقي المُثبَت).

The layer ABOVE the hardened engine (L0) and the Attack Path Intelligence
(L2). L0 answers "is THIS input injectable"; L2 strings findings into complete
attack paths with every link evidence-cited. L3 answers the question neither
can: what does the attacker ACTUALLY REACH at the end of a path — which data,
which object, which capability — proven by a FRESH LIVE probe, never by
description.

THE CONTRACT (supervisor order, trace 1a107bbe20c548bd — never compromise it):

  1. IMPACT IS PROVEN, NOT ASSUMED. An impact is VERIFIED only when a fresh
     live probe FROM THIS L3 run shows the attacker reaching the end state.
     Reasoned-only impact stays INFERRED and says so. Attempted-but-
     unconfirmed is PROBE_FAILED with the measured numbers. A class with no
     safe probe is NOT_SAFE_TO_PROVE and carries the honest label — never a
     fake proof: "القدرة مستنتَجة، غير قابلة للإثبات الآمن".

  2. SAFETY CEILING (hard, enforced in code, fail-closed allowlists):
       - SQLi        -> a trivial read proof over DB METADATA only (version
                        predicates + one extracted character). Never data
                        extraction, never table names, never timing.
       - XXE / file  -> benign files only (hostname). Never a secret file.
       - traversal   -> the allowlisted benign file of the proven shape only.
       - state change-> on OUR OWN session, additive only (cart add), on an
                        allowlisted surface, never destructive, never a
                        victim's session.
     Principle: "capability proven, not exploited" — أُثبتت القدرة، لم تُستغَل.

  3. L3 IS STRICTLY OPT-IN. Planning is a pure projection over a serialized
     scan report (zero requests, no engine imports, deterministic). The scan
     pipeline never plans or executes impact probes; L2's output is not
     altered by this layer's presence. Live execution happens only through
     execute_impact_probes(), driven by the CLI / a driver script.

  4. EVIDENCE INTEGRITY (the L2 discipline, extended): every VERIFIED impact
     cites the probe journal entry it rests on and its excerpt is a literal
     slice of that entry's raw fields — substring-verifiable, zero tolerance.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
import urllib.parse

from . import apath  # L2 sits below L3 (pure projection, no engine imports)

IMPACT_LAYER = "L3-proven-impact"
SCANNER_LAYER = "burhan-impact/4.4.0"

# ------------------------------------------------------------------ fixed fresh-probe material
# Deterministic, public, never secret. Every constant below is the byte-shape
# the live executor issues; the probe journal records exactly these.
VERSION_TRUE_COND = "@@version LIKE '%'"
VERSION_FALSE_COND = "@@version LIKE 'zzz-burhan-nope%'"
DIGIT_LADDER = ("8", "5", "3", "1")   # MySQL 8/5, SQLite 3, MSSQL/PG 1x majors
                                            # (MAX-08 follow-up: the old (8,5)-only
                                            # ladder could never read a SQLite or
                                            # MSSQL/PostgreSQL major version char)

XXE_CONTROL_FILE = "file:///nonexistent-burhan-control"
XXE_READ_FILE = "file:///etc/hostname"
XXE_CONTROL_BODY = ('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY c SYSTEM "'
                    + XXE_CONTROL_FILE + '">]><d>&c;</d>')
XXE_READ_BODY = ('<?xml version="1.0"?><!DOCTYPE d [<!ENTITY f SYSTEM "'
                 + XXE_READ_FILE + '">]><d>&f;</d>')

L3_REDIRECT_SINK = "https://webhook.site/token?i=l3redir-ab12"   # overridden live with our OAST channel
L3_ORIGIN_PROBE = "https://csrf-probe.example"                   # reserved TLD — hostile origin, never resolved
L3_HEADER_NAME = "x-burhan-l3-proof"
L3_HEADER_VALUE = "capability-proven"
L3_HEADER_TAIL = "x-burhan-l3-proof%3a%20capability-proven"

XSS_FLAG = {"xss_reflected": "l3canary", "xss_dom": "l3domcanary", "xss_stored": "l3stocanary"}
XSS_VARIANT = {"xss_reflected": "attr_inject_onerror", "xss_dom": "attr_inject_onload",
               "xss_stored": "raw_markup"}

PROBE_KINDS = {
    "sql_injection": "sql_version_oracle",
    "xxe": "xxe_file_read",
    "csrf": "csrf_own_session_state_change",
    "path_traversal": "traversal_file_read",
    "xss_reflected": "xss_browser_execution",
    "xss_dom": "xss_browser_execution",
    "xss_stored": "xss_stored_persistence",
    "open_redirect": "open_redirect_navigation",
    "http_response_header_injection": "header_split_proof",
}
SAFE_CLASSES = frozenset(PROBE_KINDS)
# classes with a defined safe probe get a plan; these get the honest label:
NOT_SAFE_CLASSES = frozenset({"command_injection", "ssti", "nosql_injection", "ssrf",
                              "jwt_security", "host_header_injection", "idor_bola",
                              "vertical_privilege_escalation", "workflow_state_bypass",
                              "authorization_bypass"})
NOT_SAFE_REASON = ("no safe minimal probe exists for this vulnerability class — the real "
                   "impact stays inferred from the verified defect, never claimed as "
                   "proven: القدرة مستنتَجة، غير قابلة للإثبات الآمن")


def _xss_payload(cls):
    if cls == "xss_reflected":
        return "\" onerror=\"window.__BURHAN_XSS__='l3canary'\""
    if cls == "xss_dom":
        return "\" onload=\"window.__BURHAN_XSS__='l3domcanary'\""
    return "<img src=x onerror='window.__BURHAN_XSS__=\"l3stocanary\"'>"


# ------------------------------------------------------------------ safety registries (fail-closed)
_SQL_ALLOW = (
    re.compile(r"^\d+\s*=\s*\d+$"),
    re.compile(r"^'[^']*'\s*=\s*'[^']*'$"),
    re.compile(r"^@@version\s+LIKE\s+'[^']*'$"),
    re.compile(r"^(?i:version)\(\)\s+LIKE\s+'[^']*'$"),
    re.compile(r"^sqlite_version\(\)\s+LIKE\s+'[^']*'$"),
    re.compile(r"^SUBSTRING\((?:@@version|(?i:version)\(\)|sqlite_version\(\)),\d+,\d+\)\s*=\s*'[^']*'$"),
    re.compile(r"^SUBSTR\(sqlite_version\(\),\d+,\d+\)\s*=\s*'[^']*'$"),
)
# MAX-08 (maximum internal test, live-caught on Juice Shop 20.2.0 — SQLite):
# the version oracle was hardcoded to the MSSQL family (@@version). On any
# non-MSSQL backend every version predicate is a syntax error and the impact
# honestly PROBE_FAILEDs. The family is now derived from the finding's OWN
# evidence text (the db_error signature that verified it), defaulting to the
# authorized-targets provenance (MSSQL). Every emitted shape stays inside the
# fail-closed _SQL_ALLOW registry above.
_SQL_FAMILY_CONDS = {
    "mssql":    ("@@version LIKE '%'", "@@version LIKE 'zzz-burhan-nope%'",
                 "SUBSTRING(@@version,1,1)='{}'"),
    "mysql":    ("VERSION() LIKE '%'", "VERSION() LIKE 'zzz-burhan-nope%'",
                 "SUBSTRING(VERSION(),1,1)='{}'"),
    "postgres": ("version() LIKE '%'", "version() LIKE 'zzz-burhan-nope%'",
                 "SUBSTRING(version(),1,1)='{}'"),
    "sqlite":   ("sqlite_version() LIKE '%'", "sqlite_version() LIKE 'zzz-burhan-nope%'",
                 "SUBSTR(sqlite_version(),1,1)='{}'"),
}


def _sql_family(f: dict) -> str:
    hay = " ".join(str(e.get("detail", "")) for e in (f.get("evidence") or []))
    hay += " " + str((f.get("verification") or {}).get("notes", ""))
    hay = hay.lower()
    if "sqlite" in hay:
        return "sqlite"
    if "mysql" in hay:
        return "mysql"
    if "postgres" in hay or "psql" in hay or "pgsql" in hay:
        return "postgres"
    return "mssql"
# proven-vector taint: a finding proven with extraction/destructive material is
# never used to derive an impact probe (fail-closed, never guessed)
_SQL_TAINT = ("union", "information_schema", "sleep(", "benchmark(", "load_file",
              "into outfile", "waitfor", "xp_cmdshell", "drop table", "insert into",
              "update set", "delete from", "select password", "select table_name",
              "shutdown")

_READ_ALLOW = frozenset({"etc/hostname", "etc/passwd", "etc/hosts", "win.ini",
                         "windows/win.ini", "c:/windows/win.ini"})
_READ_DENY = ("shadow", ".env", "id_rsa", "web.config", "wp-config", "/proc/",
              "boot.ini", ".ssh", ".aws", ".gnupg", "secret", "credential",
              "token", ".pem", ".pfx", ".keystore", "sudoers", "authorized_keys",
              "crontab")

_STATE_SURFACES = frozenset({"/catalog/cart", "/cart"})
_STATE_MARKERS = ("logout", "signout", "sign-out", "log-out", "delete", "remove",
                  "reset", "password", "passwd", "drop", "truncate", "purge",
                  "wipe", "destroy", "cancel", "close", "unsubscribe", "erase",
                  "shutdown", "kill", "update")


def validate_sqli_condition(cond):
    """Only controls and version predicates over DB metadata pass. Everything
    else — extraction, destructive, timing — is refused with a reason."""
    c = str(cond or "").strip()
    if not c:
        return False, "empty condition"
    for rx in _SQL_ALLOW:
        if rx.match(c):
            return True, "allowlisted control / version predicate over DB metadata"
    return False, ("condition outside the control/version allowlist "
                   "(extraction, destructive or timing classes are refused)")


def _norm_candidate(s):
    s = str(s or "").strip().lower().replace("\\", "/")
    s = urllib.parse.unquote(s)
    s = urllib.parse.unquote(s)
    s = posixpath.normpath(s)
    while True:
        if s.startswith("./"):
            s = s[2:]
            continue
        if s.startswith("../"):
            s = s[3:]
            continue
        if s.startswith("/"):
            s = s[1:]
            continue
        break
    return s


def _secret_marker(x):
    hay = urllib.parse.unquote(urllib.parse.unquote(str(x or ""))).lower()
    for m in _READ_DENY:
        if m in hay:
            return m
    return ""


def validate_read_file(x):
    """Benign allowlist in, secret files out. Accepts a bare path or a full URL
    (param values are decoded and dot-segments resolved before matching)."""
    marker = _secret_marker(x)
    if marker:
        return False, f"secret-class file marker ({marker}) — L3 never reads secret files"
    raw = str(x or "")
    cands = []
    if "://" in raw:
        try:
            u = urllib.parse.urlsplit(raw)
            cands.append(u.path or "")
            for _k, v in urllib.parse.parse_qsl(u.query or "", keep_blank_values=True):
                cands.append(v)
        except Exception:
            pass
    else:
        cands.append(raw)
    for c in cands:
        n = _norm_candidate(c)
        if n and n in _READ_ALLOW:
            return True, f"benign allowlisted file ({n})"
    return False, ("no benign allowlisted file in the input "
                   "(hostname / passwd / hosts / win.ini only)")


def validate_state_change(url, body):
    """Additive-only state changes on allowlisted surfaces, in our own session.
    Destructive markers and non-allowlisted surfaces are refused with a reason."""
    hay = (str(url or "") + " " + str(body or "")).lower()
    for m in _STATE_MARKERS:
        if m in hay:
            return False, f"destructive marker ({m}) — L3 only plans additive state changes"
    try:
        path = (urllib.parse.urlsplit(str(url or "")).path or "").lower()
    except Exception:
        path = ""
    if path in _STATE_SURFACES:
        return True, "additive allowlisted state-changing surface (own session)"
    return False, ("state-changing surface not in the additive allowlist — L3 only "
                   "plans additive cart-add-style proofs, never destructive ones")


# ------------------------------------------------------------------ boolean template derivation
_COND_NUMERIC = re.compile(r"^\d+\s*=\s*\d+$")
_COND_QUOTED = re.compile(r"^'[^']*'\s*=\s*'[^']*'$")


def _raw_param(query, name):
    """Raw (still-encoded) value of `name` in a query string, order-preserving."""
    for pair in (query or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == name:
                return v
    return None


def derive_bool_template(url, body, param):
    """Reproduce the EXACT byte-shape of a proven boolean vector, substituting
    only the condition. Returns None when the value carries no boolean shape —
    the planner must then refuse (never guess)."""
    raw_url, raw_body = str(url or ""), str(body or "")
    val, kind = None, ""
    try:
        q = urllib.parse.urlsplit(raw_url).query or ""
    except Exception:
        q = ""
    rv = _raw_param(q, param)
    if rv is not None:
        val, kind = rv, "query"
    if val is None:
        for pair in (raw_body or "").split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if urllib.parse.unquote_plus(k) == param:
                    val, kind = v, "body"
                    break
    if val is None:
        return None
    v = urllib.parse.unquote_plus(val)
    m = None
    for m0 in re.finditer(r"\b(OR|AND)\b", v, re.IGNORECASE):
        m = m0
        break
    if m is None:
        return None
    pre = v[:m.start()].rstrip()
    kw = m.group(1).upper()
    rest = v[m.end():].lstrip()
    idx = rest.find("--")
    if idx >= 0:
        cond_raw = rest[:idx]
        cond = cond_raw.rstrip()
        gap = cond_raw[len(cond):]
        # the comment suffix keeps its leading gap; anything trailing the
        # comment marker (capture whitespace) is normalized away
        suffix = (gap + rest[idx:]).rstrip()
    else:
        cond = rest.rstrip()
        suffix = ""
    if not (cond and (_COND_NUMERIC.match(cond) or _COND_QUOTED.match(cond))):
        return None
    if not pre:
        return None

    def render(c, _pre=pre, _kw=kw, _suf=suffix):
        return urllib.parse.quote_plus(f"{_pre} {_kw} {c}{_suf}")

    return {"param": param, "kind": kind, "keyword": kw, "orig_cond": cond,
            "prefix": pre, "suffix": suffix, "old_value": val,
            "render": render, "raw_url": raw_url, "raw_body": raw_body}


# ------------------------------------------------------------------ planner
def _b(s, n=80):
    s = str(s or "")
    return s[:n]


def _pid(prefix, *material):
    return prefix + hashlib.sha1("|".join(str(m) for m in material).encode()).hexdigest()[:10]


def _surface_entries(f, ctx):
    """EVERY journal entry on the finding's own surface (method + path + any
    param name present), deterministic rid order. Uncapped on purpose: the
    proving pool (capped at 6) cut the CRLF/stored vectors on the live reports
    — L3 must always see the finding's whole surface. Findings whose vector
    lives in the URL PATH (gruyere's /..%2f../etc/passwd, no query param) fall
    back to a surface-only match."""
    path = apath._path_of(f.get("url", ""))
    method = (f.get("method") or "GET").upper()
    params = [p.strip() for p in (f.get("parameter") or "").split(",") if p.strip()]
    exact, loose = [], []
    for rid in sorted((ctx.journal or {}).keys(), key=str):
        e = ctx.entry(rid)
        req = e.get("request") or {}
        rpath = apath._path_of(req.get("url", ""))
        rmethod = (req.get("method") or "").upper()
        hay = f"{req.get('url', '')} {req.get('body', '')}"
        if rmethod != method or rpath != path:
            continue
        if any(p in hay for p in params):
            exact.append((rid, req, hay))
        else:
            loose.append((rid, req, hay))
    return exact if exact else loose


def _finding_proving_entries(f, ctx):
    """Decoded proving-request haystacks for a finding, deterministic order."""
    out = []
    for rid, req, hay in _surface_entries(f, ctx):
        out.append((rid, req,
                    urllib.parse.unquote_plus(
                        f"{req.get('url', '')} {req.get('body', '')}").lower()))
    return out




def _swap_query_value(url, param, new_val):
    """Swap one param's value inside its OWN query pair (byte-exact elsewhere)."""
    try:
        u = urllib.parse.urlsplit(url)
    except Exception:
        return url
    pairs = (u.query or "").split("&")
    out, done = [], False
    for pair in pairs:
        if "=" in pair and not done:
            k, _v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == param:
                out.append(k + "=" + new_val)
                done = True
                continue
        out.append(pair)
    if not done:
        out.append(urllib.parse.quote_plus(param) + "=" + new_val)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "&".join(out), ""))


def _swap_body_value(body, param, new_val):
    """Swap one param's value inside its OWN body pair (byte-exact elsewhere)."""
    pairs = (body or "").split("&")
    out, done = [], False
    for pair in pairs:
        if "=" in pair and not done:
            k, _v = pair.split("=", 1)
            if urllib.parse.unquote_plus(k) == param:
                out.append(k + "=" + new_val)
                done = True
                continue
        out.append(pair)
    if not done:
        out.append(urllib.parse.quote_plus(param) + "=" + new_val)
    return "&".join(out)


def _mk_req(label, method, url, headers=None, body="", **extra):
    r = {"label": label, "method": (method or "GET").upper(), "url": url,
         "headers": dict(headers or {}), "body": body or ""}
    r.update(extra)
    return r


def _refuse(reason):
    return {"status": "REFUSED", "requests": [], "refusal_reason": reason}


def _true_form(cond):
    """Normalize a derived condition to its tautology form: a template picked
    from the FALSE-side vector (1=2 / '1'='2') must not collapse
    control_true onto control_false — the true control is LHS=LHS."""
    if _COND_NUMERIC.match(cond or ""):
        l, _, r = (cond or "").partition("=")
        l, r = l.strip(), r.strip()
        if l and r and l != r:
            return f"{l}={l}"
        return cond
    if _COND_QUOTED.match(cond or ""):
        parts = re.findall(r"'([^']*)'", cond)
        if len(parts) >= 2 and parts[0] != parts[1]:
            return f"'{parts[0]}'='{parts[0]}'"
    return cond


def _plan_sql(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    for _rid, _req, hay in ents:
        for m in _SQL_TAINT:
            if m in hay:
                return _refuse("the finding's proven vector set contains non-allowlisted "
                               "SQL material (extraction or destructive class) — fail-closed: "
                               "L3 refuses to derive an impact probe from it")
    # pick the PROVEN vector: 2xx first (it actually worked), then anchored to
    # the finding's own TRUE-side size (the L0 evidence records it — the entry
    # whose response matches the TRUE side is the vector that produced the
    # finding; live-measured on testasp/Login.asp where an arbitrary same-shape
    # entry landed on a different page and collapsed the oracle), then quoted
    # breakout over bare numeric, then the stable entry order
    true_size = 0
    for e in f.get("evidence") or []:
        for m0 in re.findall(r"(\d{3,})B", e.get("detail") or ""):
            n = int(m0)
            if n > true_size:
                true_size = n
    # MAX-09b (maximum internal test, live-caught on Juice Shop 20.2.0): prefer
    # a template whose OWN battery pair already SEPARATED in the journal (the
    # true/false variants of the same prefix+keyword returned different sizes).
    # The old ranking (2xx, anchored-to-evidence-size, quoted, order) picked the
    # numeric AND pair on Juice Shop — a pair that never separates there (the
    # AND stays a literal LIKE term) — while the paren-closing pair in the same
    # journal separated 4000B/30B. A separated pair is the strongest plan-time
    # signal the probe will reproduce; it ranks directly after 2xx.
    _pname = (f.get("parameter") or "").split(",")[0].strip()
    by_pk: dict[tuple, list] = {}
    for _rid2, _req2, _h2 in ents:
        t2 = derive_bool_template(_req2.get("url", ""), _req2.get("body", ""), _pname)
        if t2:
            by_pk.setdefault((t2["prefix"], t2["keyword"]), []).append(_rid2)
    separating: set[str] = set()
    for _items in by_pk.values():
        sizes = []
        for _rid2 in _items:
            e2 = ctx.entry(_rid2) or {}
            sizes.append(len((e2.get("response") or {}).get("body") or ""))
        if len(sizes) >= 2:
            smax, smin = max(sizes), min(sizes)
            if smax - smin > max(200, 0.25 * smax):
                separating.update(_items)
    ranked = []
    for idx, (_rid, req, _hay) in enumerate(ents):
        tpl0 = derive_bool_template(req.get("url", ""), req.get("body", ""),
                                    (f.get("parameter") or "").split(",")[0].strip())
        if not tpl0:
            continue
        ent = ctx.entry(_rid) or {}
        st = int((ent.get("response") or {}).get("status") or 0)
        rlen = len((ent.get("response") or {}).get("body") or "")
        quoted = 1 if _COND_QUOTED.match(tpl0["orig_cond"] or "") else 0
        ok2xx = 1 if 200 <= st < 300 else 0
        sep = 1 if _rid in separating else 0
        anchored = 0
        if true_size:
            if rlen == true_size:
                anchored = 1
            elif rlen >= 3990 and true_size >= rlen:
                anchored = 1     # journal-capped big response == a big TRUE side
        ranked.append((-ok2xx, -sep, -anchored, -quoted, idx, tpl0))
    ranked.sort()
    tpl = ranked[0][5] if ranked else None
    if not tpl:
        return _refuse("no boolean-shaped proven vector on the finding's surface — "
                       "L3 never guesses a template")
    orig = _true_form(tpl["orig_cond"])
    if _COND_NUMERIC.match(orig):
        false_cond = re.sub(r"=\s*\d+$", "=2", orig)
    else:
        false_cond = re.sub(r"'[^']*'\s*$", "'2'", orig)
    fam = _sql_family(f)
    ver_true, ver_false, digit_tpl = _SQL_FAMILY_CONDS[fam]
    for c in (orig, false_cond, ver_true, ver_false):
        ok, why = validate_sqli_condition(c)
        if not ok:
            return _refuse(f"derived condition failed the allowlist ({why})")
    conds = [("control_true", orig), ("control_false", false_cond),
             ("version_true", ver_true), ("version_false", ver_false)]
    conds += [(f"version_digit_{d}", digit_tpl.format(d)) for d in DIGIT_LADDER]
    reqs = []
    base_headers = dict((ents[0][1].get("headers") or {})) if ents else {}
    base_method = (ents[0][1].get("method") or "GET").upper() if ents else "GET"
    for label, cond in conds:
        new_val = tpl["render"](cond)
        if tpl["kind"] == "query":
            nurl = _swap_query_value(tpl["raw_url"], tpl["param"], new_val)
            reqs.append(_mk_req(label, base_method, nurl, dict(base_headers),
                                body=(tpl["raw_body"] or ""), condition=cond))
        else:
            nbody = _swap_body_value(tpl["raw_body"] or "", tpl["param"], new_val)
            reqs.append(_mk_req(label, base_method, tpl["raw_url"], dict(base_headers),
                                body=nbody, condition=cond))
    return {"status": "PLANNED", "requests": reqs,
            "detail": {"template": {"keyword": tpl["keyword"], "kind": tpl["kind"],
                                    "param": tpl["param"], "orig_cond": orig}},
            "refusal_reason": ""}


def _plan_xxe(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    for _rid, req, hay in ents:
        if "<!entity" not in hay:
            continue
        body = urllib.parse.unquote_plus(req.get("body") or "")
        for target in re.findall(r'SYSTEM\s+"([^"]+)"', body, re.IGNORECASE):
            marker = _secret_marker(target)
            if marker:
                return _refuse("the proven XXE vector targets a secret-class file — "
                               "L3 never reads secret files to prove impact")
        url = req.get("url") or f.get("url") or ""
        method = (req.get("method") or "POST").upper()
        hdrs = dict(req.get("headers") or {})
        hdrs.setdefault("Content-Type", "application/xml")
        return {"status": "PLANNED", "requests": [
            _mk_req("xxe_control", method, url, hdrs, XXE_CONTROL_BODY,
                    expected_file="nonexistent-burhan-control"),
            _mk_req("xxe_file_read", method, url, hdrs, XXE_READ_BODY,
                    expected_file="etc/hostname")],
            "refusal_reason": ""}
    return _refuse("no entity-bearing proven vector on the finding's surface")


def _plan_csrf(f, ctx, origin_probe, cart_view="/cart"):
    url = f.get("url") or ""
    ents = _finding_proving_entries(f, ctx)
    # the body must come from an ACCEPTED replay (2xx): the pool also contains
    # 400-rejected probe shapes (CRLF/SQL junk) that the app never accepted —
    # live-measured on ginjuice where a CRLF body collapsed the state change
    ents = sorted(ents, key=lambda t: (
        0 if 200 <= int(((ctx.entry(t[0]) or {}).get("response") or {}).get("status") or 0) < 300 else 1,
        t[0]))
    body = ""
    for _rid, req, _hay in ents:
        if (req.get("body") or "").strip():
            body = req.get("body")
            break
    ok, why = validate_state_change(url, body)
    if not ok:
        return _refuse(f"state-changing proof refused — {why}; L3 only proves additive "
                       "state changes on allowlisted surfaces in our own session, "
                       "never destructive ones")
    try:
        u = urllib.parse.urlsplit(url)
        origin = f"{u.scheme}://{u.netloc}"
    except Exception:
        return _refuse("cannot derive the target origin")
    hdrs = {"Origin": origin_probe,
            "Content-Type": "application/x-www-form-urlencoded"}
    view = origin + (cart_view if cart_view.startswith("/") else "/" + cart_view)
    return {"status": "PLANNED", "requests": [
        _mk_req("session_mint", "GET", origin + "/", {}, ""),
        _mk_req("cart_baseline", "GET", view, {}, ""),
        _mk_req("cross_origin_state_change", (f.get("method") or "POST").upper(),
                url, hdrs, body, origin=origin_probe),
        _mk_req("cart_after", "GET", view, {}, "")],
        "refusal_reason": ""}


def _plan_trav(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    ents = sorted(ents, key=lambda t: (
        0 if 200 <= int(((ctx.entry(t[0]) or {}).get("response") or {}).get("status") or 0) < 300 else 1,
        t[0]))
    for _rid, req, hay in ents:
        if ".." not in hay:
            continue
        url = req.get("url") or ""
        ok, why = validate_read_file(url)
        if not ok:
            return _refuse("the proven traversal vector's file is not in the benign "
                           "read allowlist (secret-class) — L3 never reads secret "
                           "files to prove impact")
        return {"status": "PLANNED", "requests": [
            _mk_req("file_read", (req.get("method") or "GET").upper(), url,
                    dict(req.get("headers") or {}), req.get("body") or "",
                    expected_file=_norm_candidate(
                        (urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                                keep_blank_values=True) or [("", "")])[-1][1]))],
            "refusal_reason": ""}
    return _refuse("no traversal-shaped proven vector on the finding's surface")


def _plan_crlf(f, ctx):
    ents = _finding_proving_entries(f, ctx)
    for _rid, req, _hay in ents:
        url = req.get("url") or ""
        try:
            q = urllib.parse.urlsplit(url).query or ""
        except Exception:
            continue
        param = (f.get("parameter") or "").split(",")[0].strip()
        rv = _raw_param(q, param)
        if rv is None:
            continue
        low = rv.lower()
        cut = low.find("%0d%0a")
        sep = ""
        if cut >= 0:
            sep = rv[cut:cut + 6]          # preserve the proven separator bytes
        else:
            cut = rv.find("\r\n")
            if cut >= 0:
                sep = "%0D%0A"
        if cut < 0:
            continue
        # the fresh header tail, byte-exact (lowercase %3a / %20 — the shape
        # the live targets accept after decoding and the fixture pins)
        new_val = rv[:cut] + sep + L3_HEADER_TAIL
        nurl = _swap_query_value(url, param, new_val)
        return {"status": "PLANNED", "requests": [
            _mk_req("header_injection", (req.get("method") or "GET").upper(), nurl,
                    dict(req.get("headers") or {}), req.get("body") or "",
                    expected_header=L3_HEADER_NAME, expected_value=L3_HEADER_VALUE)],
            "refusal_reason": ""}
    return _refuse("no CRLF-shaped proven vector on the finding's surface")


def _set_qparam(url, param, value):
    try:
        u = urllib.parse.urlsplit(url)
        qs = [(k, v) for k, v in urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
              if k != param]
        qs.append((param, value))
        return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path,
                                        urllib.parse.urlencode(qs), ""))
    except Exception:
        return url


def _plan_redirect(f, ctx, redirect_sink, redirect_param=None):
    param = (redirect_param or f.get("parameter") or "").split(",")[0].strip()
    base = f.get("url") or ""
    # build from the L0 redirect-verification entry (the proving entry whose
    # query already carries an off-site URL): it preserves the surface STATE
    # the redirect needs — live-measured on ginjuice: the linkback UI (the
    # location-assigning handler) only renders while a search is active, so a
    # bare ?back=<sink> page carries no redirect mechanism at all
    if ctx is not None:
        for _rid, req, _hay in _surface_entries(f, ctx):
            try:
                q = urllib.parse.urlsplit(req.get("url") or "").query or ""
            except Exception:
                continue
            if any(v.startswith(("http://", "https://", "//"))
                   for _k, v in urllib.parse.parse_qsl(q, keep_blank_values=True)):
                base = req.get("url") or base
                break
    url = _set_qparam(base, param, redirect_sink)
    return {"status": "PLANNED", "requests": [
        _mk_req("browser_redirect", "GET", url, {}, "",
                expected_landing=redirect_sink)], "refusal_reason": ""}


def _plan_xss_single(f, cls):
    param = (f.get("parameter") or "").split(",")[0].strip()
    url = _set_qparam(f.get("url") or "", param, _xss_payload(cls))
    label = "browser_exec" if cls == "xss_reflected" else "browser_exec_dom"
    return {"status": "PLANNED", "requests": [
        _mk_req(label, "GET", url, {}, "",
                expected_flag=XSS_FLAG[cls], expected_variant=XSS_VARIANT[cls])],
        "refusal_reason": ""}


def _plan_stored(f, ctx):
    param = (f.get("parameter") or "").split(",")[0].strip()
    render_url = ""
    for e in f.get("evidence") or []:
        if e.get("kind") == "stored_xss_surfaces":
            m = re.search(r"https?://\S+", e.get("detail") or "")
            if m:
                render_url = m.group(0)
                break
    if not render_url:
        return _refuse("no render surface recorded for the stored finding")
    ents = _finding_proving_entries(f, ctx)
    new_val = urllib.parse.quote_plus(_xss_payload("xss_stored"))
    # prefer a REAL-FORM entry (one that carries a submit-button field): the
    # WebForms postback only processes the comment when the button field rides
    # the body (live-measured: without it the POST is a silent no-op)
    def _has_submit(req):
        b = req.get("body") or ""
        names = [pair.split("=", 1)[0] for pair in b.split("&") if "=" in pair]
        return any(("btn" in n) or ("send" in n) or ("submit" in n) for n in names)
    ents = sorted(ents, key=lambda t: (0 if _has_submit(t[1]) else 1, t[0]))
    for _rid, req, _hay in ents:
        url = req.get("url") or ""
        body = req.get("body") or ""
        try:
            q = urllib.parse.urlsplit(url).query or ""
        except Exception:
            continue
        # body-param shape (POST forms, e.g. testaspnet Comments.aspx)
        rv = None
        carrier = ""
        if body.strip():
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    if urllib.parse.unquote_plus(k) == param:
                        rv = v
                        carrier = "body"
                        break
        # query-param shape (GET forms, e.g. gruyere saveprofile)
        if rv is None:
            rv = _raw_param(q, param)
            if rv is not None:
                carrier = "query"
        if rv is None:
            continue
        if carrier == "body":
            nbody = _swap_body_value(body, param, new_val)
            # hidden fields (__VIEWSTATE & friends) are refreshed LIVE by the
            # executor — they never belong to the planned bytes
            nbody = "&".join(p for p in nbody.split("&")
                             if not p.split("=", 1)[0].startswith("__"))
            nurl = url
            method = (req.get("method") or "POST").upper()
            hdrs = dict(req.get("headers") or {})
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            nurl = _swap_query_value(url, param, new_val)
            nbody = ""
            method = (req.get("method") or "GET").upper()
            hdrs = dict(req.get("headers") or {})
        return {"status": "PLANNED", "requests": [
            _mk_req("stored_resubmit", method, nurl, hdrs, nbody, expected_status=200),
            _mk_req("browser_exec_stored", "GET", render_url, {}, "",
                    expected_flag=XSS_FLAG["xss_stored"],
                    expected_variant=XSS_VARIANT["xss_stored"], render_url=render_url)],
            "refusal_reason": ""}
    return _refuse("no proven vector carrying the stored parameter on its surface")


def _plan_single(f, ctx, redirect_sink, origin_probe, cart_view="/cart", redirect_param=None):
    t = f.get("type") or ""
    if t == "sql_injection":
        return _plan_sql(f, ctx)
    if t == "xxe":
        return _plan_xxe(f, ctx)
    if t == "csrf":
        return _plan_csrf(f, ctx, origin_probe, cart_view)
    if t == "path_traversal":
        return _plan_trav(f, ctx)
    if t == "http_response_header_injection":
        return _plan_crlf(f, ctx)
    if t == "open_redirect":
        return _plan_redirect(f, ctx, redirect_sink, redirect_param)
    if t in ("xss_reflected", "xss_dom"):
        return _plan_xss_single(f, t)
    if t == "xss_stored":
        return _plan_stored(f, ctx)
    return {"status": "NOT_SAFE_TO_PROVE", "requests": [], "refusal_reason": NOT_SAFE_REASON}


def plan_impact_probes(report, *, redirect_sink=L3_REDIRECT_SINK,
                       origin_probe=L3_ORIGIN_PROBE, cart_view="/cart",
                       redirect_param=None):
    """Pure projection of one scan report into SAFE impact-probe plans.
    Zero requests, deterministic, never mutates the input."""
    ctx = apath._Ctx(report)
    plans = []
    by_finding = {}
    for f in sorted(ctx.findings, key=lambda x: x.get("id", "")):
        t = f.get("type") or ""
        if t not in SAFE_CLASSES and t not in NOT_SAFE_CLASSES:
            continue  # passive/banner context — not a capability claim, no L3 record
        res = _plan_single(f, ctx, redirect_sink, origin_probe, cart_view, redirect_param)
        pk = PROBE_KINDS.get(t, t + "_impact")
        p = {"path_id": _pid("L3P-", pk, f.get("id")),
             "probe_kind": pk, "findings": [f.get("id")],
             "title": _impact_title(pk, f),
             "status": res["status"], "refusal_reason": res.get("refusal_reason", ""),
             "requests": res.get("requests", []),
             "plan_detail": res.get("detail", {})}
        plans.append(p)
        by_finding[f.get("id")] = p
    # chains: only L2 chains whose bridge is VERIFIED (execution demonstrated);
    # an inferred bridge never yields a chain impact plan
    ap = apath.build_attack_paths(report)
    for cp in ap.get("paths", []):
        if not cp.get("hops") or cp.get("classification") != "VERIFIED":
            continue
        legs = []
        broken = ""
        for fid in cp.get("findings", []):
            leg = by_finding.get(fid)
            if leg is None or leg.get("status") != "PLANNED":
                broken = fid
                break
            legs.append({"probe_kind": leg["probe_kind"], "findings": leg["findings"],
                         "requests": leg["requests"], "path_id": leg["path_id"]})
        if broken:
            plans.append({"path_id": _pid("L3PC-", "chain", *cp.get("findings", [])),
                          "probe_kind": "chain_conjunction",
                          "findings": list(cp.get("findings", [])),
                          "title": _chain_title(cp), "status": "REFUSED",
                          "refusal_reason": (f"chain leg {broken} has no safe impact "
                                             "probe plan — the chain cannot be proven safely"),
                          "requests": [], "legs": [], "plan_detail": {}})
            continue
        plans.append({"path_id": _pid("L3PC-", "chain", *cp.get("findings", [])),
                       "probe_kind": "chain_conjunction",
                       "findings": list(cp.get("findings", [])),
                       "title": _chain_title(cp), "status": "PLANNED",
                       "refusal_reason": "", "requests": [], "legs": legs,
                       "plan_detail": {}})
    # deterministic sequential rids over the planned requests
    n = 0
    for p in plans:
        if p.get("status") != "PLANNED":
            continue
        for r in p.get("requests") or []:
            n += 1
            r["rid"] = f"pr-{n:04d}"
    planned = sum(1 for p in plans if p["status"] == "PLANNED")
    refused = sum(1 for p in plans if p["status"] == "REFUSED")
    not_safe = sum(1 for p in plans if p["status"] == "NOT_SAFE_TO_PROVE")
    return {
        "layer": SCANNER_LAYER, "target": report.get("target", ""),
        "run_id": report.get("run_id", ""),
        "redirect_sink": redirect_sink, "origin_probe": origin_probe,
        "cart_view": cart_view, "redirect_param": redirect_param,
        "path_plans": plans,
        "summary": {"total": len(plans), "planned": planned, "refused": refused,
                    "not_safe": not_safe, "requests": n,
                    "honesty": ("every planned request is a minimal benign probe from the "
                                "fail-closed safety registries; REFUSED and NOT_SAFE_TO_PROVE "
                                "name their reasons. Capability proven, not exploited — "
                                "أُثبتت القدرة، لم تُستغَل")},
    }


def _impact_title(pk, f):
    return f"{pk} at {apath._path_of(f.get('url', ''))} (param {f.get('parameter')}) — minimal benign proof"


def _chain_title(cp):
    return f"chain terminal impact — {cp.get('chain_rule', '')} ({' + '.join(cp.get('findings', []))})"


# ------------------------------------------------------------------ assessor
# RT-06 fix (audit-rb-1): the raw pattern
#   re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2,}", re.IGNORECASE)
# is quadratic on dot-less input: at every start position the greedy
# [a-z0-9-]* consumes the whole run, then backtracks char-by-char hunting the
# two mandatory dots — measured live: >5s on 50,001 chars (REDOS_CONFIRMED).
# The fix combines BOTH ordered options:
#   (A) total input cap of 65,536 chars before any matching, and
#   (B) linearization: a no-backtrack token pre-scan skips dot-less runs in
#       O(n) (a hostname match REQUIRES >=2 dots, so a dot-less token can
#       never match), and each dot-bearing token is bounded to 300-char
#       end-windows before the core pattern runs (RFC 1035/1123 hostname
#       max is 253 — longer runs are not hostnames).
_HOSTNAME_CORE = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){2,}", re.IGNORECASE)
_HOSTNAME_TOKEN = re.compile(r"[A-Za-z0-9.-]+")           # linear: single class, no backtracking
_HOSTNAME_MAX_INPUT = 65_536                               # option A cap
_HOSTNAME_MAX_TOKEN = 300                                  # RFC hostname bound + margin


class _BoundedHostnameRE:
    """Drop-in findall replacement: same extraction language on realistic
    bodies, linear time on hostile ones. Honest boundary: matches living
    ENTIRELY inside a >300-char dot-bearing run beyond both end-windows are
    not extracted (they are not valid hostnames by RFC length anyway)."""

    def findall(self, s):
        if not s:
            return []
        if len(s) > _HOSTNAME_MAX_INPUT:
            s = s[:_HOSTNAME_MAX_INPUT]
        out = []
        for tok in _HOSTNAME_TOKEN.findall(s):
            if "." not in tok:
                continue                       # linear skip: no dots, no match possible
            if len(tok) <= _HOSTNAME_MAX_TOKEN:
                out.extend(_HOSTNAME_CORE.findall(tok))
            else:
                head = tok[:_HOSTNAME_MAX_TOKEN]
                tail = tok[-_HOSTNAME_MAX_TOKEN:]
                out.extend(_HOSTNAME_CORE.findall(head))
                out.extend(_HOSTNAME_CORE.findall(tail))
        return out


_HOSTNAME_RE = _BoundedHostnameRE()
_WORD_RE = re.compile(r"\b[A-Za-z0-9]{4,}\b")
BROWSER_LABELS = frozenset({"browser_exec", "browser_exec_dom",
                             "browser_exec_stored", "browser_redirect"})


def _size(entry):
    resp = entry.get("response") or {}
    try:
        return int(resp.get("size") or len(resp.get("body") or ""))
    except Exception:
        return len(resp.get("body") or "")


def _body(entry):
    return str((entry.get("response") or {}).get("body") or "")


def _headers(entry):
    return dict((entry.get("response") or {}).get("headers") or {})


def _match_entries(requests, journal):
    """Match journal entries to planned requests by (label, url[, body]).
    stored_resubmit is body-exempt on purpose: its hidden fields
    (__VIEWSTATE & friends) are refreshed LIVE by the executor and never
    belong to the planned bytes — the payload-pair presence is confirmed
    separately by the kind's own logic."""
    out = {}
    for r in requests or []:
        body_exempt = r.get("label") == "stored_resubmit"
        for k in sorted(journal.keys(), key=str):
            e = journal.get(k)
            if not isinstance(e, dict):
                continue
            if e.get("label") != r.get("label"):
                continue
            req = e.get("request") or {}
            if (req.get("method") or "").upper() != (r.get("method") or "GET").upper():
                continue
            if (req.get("url") or "") != (r.get("url") or ""):
                continue
            if not body_exempt and (req.get("body") or "") != (r.get("body") or ""):
                continue
            out[r["label"]] = (k, e)
            break
    return out


def _ev(ref, entry, excerpt):
    return {"kind": "probe", "ref": str(ref), "excerpt": _b(excerpt)}


def _inferred_no_records():
    return {"status": "INFERRED",
            "reason": ("impact probes were not recorded in this run — no fresh live "
                       "proof exists; the capability remains inferred from the verified "
                       "defect (L2), never claimed as proven"),
            "detail": {}, "evidence": []}


def _probe_failed(reason, detail):
    return {"status": "PROBE_FAILED", "reason": reason, "detail": detail, "evidence": []}


def _sep(a, b):
    return abs(a - b) > max(200, 0.25 * min(a, b))


def _assess_requests(probe_kind, requests, journal, report, ctx=None):
    """Assess one probe (single plan or chain leg). Returns
    {status, reason, detail, evidence}."""
    got = _match_entries(requests, journal)
    if not got:
        return _inferred_no_records()

    if probe_kind == "sql_version_oracle":
        need = ("control_true", "control_false", "version_true", "version_false")
        missing = [lb for lb in need if lb not in got]
        if missing:
            return _probe_failed("probe records incomplete — " + ", ".join(missing),
                                 {"missing_labels": missing})
        ct, cf = _size(got["control_true"][1]), _size(got["control_false"][1])
        vt, vf = _size(got["version_true"][1]), _size(got["version_false"][1])
        if not _sep(ct, cf) or not _sep(vt, vf):
            return _probe_failed(
                "the boolean oracle did not separate on this run (measured sizes below) "
                "— honest failure, never a fake proof",
                {"control_true_size": ct, "control_false_size": cf,
                 "version_true_size": vt, "version_false_size": vf,
                 "control_separated": _sep(ct, cf), "version_separated": _sep(vt, vf)})
        version_char = None
        digit_detail = {}
        for lb, (k, e) in sorted(got.items()):
            if not lb.startswith("version_digit_"):
                continue
            ds = _size(e)
            digit_detail[lb] = ds
            if abs(ds - ct) < abs(ds - cf):
                version_char = lb.rsplit("_", 1)[-1]
        detail = {"control_true_size": ct, "control_false_size": cf,
                  "version_true_size": vt, "version_false_size": vf,
                  "version_char": version_char, "digit_probes": digit_detail}
        ev = [_ev(got[lb][0], got[lb][1], _body(got[lb][1])[:60] or (got[lb][1].get("request") or {}).get("url", "")[:60])
              for lb in need]
        if version_char:
            lb = f"version_digit_{version_char}"
            if lb in got:
                ev.append(_ev(got[lb][0], got[lb][1], _body(got[lb][1])[:60]))
        return {"status": "VERIFIED", "reason": "", "detail": detail, "evidence": ev}

    if probe_kind == "xxe_file_read":
        if "xxe_control" not in got or "xxe_file_read" not in got:
            return _probe_failed("probe records incomplete",
                                 {"missing_labels": [lb for lb in ("xxe_control", "xxe_file_read") if lb not in got]})
        ctl, rd = got["xxe_control"][1], got["xxe_file_read"][1]
        cb, rb = _body(ctl), _body(rd)
        known = set(_HOSTNAME_RE.findall(cb))
        extracted = [h for h in _HOSTNAME_RE.findall(rb) if h not in known]
        if not extracted:
            return _probe_failed("the file-read response carried no hostname-class "
                                 "content beyond the control (blind on this run) — "
                                 "honest failure, never a fake proof",
                                 {"control_body_len": len(cb), "read_body_len": len(rb),
                                  "control_excerpt": _b(cb, 60), "read_excerpt": _b(rb, 60)})
        token = extracted[0]
        return {"status": "VERIFIED", "reason": "", "detail": {
            "file": "etc/hostname", "extracted": token,
            "control_body_len": len(cb), "read_body_len": len(rb)},
            "evidence": [_ev(got["xxe_file_read"][0], rd, token),
                         _ev(got["xxe_control"][0], ctl, _b(cb, 60))]}

    if probe_kind == "csrf_own_session_state_change":
        need = ("session_mint", "cart_baseline", "cross_origin_state_change", "cart_after")
        missing = [lb for lb in need if lb not in got]
        if missing:
            return _probe_failed("probe records incomplete — " + ", ".join(missing),
                                 {"missing_labels": missing})
        sm, cb_e = got["session_mint"][1], got["cart_baseline"][1]
        co, ca = got["cross_origin_state_change"][1], got["cart_after"][1]
        base_body, after_body = _body(cb_e), _body(ca)
        co_status = int((co.get("response") or {}).get("status") or 0)
        base_words = set(_WORD_RE.findall(base_body))
        new_words = [w for w in _WORD_RE.findall(after_body) if w not in base_words]
        state_changed = bool(new_words) and after_body != base_body and 200 <= co_status < 300
        if not state_changed:
            return _probe_failed("the hostile-origin state change did not materialize "
                                 "in our own session (measured below) — honest failure",
                                 {"cross_origin_status": co_status,
                                  "baseline_excerpt": _b(base_body, 60),
                                  "after_excerpt": _b(after_body, 60),
                                  "new_state_tokens": []})
        first_new = max([w for w in new_words if w in after_body] or new_words, key=len)
        return {"status": "VERIFIED", "reason": "", "detail": {
            "origin": ((co.get("request") or {}).get("headers") or {}).get("Origin",
                    ((got["cross_origin_state_change"][1].get("request") or {}).get("url") or "")[:40]),
            "cross_origin_status": co_status, "state_changed": True,
            "new_state_tokens": sorted(set(new_words))[:8]},
            "evidence": [_ev(got["cross_origin_state_change"][0], co,
                             _b((co.get("request") or {}).get("body") or "", 80)),
                         _ev(got["cart_after"][0], ca, first_new),
                         _ev(got["cart_baseline"][0], cb_e, _b(base_body, 60))]}

    if probe_kind == "traversal_file_read":
        if "file_read" not in got:
            return _probe_failed("probe records incomplete", {"missing_labels": ["file_read"]})
        fr = got["file_read"][1]
        fb = _body(fr)
        fst = int((fr.get("response") or {}).get("status") or 0)
        if not (200 <= fst < 300):
            return _probe_failed("the fresh read returned an error page, not file "
                                 "content — honest failure (never a fake proof)",
                                 {"status": fst, "resp_len": len(fb),
                                  "resp_excerpt": _b(fb, 60)})
        orig = _original_traversal_body(report, ctx) if (report or {}) else ""
        shared = [ln.strip() for ln in (orig or "").splitlines()
                  if len(ln.strip()) >= 8 and ln.strip() and ln.strip() in fb]
        if not shared:
            return _probe_failed("the fresh read did not reproduce the original proving "
                                 "content (no shared marker) — honest failure",
                                 {"resp_len": len(fb), "resp_excerpt": _b(fb, 60),
                                  "shared_markers": []})
        return {"status": "VERIFIED", "reason": "", "detail": {
            "file": ((fr.get("request") or {}).get("url") or "")[-60:],
            "shared_markers": shared[:4]},
            "evidence": [_ev(got["file_read"][0], fr, shared[0])]}

    if probe_kind == "header_split_proof":
        if "header_injection" not in got:
            return _probe_failed("probe records incomplete", {"missing_labels": ["header_injection"]})
        hi = got["header_injection"][1]
        hs = _headers(hi)
        name, want = L3_HEADER_NAME, L3_HEADER_VALUE
        val = ""
        for k, v in hs.items():
            if str(k).lower() == name:
                val = str(v)
                break
        if not (val == want or val.startswith(want)):
            return _probe_failed("the fresh header name was not split into the response "
                                 "headers (measured below) — honest failure",
                                 {"expected_header": name, "expected_value": want,
                                  "observed_value": val,
                                  "response_headers": sorted(str(k) for k in hs)[:12]})
        return {"status": "VERIFIED", "reason": "", "detail": {
            "header": name, "value": val},
            "evidence": [_ev(got["header_injection"][0], hi, val)]}

    if probe_kind in ("xss_browser_execution",):
        e = None
        for lb in ("browser_exec", "browser_exec_dom"):
            if lb in got:
                e = got[lb][1]
                used = lb
                break
        if e is None:
            return _probe_failed("probe records incomplete",
                                 {"missing_labels": ["browser_exec", "browser_exec_dom"]})
        b = (e.get("response") or {}).get("browser") or {}
        want = _first_expected(requests, "expected_flag", "")
        if not b.get("fired") or b.get("flag_value") != want:
            return _probe_failed("the browser did not execute the planned canary "
                                 "(measured below) — honest failure, never a fake proof",
                                 {"fired": bool(b.get("fired")),
                                  "observed_flag": b.get("flag_value"),
                                  "expected_flag": want})
        return {"status": "VERIFIED", "reason": "", "detail": {
            "variant": b.get("variant"), "flag": b.get("flag_value")},
            "evidence": [_ev(got[used][0], e, b.get("flag_value") or "")]}

    if probe_kind in ("xss_stored_persistence",):
        need = ("stored_resubmit", "browser_exec_stored")
        missing = [lb for lb in need if lb not in got]
        if missing:
            return _probe_failed("probe records incomplete — " + ", ".join(missing),
                                 {"missing_labels": missing})
        sr, be = got["stored_resubmit"][1], got["browser_exec_stored"][1]
        sr_status = int((sr.get("response") or {}).get("status") or 0)
        b = (be.get("response") or {}).get("browser") or {}
        want = _first_expected(requests, "expected_flag", XSS_FLAG["xss_stored"])
        # the planned payload VALUE must ride the request the executor sent
        # (url for GET forms, body for POST forms); hidden fields never count
        payload_val = next((urllib.parse.quote_plus(_xss_payload("xss_stored"))
                            for r in requests or [] if r.get("label") == "stored_resubmit"
                            for _x in [1]), "")
        sent = ((sr.get("request") or {}).get("url", "") + " " +
                ((sr.get("request") or {}).get("body") or ""))
        payload_rides = bool(payload_val) and payload_val in sent
        if not (200 <= sr_status < 300) or not payload_rides or \
                not b.get("fired") or b.get("flag_value") != want:
            return _probe_failed("the stored canary did not persist AND execute "
                                 "(measured below) — honest failure",
                                 {"resubmit_status": sr_status, "fired": bool(b.get("fired")),
                                  "payload_rides_the_request": payload_rides,
                                  "observed_flag": b.get("flag_value"), "expected_flag": want})
        return {"status": "VERIFIED", "reason": "", "detail": {
            "flag": b.get("flag_value"), "variant": b.get("variant"),
            "resubmit_status": sr_status},
            "evidence": [_ev(got["stored_resubmit"][0], sr,
                             _b((sr.get("request") or {}).get("body") or "", 80)),
                         _ev(got["browser_exec_stored"][0], be, b.get("flag_value") or "")]}

    if probe_kind == "open_redirect_navigation":
        lb = "browser_redirect"
        if lb not in got:
            return _probe_failed("probe records incomplete", {"missing_labels": [lb]})
        e = got[lb][1]
        b = (e.get("response") or {}).get("browser") or {}
        want = _first_expected(requests, "expected_landing", "")
        landed = str(b.get("landed_url") or "")
        if not b.get("navigated_off_site") or (want and landed != want):
            return _probe_failed("the browser did not land on the off-site sink "
                                 "(measured below) — honest failure",
                                 {"navigated_off_site": bool(b.get("navigated_off_site")),
                                  "landed_url": landed, "expected_landing": want})
        return {"status": "VERIFIED", "reason": "", "detail": {"landed_url": landed},
            "evidence": [_ev(got[lb][0], e, landed)]}

    # unknown kind: never verified by description
    return _inferred_no_records()


def _first_expected(requests, key="expected_flag", default=""):
    for r in requests or []:
        if r.get(key):
            return r[key]
    return default


def _original_traversal_body(report, ctx):
    """The finding's ORIGINAL proving response body (the L0-certified read)."""
    try:
        if ctx is None:
            ctx = apath._Ctx(report)
        for f in ctx.findings:
            if f.get("type") == "path_traversal":
                cands = [(rid, req) for rid, req, _hay in _surface_entries(f, ctx)
                         if ".." in urllib.parse.unquote_plus(
                             f"{req.get('url', '')} {req.get('body', '')}")]
                cands.sort(key=lambda t: (
                    0 if 200 <= int(((ctx.entry(t[0]) or {}).get("response") or {})
                                    .get("status") or 0) < 300 else 1, t[0]))
                if cands:
                    return _body(ctx.entry(cands[0][0]))
    except Exception:
        pass
    return ""


def assess_impacts(report, plan, probe_journal):
    """Pure assessment of one probe journal against a plan. VERIFIED only with
    confirming fresh records; missing records -> INFERRED; non-confirming
    records -> PROBE_FAILED with the measured numbers. Zero tolerance."""
    impacts = []
    ctx = apath._Ctx(report) if report else None
    for p in plan.get("path_plans", []):
        rec = {"path_id": p.get("path_id"), "probe_kind": p.get("probe_kind"),
               "findings": list(p.get("findings") or []), "title": p.get("title", "")}
        if p.get("status") == "NOT_SAFE_TO_PROVE":
            rec.update({"status": "NOT_SAFE_TO_PROVE", "reason": p.get("refusal_reason") or NOT_SAFE_REASON,
                        "detail": {}, "evidence": []})
        elif p.get("status") == "REFUSED":
            rec.update({"status": "REFUSED", "reason": p.get("refusal_reason") or "refused",
                        "detail": {}, "evidence": []})
        elif p.get("probe_kind") == "chain_conjunction":
            legs = []
            failed = []
            for leg in p.get("legs") or []:
                r = _assess_requests(leg.get("probe_kind"), leg.get("requests"),
                                     probe_journal, report, ctx)
                legs.append({"probe_kind": leg.get("probe_kind"), "status": r["status"]})
                if r["status"] != "VERIFIED":
                    failed.append(leg.get("probe_kind"))
                if r["status"] == "VERIFIED":
                    rec.setdefault("evidence", []).extend(r.get("evidence") or [])
            rec["detail"] = {"legs": legs}
            if failed or not legs:
                rec["status"] = "INFERRED"
                rec["reason"] = ("terminal impact not proven: the " + " and ".join(failed or ["chain"])
                                 + " leg(s) did not verify fresh in this run — the whole "
                                   "chain stays INFERRED (weakest-link rule, same as L2)")
                if not rec.get("evidence"):
                    rec["evidence"] = []
            else:
                rec["status"] = "VERIFIED"
                rec["reason"] = ""
        else:
            r = _assess_requests(p.get("probe_kind"), p.get("requests"),
                                 probe_journal, report, ctx)
            rec.update(r)
        impacts.append(rec)
    verified = sum(1 for i in impacts if i["status"] == "VERIFIED")
    inferred = sum(1 for i in impacts if i["status"] == "INFERRED")
    failed = sum(1 for i in impacts if i["status"] == "PROBE_FAILED")
    not_safe = sum(1 for i in impacts if i["status"] == "NOT_SAFE_TO_PROVE")
    refused = sum(1 for i in impacts if i["status"] == "REFUSED")
    return {
        "layer": SCANNER_LAYER, "target": plan.get("target", ""),
        "run_id": plan.get("run_id", ""),
        "impacts": impacts,
        "summary": {"total": len(impacts), "verified": verified, "inferred": inferred,
                    "probe_failed": failed, "not_safe": not_safe, "refused": refused,
                    "honesty": ("an impact is VERIFIED only via a confirming fresh live "
                                "probe from this run; reasoned-only stays INFERRED; "
                                "attempted-but-unconfirmed is PROBE_FAILED with the "
                                "measured numbers. Capability proven, not exploited — "
                                "أُثبتت القدرة، لم تُستغَل")},
    }


# ------------------------------------------------------------------ live executor
def execute_impact_probes(plan, engine, browser=None):
    """Issue every PLANNED request live and return the probe journal
    {rid: entry}. The engine's cookie jar owns the session — every plan runs
    in OUR OWN session by construction. Browser probes drive a real headless
    browser; when the browser layer is unavailable the record says so honestly
    (the assessor then degrades to PROBE_FAILED, never to VERIFIED)."""
    import time

    from .core import Endpoint, Parameter, ParamLocation
    from .http_engine import RequestMutation

    journal = {}
    pw = None

    def _browser_page():
        nonlocal pw
        if pw is None:
            from playwright.sync_api import sync_playwright
            pw = {}
            p = sync_playwright().start()
            b = p.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"])
            pw = {"p": p, "b": b, "ctx": b.new_context()}
            # R15-4: impact's private playwright instance is a WEDGE POINT
            # exactly like BrowserEngine's (same _sync dispatch machinery) —
            # it must join the shared driver registry or the SIGINT sweep
            # would never see it.
            try:
                from .browser import register_driver
                _c = getattr(getattr(p, "_impl_obj", None), "_connection", None)
                _d = getattr(getattr(_c, "_transport", None), "_proc", None)
                if _d is not None:
                    register_driver(_d)
            except Exception:  # noqa: BLE001 — registry is best-effort
                pass
        return pw["ctx"].new_page()

    try:
        for p in plan.get("path_plans", []):
            if p.get("status") != "PLANNED":
                continue
            for r in p.get("requests") or []:
                rid = r.get("rid") or f"pr-{len(journal) + 1:04d}"
                t0 = time.time()
                if r.get("label") in BROWSER_LABELS:
                    entry = _exec_browser(r, _browser_page, engine)
                else:
                    entry = _exec_http(r, engine, Endpoint, Parameter,
                                       ParamLocation, RequestMutation)
                entry["label"] = r.get("label")
                entry["t"] = round(t0 + 0.5, 3)
                journal[rid] = entry
    finally:
        if pw:
            try:
                pw["ctx"].close()
                pw["b"].close()
                pw["p"].stop()
            except Exception:
                pass
    return journal


def _exec_http(r, engine, Endpoint, Parameter, ParamLocation, RequestMutation):
    import re as _re
    u = urllib.parse.urlsplit(r["url"])
    q = urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
    body = r.get("body") or ""
    # WebForms real-form replay: hidden fields are refreshed from a LIVE GET
    # (a stale __VIEWSTATE is rejected silently — live-measured on testaspnet)
    if r.get("label") == "stored_resubmit" and (r.get("method") or "GET").upper() == "POST":
        page = engine.send(_mk_probe_mutation(r, Endpoint, Parameter, ParamLocation,
                                              RequestMutation, method="GET", body=""))
        html = (page.body or "") if page else ""
        fresh = []
        for m0 in _re.finditer(r"<input[^>]*type=[\"']hidden[\"'][^>]*>", html or "", _re.I):
            tag = m0.group(0)
            n = _re.search(r"name=[\"']([^\"]+)[\"']", tag)
            v = _re.search(r"value=[\"']([^\"]*)[\"']", tag)
            if n:
                name = n.group(1)
                val = (v.group(1) if v else "")
                fresh.append(f"{urllib.parse.quote_plus(name)}="
                             f"{urllib.parse.quote_plus(val)}")
        m0 = _re.search(r"<input[^>]*name=[\"']([^\"]*(?:btn|send|submit)[^\"]*)[\"'][^>]*value=[\"']([^\"]*)[\"']", html or "", _re.I)
        if m0 and not any(m0.group(1) == p.split("=", 1)[0] for p in body.split("&") if "=" in p):
            fresh.append(f"{urllib.parse.quote_plus(m0.group(1))}="
                         f"{urllib.parse.quote_plus(m0.group(2))}")
        if fresh:
            body = "&".join(fresh + [body]) if body else "&".join(fresh)
    m = _mk_probe_mutation(r, Endpoint, Parameter, ParamLocation, RequestMutation,
                           body=body)
    resp = engine.send(m)
    rbody = resp.body or ""
    return {"request": {"method": (r.get("method") or "GET").upper(),
                        "url": r["url"], "headers": dict(r.get("headers") or {}),
                        "body": body},
            "response": {"status": int(resp.status or 0),
                         "headers": dict(resp.headers or {}),
                         "body": rbody[:4000], "size": len(rbody),
                         "redirect_chain": [list(h) for h in (resp.redirect_chain or [])]}}


def _mk_probe_mutation(r, Endpoint, Parameter, ParamLocation, RequestMutation,
                       method=None, body=None):
    u = urllib.parse.urlsplit(r["url"])
    q = urllib.parse.parse_qsl(u.query or "", keep_blank_values=True)
    ep = Endpoint(url=urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "", "")),
                  method=(method or r.get("method") or "GET").upper(),
                  parameters=[Parameter(n, ParamLocation.QUERY, v) for n, v in q],
                  headers=dict(r.get("headers") or {}))
    return RequestMutation(endpoint=ep, method=(method or r.get("method") or "GET").upper(),
                           body_override=(body if body is not None else (r.get("body") or "")),
                           extra_headers=dict(r.get("headers") or {}))


def _exec_browser(r, page_factory, engine):
    url = r["url"]
    try:
        page = page_factory()
        resp = page.goto(url, wait_until="load", timeout=20000)
        page.wait_for_timeout(900)
        status = int(resp.status) if resp else 0
        if r.get("label") == "browser_redirect":
            def _offsite(u):
                try:
                    return (urllib.parse.urlsplit(u).hostname or "") != \
                           (urllib.parse.urlsplit(url).hostname or "")
                except Exception:
                    return False
            if not _offsite(page.url):
                # exercise the page's OWN client-redirect mechanism once: the
                # linkback pattern (an anchor whose handler assigns location).
                # The anchor itself usually carries no class — match the
                # onclick contract, then the wrapper div, then give up.
                try:
                    clicked = page.evaluate(
                        "() => { const a = document.querySelector(\"a[onclick*='location']\")"
                        " || document.querySelector(\"div[class*=linkback] a\")"
                        " || document.querySelector(\"a[class*=linkback]\");"
                        " if (a) { a.click(); return true; } return false; }")
                    if clicked:
                        page.wait_for_timeout(900)
                except Exception:
                    pass
            landed = page.url
            browser = {"navigated_off_site": bool(_offsite(landed)),
                       "landed_url": landed}
        else:
            flag = page.evaluate("(window.__BURHAN_XSS__ || '')")
            want = r.get("expected_flag") or ""
            browser = {"fired": bool(flag) and flag == want,
                       "flag_value": flag, "variant": r.get("expected_variant", ""),
                       "flag_expected": want}
        page.close()
        return {"request": {"method": "GET", "url": url, "headers": {}, "body": ""},
                "response": {"status": status, "headers": {}, "body": "",
                             "size": 0, "browser": browser}}
    except Exception as e:
        return {"request": {"method": "GET", "url": url, "headers": {}, "body": ""},
                "response": {"status": 0, "headers": {}, "body": "", "size": 0,
                             "browser": {"error": f"{type(e).__name__}: {e}"[:160]}}}


# ------------------------------------------------------------------ doctor fixture + check
def _doctor_fixture():
    """Minimal offline report for the doctor check: one SQLi (proven, boolean
    vector in the journal), one CSRF (proven hostile-origin), one
    command_injection (no safe proof exists)."""
    def F(fid, ftype, url, param, method="GET", body=""):
        return {"id": fid, "type": ftype, "severity": "high", "status": "verified",
                "confidence": 0.9, "method": method, "url": url, "parameter": param,
                "evidence": [{"kind": "response_diff", "detail": "differential"}],
                "verification": {"method": "oracle:replay-2round", "passed": True,
                                 "confidence": 0.9, "rounds": 2, "notes": ""},
                "run_id": "run-l3doc", "risk": 70,
                "impact": {"grade": "proven", "statement": "s", "safe_proof": "-",
                           "evidence_chain": {"request": f"{method} {url}", "parameter": param,
                                              "evidence_kinds": ["response_diff"],
                                              "out_of_band": False,
                                              "verification": "oracle:replay-2round",
                                              "verification_passed": True}}}
    journal = {
        "req-901": {"request": {"method": "GET", "url": "http://l3doc.test/?q=1%20AND%201%3D1",
                                "path": "/", "headers": {}, "body": ""},
                    "response": {"status": 200, "headers": {}, "body": "A" * 900}},
        "req-902": {"request": {"method": "GET", "url": "http://l3doc.test/?q=1%20AND%201%3D2",
                                "path": "/", "headers": {}, "body": ""},
                    "response": {"status": 200, "headers": {}, "body": "B" * 500}},
        "req-903": {"request": {"method": "POST", "url": "http://l3doc.test/cart",
                                "path": "/cart", "headers": {"Origin": "https://csrf-probe.example"},
                                "body": "productId=1&quantity=1"},
                    "response": {"status": 200, "headers": {}, "body": "ok"}},
    }
    return {"run_id": "run-l3doc", "seed": "s", "scanner": "burhan-core/4.4.0",
            "target": "http://l3doc.test",
            "stats": {"request_journal": journal, "digital_twin": {},
                      "action_matrix": {"identities": [{"name": "anonymous", "role": "anonymous"}],
                                        "matrix": {}}},
            "findings": [
                F("F-dsql", "sql_injection", "http://l3doc.test/", "q"),
                F("F-dcsrf", "csrf", "http://l3doc.test/cart", "productId, quantity", "POST"),
                F("F-dcmd", "command_injection", "http://l3doc.test/ping", "host")],
            "rejected_candidates": [], "unverified_candidates": []}


def doctor_check():
    """(ok, detail) for the orchestrator doctor: the layer must plan safely
    (allowlisted material only), refuse honestly, and never verify without a
    confirming fresh probe record."""
    rep = _doctor_fixture()
    plan = plan_impact_probes(rep)
    a = assess_impacts(rep, plan, {})
    s, as_ = plan["summary"], a["summary"]
    ok = (s["planned"] >= 2 and s["not_safe"] >= 1
          and as_["verified"] == 0
          and all(i.get("reason") for i in a["impacts"] if i["status"] == "INFERRED")
          and any(i["status"] == "NOT_SAFE_TO_PROVE" for i in a["impacts"]))
    return ok, (f"L3 active: {s['planned']} planned / {s['refused']} refused / "
                f"{s['not_safe']} not-safe-to-probe; empty probe journal -> "
                f"{as_['verified']} verified (honest register live)")


# ------------------------------------------------------------------ human report
def write_report(assessment, plan, probe_journal, out_path):
    """Markdown evidence report — every VERIFIED impact with its cited probe
    records (the L2 discipline: literal slices, zero tolerance)."""
    s = assessment["summary"]
    lines = [f"# L3 Proven Real Impact — {assessment.get('target', '')}",
             f"run `{assessment.get('run_id', '')}` — layer {SCANNER_LAYER}",
             "",
             f"- impacts: {s['total']} total / **{s['verified']} VERIFIED** / "
             f"{s['inferred']} INFERRED / {s['probe_failed']} PROBE_FAILED / "
             f"{s['not_safe']} NOT_SAFE_TO_PROVE / {s['refused']} REFUSED",
             f"- safety ceiling: capability proven, not exploited — أُثبتت القدرة، لم تُستغَل",
             ""]
    for i in assessment["impacts"]:
        lines.append(f"## {i['probe_kind']} — {i['status']}")
        lines.append(f"- path `{i['path_id']}` findings {i['findings']} — {i['title']}")
        if i.get("reason"):
            lines.append(f"- reason: {i['reason']}")
        if i.get("detail"):
            lines.append(f"- detail: `{json.dumps(i['detail'], ensure_ascii=False)[:400]}`")
        for e in i.get("evidence") or []:
            ent = (probe_journal or {}).get(e["ref"])
            if ent is None:
                lines.append(f"- evidence [{e['kind']}] {e['ref']}: {e['excerpt']!r} "
                             "(probe journal entry)")
            else:
                req = ent.get("request") or {}
                resp = ent.get("response") or {}
                lines.append(f"- evidence [{e['kind']}] {e['ref']}: {e['excerpt']!r}")
                lines.append(f"  - probe: {(req.get('method') or '')} {req.get('url', '')} "
                             f"body={ (req.get('body') or '')[:90]!r}")
                lines.append(f"  - response: status {resp.get('status')} "
                             f"body={ (resp.get('body') or '')[:90]!r}")
        lines.append("")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return out_path

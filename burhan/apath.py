"""Burhan v4.3.0 — Attack Path Intelligence (L2).

The layer ABOVE the hardened engine (L0, v4.2.3 detectors + verifiers) and
the Security Digital Twin (L1, twin.py). L0 answers "is THIS input
injectable" one finding at a time; L1 fuses the scan into a knowledge graph.
L2 answers the question a finding list cannot: WHICH COMPLETE ATTACK PATHS
does the evidence actually support — strung through the seven links

    Identity -> Entry -> Action -> Object -> Authorization -> State -> Impact

THE DECISIVE RULE (supervisor directive, 2026-10-04 — never compromise it):
    A path equals its weakest link. EVERY link must trace to VERIFIED
    evidence — a verified finding, its raw request-journal entry, or a scan
    artifact (twin / action matrix). If ANY link is inferred or assumed,
    the WHOLE path is classified INFERRED, never VERIFIED, and the weak
    links are named. An unproven chain is never presented as proof. This is
    the same no-hallucination discipline the engine applies to findings.

Everything here is a PROJECTION of scan artifacts: build_attack_paths()
is a pure function over the serialized scan report (findings + request
journal + twin stats + action matrix). Zero requests. Fully deterministic:
same input -> byte-identical output. No module below this file is imported
except stdlib — the layer cannot perturb the engine, and the engine's
verdicts cannot be altered by it.

Evidence kinds a link may cite:
    finding       -> ref: finding id,        excerpt: evidence detail / verification
    journal       -> ref: request id,        excerpt: literal slice of the raw request/response
    twin          -> ref: twin stats key,    excerpt: the matching row
    scan_artifact -> ref: stats key,         excerpt: the artifact value
"""
from __future__ import annotations

import hashlib
import json
import urllib.parse

SCANNER_LAYER = "burhan-apath/4.3.0"

# The seven links, in the order the supervisor's chain defines them.
PATH_SLOTS = ("identity", "entry", "action", "object",
              "authorization", "state", "impact")

# Vulnerability classes that can SEED a path (an attacker pathway). Passive
# context classes (banner/header-absence/version disclosure) never seed —
# they annotate paths as verified mitigation-absence facts instead.
SEED_CLASSES = frozenset({
    "sql_injection", "nosql_injection", "xss_reflected", "xss_dom", "xss_stored",
    "path_traversal", "xxe", "ssrf", "command_injection", "ssti", "csrf",
    "jwt_security", "host_header_injection", "http_response_header_injection",
    "open_redirect", "idor_bola", "vertical_privilege_escalation",
    "workflow_state_bypass", "authorization_bypass",
})
XSS_CLASSES = frozenset({"xss_reflected", "xss_dom", "xss_stored"})
# banner findings whose "missing: a, b" evidence names absent mitigations
MITIGATION_SOURCE_CLASS = "missing_security_headers"

_TOKEN_FIELD_HINTS = ("csrf", "token", "nonce", "authenticity",
                      "requestverification")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ------------------------------------------------------------------ helpers
def _b(s, n=120):
    """Bound an excerpt. A truncated prefix is still a literal slice of the
    raw artifact, so every excerpt stays substring-verifiable."""
    s = str(s or "")
    return s[:n]


def _host(url):
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def _path_of(url):
    return urllib.parse.urlsplit(url).path or "/"


def _params_of(finding):
    return [p.strip() for p in (finding.get("parameter") or "").split(",") if p.strip()]


def _ev(kind, ref, excerpt):
    return {"kind": kind, "ref": str(ref), "excerpt": _b(excerpt)}


def _finding_ev(f, excerpt=None):
    """Cite the finding itself with a real slice of its own record."""
    if excerpt is None:
        evs = f.get("evidence") or []
        excerpt = (evs[0].get("detail") if evs else
                   (f.get("verification") or {}).get("method") or f.get("type"))
    return _ev("finding", f.get("id"), excerpt)


def _cookie_names(cookie_header):
    if not cookie_header:
        return []
    out = []
    for part in cookie_header.split(";"):
        if "=" in part:
            out.append(part.split("=", 1)[0].strip())
    return [c for c in out if c]


def _form_fields(body):
    """Field names of an urlencoded body (deterministic, order-preserving)."""
    if not body:
        return []
    names = []
    for pair in body.split("&"):
        if "=" in pair:
            names.append(pair.split("=", 1)[0])
    return names


# ------------------------------------------------------------------ journal context
def _hay_relevance(ftype, hay):
    """Type-aware preference: a SQLi path must cite the boolean-probe request,
    not a traversal probe that happened to hit the same surface. The raw hay
    (url + body) is unquoted before matching so encoded payloads still score."""
    h = urllib.parse.unquote_plus(hay or "")
    if ftype == "sql_injection":
        if " and 1=" in f" {h.lower()} " or " or 1=" in f" {h.lower()} ":
            return 4
        if "'" in h or "%27" in (hay or ""):
            return 2
        return 0
    if ftype in XSS_CLASSES:
        return 3 if "burhan" in h.lower() else 0
    if ftype == "path_traversal":
        return 3 if ".." in h else 0
    if ftype == "csrf":
        return 3 if "origin" in (hay or "").lower() else 0
    if ftype == "xxe":
        return 3 if "<!entity" in h.lower() or "SYSTEM" in h else 0
    return 1


class _Ctx:
    """Per-report context: journal + twin + action matrix, pre-indexed."""

    def __init__(self, report):
        stats = (report.get("stats") or {})
        self.journal = stats.get("request_journal") or {}
        self.twin = stats.get("digital_twin") or {}
        self.action_matrix = stats.get("action_matrix") or {}
        self.entities = self.twin.get("entity_inventory") or []
        self.findings = [f for f in (report.get("findings") or [])
                         if f.get("status") == "verified"]
        self.banner = [f for f in self.findings
                       if f.get("type") == MITIGATION_SOURCE_CLASS]
        # sort journal ids once — every later selection stays deterministic
        self.journal_ids = sorted(self.journal.keys())

    # ---- proving entries: raw requests that exercised the finding's surface
    def proving_entries(self, f):
        ftype = f.get("type") or ""
        path, method = _path_of(f.get("url", "")), (f.get("method") or "GET").upper()
        params = _params_of(f)
        render_paths = set()
        for e in f.get("evidence") or []:
            if e.get("kind") == "stored_xss_surfaces":
                for url in (e.get("detail") or "").split():
                    if url.startswith("http"):
                        render_paths.add(_path_of(url))
        exact, loose, render = [], [], []
        for rid in self.journal_ids:
            entry = self.journal[rid]
            req = entry.get("request") or {}
            rpath, rmethod = _path_of(req.get("url", "")), (req.get("method") or "").upper()
            hay = f"{req.get('url', '')} {req.get('body', '')}"
            if rmethod == method and rpath == path and any(p in hay for p in params):
                exact.append((_hay_relevance(ftype, hay), rid))
            elif rmethod == method and rpath == path:
                loose.append((_hay_relevance(ftype, hay), rid))
            elif rmethod == "GET" and rpath in render_paths:
                # render entries: prefer a CLEAN re-fetch (no other probe payload in
                # the URL) whose retained response window shows the canary. The
                # journal keeps only the first JOURNAL_MAX bytes of a body — the
                # marker may legitimately live outside that window.
                body = str((entry.get("response") or {}).get("body") or "")
                clean = ".." not in (req.get("url") or "") and "AND" not in (req.get("url") or "")
                render.append(((2 if "burhan" in body.lower() else 0) + (1 if clean else 0), rid))
        pool = exact if exact else loose
        # most class-relevant proving request first, then by stable req id
        chosen = [rid for _, rid in sorted(pool, key=lambda t: (-t[0], t[1]))][:6]
        return (chosen + [rid for _, rid in sorted(render, key=lambda t: (-t[0], t[1]))
                          if rid not in chosen][:2])

    def entry(self, rid):
        return self.journal.get(rid) or {}

    # ---- cookie provenance: which journal response FIRST issued each cookie
    def cookie_provenance(self, names):
        prov = {}
        for rid in self.journal_ids:
            headers = ((self.entry(rid).get("response") or {}).get("headers") or {})
            setc = str(headers.get("set-cookie") or headers.get("Set-Cookie") or "")
            for n in names:
                if n not in prov and f"{n}=" in setc:
                    prov[n] = (rid, setc)
        return prov

    def identity_identities_artifact(self):
        ids = self.action_matrix.get("identities") or []
        return [i.get("name") for i in ids if isinstance(i, dict) and i.get("name")]


# ------------------------------------------------------------------ link builders
def _link_identity(f, ctx, rids):
    """WHO the proving requests ran as — traced to raw headers, never guessed."""
    entries = [ctx.entry(r) for r in rids]
    auth_h = []
    for r, e in zip(rids, entries):
        for k in ((e.get("request") or {}).get("headers") or {}):
            if k.lower() == "authorization":
                auth_h.append(r)
    if auth_h:
        r = auth_h[0]
        return {"slot": "identity", "status": "verified",
                "statement": f"authenticated context — an Authorization header is carried by the raw proving request ({r})",
                "evidence": [_ev("journal", r, "Authorization")] + [_finding_ev(f)]}
    cookies, cookie_vals = [], {}
    for r, e in zip(rids, entries):
        for k, v in ((e.get("request") or {}).get("headers") or {}).items():
            if k.lower() == "cookie":
                for n in _cookie_names(v):
                    cookies.append(n)
                    # REGRESSION FIX (live ginjuice, round 6): a load-balancer
                    # cookie (AWSALB) ROTATES between proving requests. Keep the
                    # value PAIRED with the request id it was seen in, so the
                    # excerpt is always a literal slice of the CITED entry —
                    # citation and excerpt must never come from different entries.
                    cookie_vals[n] = (r, v)
    # FM-30 (full-repo first-match sweep, 2026-11-03): the [:3] cookie cap
    # is a STATEMENT-READABILITY bound over an identity claim — the leftover
    # cookies are now NAMED in the claim itself, never silently dropped.
    cookies_all = sorted(set(cookies))
    cookies = cookies_all[:3]
    if cookies and rids:
        prov = ctx.cookie_provenance(cookies)
        crid, cval = cookie_vals.get(cookies[0], (rids[0], "; ".join(cookies)))
        ev = [_ev("journal", crid, cval)]
        if cookies[0] in prov:
            prid, setc = prov[cookies[0]]
            ev.append(_ev("journal", prid, setc))
        leftover = (f"; {len(cookies_all) - len(cookies)} further cookie(s) "
                    f"observed (statement cap 3, documented)"
                    if len(cookies_all) > len(cookies) else "")
        return {"slot": "identity", "status": "verified",
                "statement": ("anonymous web session — cookie " + ", ".join(cookies) +
                              " carried by the raw proving requests; " +
                              (f"issued by the target on response {prov[cookies[0]][0]} (an unauthenticated fetch of a public surface)"
                               if cookies[0] in prov else "provenance not retained in the journal") +
                              "; no Authorization/credential material in any proving request"
                              + leftover),
                "evidence": ev + [_finding_ev(f)]}
    if rids:
        e = ctx.entry(rids[0])
        req = e.get("request") or {}
        return {"slot": "identity", "status": "verified",
                "statement": "credential-less requests — no Authorization header and no cookies in the raw proving requests",
                "evidence": [_ev("journal", rids[0], req.get("url", ""))] + [_finding_ev(f)]}
    # journal absent -> scan artifact (action matrix), never a guess
    names = ctx.identity_identities_artifact()
    if names:
        return {"slot": "identity", "status": "verified",
                "statement": ("the scan exercised only these identities: " +
                              ", ".join(names) + " (action-matrix artifact; raw journal not retained)"),
                "evidence": [_ev("scan_artifact", "stats.action_matrix.identities",
                                 json.dumps(names)[:120])]}
    return {"slot": "identity", "status": "unproven",
            "statement": "no identity evidence available (journal absent, action matrix empty)",
            "evidence": []}


def _link_entry(f, ctx, rids):
    params = _params_of(f)
    ev = [_finding_ev(f)]
    if rids:
        req = ctx.entry(rids[0]).get("request") or {}
        ev.append(_ev("journal", rids[0], req.get("url", "")))
    return {"slot": "entry", "status": "verified",
            "statement": (f"{(f.get('method') or 'GET').upper()} {f.get('url')}" +
                          (f" — parameter {', '.join(params)}" if params else " (no parameter)")),
            "evidence": ev}


_ACTION_PHRASES = {
    "sql_injection": "boolean condition injection — the attacker flips the query condition (AND 1=1 vs AND 1=2) and the application's behavior changes",
    "nosql_injection": "query-operator injection — attacker-supplied operators change query semantics",
    "xss_reflected": "attacker-supplied markup/JavaScript injected through the parameter survives into the response in an executable context",
    "xss_dom": "attacker-controlled data reaches a dangerous DOM sink and executes in the live browser (execution probe fired)",
    "xss_stored": "canary markup submitted through the real form (all form fields ridden verbatim) and persisted server-side",
    "path_traversal": "dot-dot traversal sequences injected into the path/parameter to escape the document root",
    "xxe": "an external entity injected into submitted XML is resolved by the parser",
    "ssrf": "the server is made to issue an outbound request to an attacker-chosen location",
    "command_injection": "operating-system command syntax injected and executed",
    "ssti": "template expressions injected and evaluated server-side",
    "csrf": "a state-changing request forged from a hostile origin and accepted",
    "jwt_security": "an unsigned/malformed token is accepted by the verifier",
    "host_header_injection": "an attacker-controlled Host header value is reflected into the response",
    "http_response_header_injection": "attacker-controlled data injected into response headers",
    "open_redirect": "an off-site URL injected into a redirect sink",
    "idor_bola": "an object identifier of another principal is accepted without an access-control check",
    "vertical_privilege_escalation": "a low-privilege session reaches a higher-privilege surface",
    "workflow_state_bypass": "workflow steps are skipped or replayed out of order",
    "authorization_bypass": "an operation is performed without the required authorization",
}


def _action_excerpt(f, req):
    """Slice the raw request AROUND the vulnerable parameter — the ride-along
    form prefix (VIEWSTATE etc.) must not bury the payload the path is about.
    The slice stays a literal substring of the raw body/url."""
    body = str(req.get("body") or "")
    for p in _params_of(f):
        i = body.find(p + "=")
        if i >= 0:
            return body[i:i + 120]
    return body[:120] or str(req.get("url") or "")[:120]


def _link_action(f, ctx, rids):
    v = f.get("verification") or {}
    ev = [_finding_ev(f, f"verification: {v.get('method', 'unrecorded')} (passed={bool(v.get('passed'))})")]
    if rids:
        req = ctx.entry(rids[0]).get("request") or {}
        ev.append(_ev("journal", rids[0], _action_excerpt(f, req)))
    return {"slot": "action", "status": "verified",
            "statement": _ACTION_PHRASES.get(f.get("type"), "the attack action recorded by the detector"),
            "evidence": ev}


_OBJECT_PHRASES = {
    "xss_reflected": "the HTTP response rendered to the victim",
    "xss_dom": "the victim's live DOM (sink executed)",
    "sql_injection": "the SQL query evaluation (a read-capable oracle)",
    "csrf": "the state-changing operation",
    "path_traversal": "the local filesystem outside the document root",
    "xxe": "the XML entity resolver (local file content reached the response)",
    "ssrf": "the server's outbound request capability",
    "open_redirect": "the client redirect sink",
    "host_header_injection": "the response headers derived from the Host header",
    "http_response_header_injection": "the response headers",
}


def _link_object(f, ctx):
    ev = [_finding_ev(f, (f.get("evidence") or [{}])[0].get("detail", f.get("type")))]
    surface = f"{(f.get('method') or 'GET').upper()} {_path_of(f.get('url', ''))}"
    entity = ""
    for row in ctx.entities:
        if surface in (row.get("surfaces") or []):
            entity = row.get("entity") or ""
            ev.append(_ev("twin", "stats.digital_twin.entity_inventory",
                          json.dumps(row, sort_keys=True)[:120]))
            break
    if f.get("type") == "xss_stored":
        obj = f"the persisted {entity.lower() + ' record' if entity else 'record'} (the canary survived an independent re-fetch — the record exists server-side)"
    else:
        obj = _OBJECT_PHRASES.get(f.get("type"), "the request/response at the vulnerable surface")
        if entity:
            obj += f" (twin entity typing: {entity})"
    return {"slot": "object", "status": "verified", "statement": obj, "evidence": ev}


def _link_authorization(f, ctx, rids):
    ftype = f.get("type")
    if ftype == "csrf":
        det = next((e.get("detail") for e in (f.get("evidence") or [])
                    if e.get("kind") == "cross_origin_acceptance"), "")
        ev = [_finding_ev(f, det or "cross_origin_acceptance")]
        if rids:
            req = ctx.entry(rids[0]).get("request") or {}
            headers = req.get("headers") or {}
            origin = next((v for k, v in headers.items() if k.lower() == "origin"), "")
            if origin:
                ev.append(_ev("journal", rids[0], origin))
        return {"slot": "authorization", "status": "verified",
                "statement": ("the state-changing operation accepts tokenless cross-origin "
                              "requests (hostile-origin replay accepted with the scan's own session; "
                              "no anti-CSRF token, no origin validation)"),
                "evidence": ev}
    if rids:
        accepted = any(200 <= ((ctx.entry(r).get("response") or {}).get("status") or 0) < 400 for r in rids)
        req = ctx.entry(rids[0]).get("request") or {}
        ev = [_ev("journal", rids[0], (req.get("headers") or {}).get("Cookie") or req.get("url", ""))]
        stmt = ("the surface is reachable without authentication: raw proving requests carried no "
                "Authorization header and were accepted" if accepted else
                "the proving requests were issued without an Authorization header")
        if (f.get("method") or "").upper() == "POST":
            fields = _form_fields(req.get("body") or "")
            token_fields = [x for x in fields if any(h in x.lower() for h in _TOKEN_FIELD_HINTS)]
            if not token_fields:
                stmt += ("; the submitted form carries no anti-CSRF token field"
                         + (f" (raw fields: {', '.join(fields[:8])})" if fields else ""))
            else:
                stmt += f"; the form carries token field(s) {', '.join(token_fields)}"
        return {"slot": "authorization", "status": "verified", "statement": stmt,
                "evidence": ev + [_finding_ev(f)]}
    return {"slot": "authorization", "status": "unproven",
            "statement": ("no raw request evidence retained — anonymous reachability of the surface "
                          "was not re-derivable from artifacts"),
            "evidence": []}


_STATE_PHRASES_VERIFIED = {
    "csrf": "the forged state-changing operation was accepted and processed (hostile-origin replay returned the same success as the baseline)",
}


def _link_state(f, ctx, rids):
    ftype = f.get("type")
    if ftype == "xss_stored":
        ev = [_finding_ev(f, next((e.get("detail") for e in (f.get("evidence") or [])
                                   if e.get("kind") == "stored_xss_reflection"), ""))]
        render = [r for r in rids
                  if (ctx.entry(r).get("request") or {}).get("method", "").upper() == "GET"]
        if render:
            req = ctx.entry(render[0]).get("request") or {}
            body = str((ctx.entry(render[0]).get("response") or {}).get("body") or "")
            # The engine's persistence control observed the marker on the re-fetch
            # (cited from the finding above). The journal corroborates that the
            # independent re-fetch REQUEST happened; its bounded response window
            # may not cover the marker — cite the body only when it actually does.
            if "burhan" in body.lower():
                ev.append(_ev("journal", render[0], body))
                state_note = "payload persisted server-side: the canary survived an independent re-fetch on the render surface (marker visible in the raw journal response window)"
            else:
                ev.append(_ev("journal", render[0], req.get("url", "")))
                state_note = ("payload persisted server-side: the canary survived an independent "
                              "re-fetch on the render surface (engine-observed reflection; the raw "
                              "journal retains the re-fetch request — its bounded response window "
                              "does not reach the marker location, so the marker observation is "
                              "cited from the finding's evidence record)")
        else:
            state_note = ("payload persisted server-side: the canary survived an independent "
                          "re-fetch on the render surface (engine-observed reflection)")
        return {"slot": "state", "status": "verified", "statement": state_note,
                "evidence": ev}
    if ftype in _STATE_PHRASES_VERIFIED:
        return {"slot": "state", "status": "verified",
                "statement": _STATE_PHRASES_VERIFIED[ftype],
                "evidence": [_finding_ev(f, (f.get("evidence") or [{}])[0].get("detail", ""))] +
                            ([_ev("journal", rids[0], ctx.entry(rids[0]).get("response", {}).get("body", ""))]
                             if rids else [])}
    if f.get("state_before") or f.get("state_after"):
        return {"slot": "state", "status": "verified",
                "statement": f"workflow state transition observed: {f.get('state_before', '?')} -> {f.get('state_after', '?')}",
                "evidence": [_finding_ev(f, f"state {f.get('state_before', '')}->{f.get('state_after', '')}")]}
    safe = ((f.get("impact") or {}).get("safe_proof") or "non-destructive verification")
    return {"slot": "state", "status": "verified",
            "statement": ("no application state change was involved in the proof (per-request class; "
                          f"verification protocol: {safe}) — whether the class can cause state changes was not tested"),
            "evidence": [_finding_ev(f, safe)]}


def _link_impact(f):
    impact = f.get("impact") or {}
    grade = impact.get("grade") or "indicated"
    chain = impact.get("evidence_chain") or {}
    if grade == "proven":
        return {"slot": "impact", "status": "verified",
                "statement": _b(impact.get("statement") or "demonstrated impact", 300),
                "evidence": [_finding_ev(f, f"impact grade=proven; chain: "
                                            f"{chain.get('verification', '')} on {chain.get('request', '')}")]}
    defect = next((e.get("detail") for e in (f.get("evidence") or [])), f.get("type"))
    return {"slot": "impact", "status": "inferred",
            "statement": (f"defect VERIFIED ({_b(defect, 90)}) but the end impact was NOT directly "
                          f"demonstrated (impact grade '{grade}') — the impact claim is inferred from "
                          "the verified defect, not from an executed demonstration"),
            "evidence": [_finding_ev(f, defect)]}


# ------------------------------------------------------------------ path assembly
def _classify(links, extra_weak=()):
    weak = [l["slot"] for l in links if l["status"] != "verified"] + list(extra_weak)
    return ("VERIFIED" if not weak else "INFERRED"), weak


def _pid(prefix, *material):
    return prefix + hashlib.sha1("|".join(str(m) for m in material).encode()).hexdigest()[:10]


def _single_path(f, ctx):
    rids = ctx.proving_entries(f)
    links = [_link_identity(f, ctx, rids), _link_entry(f, ctx, rids),
             _link_action(f, ctx, rids), _link_object(f, ctx),
             _link_authorization(f, ctx, rids), _link_state(f, ctx, rids),
             _link_impact(f)]
    cls, weak = _classify(links)
    return {
        "id": _pid("AP-", f.get("id"), cls),
        "title": f"{f.get('type')} at {_path_of(f.get('url', ''))} — single-finding path",
        "classification": cls, "weak_links": weak, "links": links,
        "findings": [f.get("id")], "hops": [], "chain_rule": "",
    }


def _chain_paths(ctx):
    """CHAIN-XSS-CSRF: an XSS finding whose execution is evidenced (impact
    grade proven) composed with a verified CSRF on the same host. The bridge
    hop — 'executing code drives the tokenless operation' — is VERIFIED only
    when script execution was actually demonstrated (xss_dom execution probe,
    xss_reflected executable-context canary). A stored XSS graded 'indicated'
    proves persistence but NOT execution -> the bridge is INFERRED and the
    whole chain is INFERRED."""
    out = []
    csrfs = [f for f in ctx.findings if f.get("type") == "csrf"]
    xs = [f for f in ctx.findings if f.get("type") in XSS_CLASSES]
    for c in sorted(csrfs, key=lambda x: x.get("id", "")):
        for x in sorted(xs, key=lambda x: x.get("id", "")):
            if _host(x.get("url", "")) != _host(c.get("url", "")):
                continue
            if x.get("id") == c.get("id"):
                continue
            bridge_ok = ((x.get("impact") or {}).get("grade") == "proven")
            rids_x = ctx.proving_entries(x)
            rids_c = ctx.proving_entries(c)
            # hops: each cites ITS OWN finding's evidence
            hops = [
                {"step": 1, "finding_id": x.get("id"), "status": "verified",
                 "statement": (f"attacker-delivered script executes in the victim's browser on "
                               f"{_host(x.get('url', ''))} ({x.get('type')}: execution proven)"),
                 "evidence": [_finding_ev(x, (x.get("evidence") or [{}])[0].get("detail", ""))] +
                             ([_ev("journal", rids_x[0], (ctx.entry(rids_x[0]).get("request") or {}).get("url", ""))]
                              if rids_x else [])},
                {"step": 2, "finding_id": c.get("id"),
                 "status": "verified" if bridge_ok else "inferred",
                 "statement": ("the executing code drives the state-changing operation "
                               f"{(c.get('method') or 'POST').upper()} {c.get('url')} — which accepts "
                               "tokenless cross-origin requests" +
                               ("" if bridge_ok else
                                " [BRIDGE INFERRED: script execution was not demonstrated for this XSS class — persistence only]")),
                 "evidence": [_finding_ev(c, next((e.get("detail") for e in (c.get("evidence") or [])
                                                   if e.get("kind") == "cross_origin_acceptance"), ""))] +
                             ([_ev("journal", rids_c[0], (ctx.entry(rids_c[0]).get("request") or {}).get("url", ""))]
                              if rids_c else [])},
            ]
            ident = {"slot": "identity",
                     "status": "verified" if bridge_ok else "inferred",
                     "statement": ("attacker-delivered script running in a victim's browser; the state "
                                   "change rides the victim's session (the operation was proven to accept "
                                   "tokenless hostile-origin requests with a valid session cookie)"),
                     "evidence": [_finding_ev(x), _finding_ev(c)]}
            entry = _link_entry(x, ctx, rids_x)
            action = {"slot": "action",
                      "status": "verified" if bridge_ok else "inferred",
                      "statement": (f"inject script via {x.get('type')} ({_path_of(x.get('url', ''))}, "
                                    f"param {x.get('parameter')}) -> executing code forges the tokenless "
                                    f"state change at {_path_of(c.get('url', ''))}"),
                      "evidence": hops[0]["evidence"] + hops[1]["evidence"]}
            obj = _link_object(c, ctx)
            authz = _link_authorization(c, ctx, rids_c)
            state = _link_state(c, ctx, rids_c)
            impact = {"slot": "impact",
                      "status": "verified" if bridge_ok else "inferred",
                      "statement": ("client-side code execution combined with an unprotected state "
                                    "change: arbitrary actions performable in the victim's session" +
                                    ("" if bridge_ok else " [INFERRED — execution half not demonstrated]")),
                      "evidence": [_finding_ev(x), _finding_ev(c)]}
            links = [ident, entry, action, obj, authz, state, impact]
            cls, _ = _classify(links)
            weak = [] if bridge_ok else ["bridge"]
            out.append({
                "id": _pid("APC-", x.get("id"), c.get("id"), cls),
                "title": (f"{x.get('type')} -> tokenless cross-site state change (chain: "
                          f"{x.get('id')} + {c.get('id')})"),
                "classification": cls, "weak_links": weak, "links": links,
                "findings": [x.get("id"), c.get("id")],
                "hops": hops, "chain_rule": "CHAIN-XSS-CSRF",
            })
    return out


def _mitigations_absent(path_findings_types, ctx, path_url_host):
    """Verified header-absence facts that annotate (never strengthen) a path."""
    out = []
    if not path_findings_types & XSS_CLASSES:
        return out
    for f in sorted(ctx.banner, key=lambda x: x.get("id", "")):
        if _host(f.get("url", "")) != path_url_host:
            continue
        for e in f.get("evidence") or []:
            det = e.get("detail") or ""
            if "missing:" in det.lower():
                names = [h.strip() for h in det.split(":", 1)[1].split(",") if h.strip()]
                for n in names[:6]:
                    out.append({"header": n.lower(), "finding_id": f.get("id"),
                                "note": "verified header-absence (annotation — does not affect path classification)"})
                break
    # unique by (header, finding), deterministic order
    seen, uniq = set(), []
    for m in sorted(out, key=lambda m: (m["header"], m["finding_id"])):
        key = (m["header"], m["finding_id"])
        if key not in seen:
            seen.add(key)
            uniq.append(m)
    return uniq[:6]


# ------------------------------------------------------------------ public API
def build_attack_paths(report: dict) -> dict:
    """Pure projection of one scan report into attack paths. Zero requests,
    fully deterministic, never mutates the input."""
    ctx = _Ctx(report)
    paths = []
    seeds = [f for f in ctx.findings if f.get("type") in SEED_CLASSES]
    non_seed = {f.get("id"): f.get("type") for f in ctx.findings
                if f.get("type") not in SEED_CLASSES}
    for f in sorted(seeds, key=lambda x: x.get("id", "")):
        p = _single_path(f, ctx)
        p["mitigations_absent"] = _mitigations_absent({f.get("type")}, ctx, _host(f.get("url", "")))
        paths.append(p)
    for p in _chain_paths(ctx):
        types = {next((f.get("type") for f in ctx.findings if f.get("id") == fid), "")
                 for fid in p["findings"]}
        host = next((_host(f.get("url", "")) for f in ctx.findings if f.get("id") == p["findings"][0]), "")
        p["mitigations_absent"] = _mitigations_absent(types, ctx, host)
        paths.append(p)
    paths.sort(key=lambda p: (0 if p["classification"] == "VERIFIED" else 1,
                              _SEVERITY_RANK.get("critical", 9), p["id"]))
    verified = sum(1 for p in paths if p["classification"] == "VERIFIED")
    hist = {}
    for p in paths:
        for w in p["weak_links"]:
            hist[w] = hist.get(w, 0) + 1
    return {
        "layer": SCANNER_LAYER,
        "paths": paths,
        "summary": {
            "target": report.get("target", ""), "run_id": report.get("run_id", ""),
            "paths_total": len(paths), "paths_verified": verified,
            "paths_inferred": len(paths) - verified,
            "singles": sum(1 for p in paths if not p.get("hops")),
            "chains": sum(1 for p in paths if p.get("hops")),
            "weak_link_histogram": dict(sorted(hist.items())),
            "seed_findings": sorted(f.get("id") for f in seeds),
            "non_seed_findings": dict(sorted(non_seed.items())),
            "honesty": ("A path equals its weakest link: "
                        f"{verified}/{len(paths)} paths carry EVERY link verified; the rest are "
                        "INFERRED and name their weak links. No link is ever marked verified "
                        "without an evidence reference traceable to a verified finding, a raw "
                        "journal entry, or a scan artifact. Chained paths additionally require "
                        "every hop evidenced; an inferred bridge (e.g. script execution not "
                        "demonstrated) makes the whole chain INFERRED."),
        },
    }


# ------------------------------------------------------------------ doctor fixture
def _doctor_fixture():
    """Minimal in-memory report for the doctor health check: one proven seed
    (-> a VERIFIED path, every link evidence-cited from the mini journal) and
    one indicated seed (-> an INFERRED path whose only weak link is impact)."""
    def F(fid, ftype, grade):
        return {"id": fid, "type": ftype, "severity": "high", "status": "verified",
                "confidence": 0.9, "method": "GET", "url": "http://doctor.local/x", "parameter": "q",
                "evidence": [{"kind": "response_diff", "detail": "differential"}],
                "verification": {"method": "oracle:replay-2round", "passed": True,
                                 "confidence": 0.9, "rounds": 2, "notes": ""},
                "run_id": "run-doctor", "risk": 50,
                "impact": {"grade": grade, "statement": "s", "safe_proof": "non-destructive",
                           "evidence_chain": {"request": "GET http://doctor.local/x", "parameter": "q",
                                              "evidence_kinds": ["response_diff"], "out_of_band": False,
                                              "verification": "oracle:replay-2round", "verification_passed": True}}}
    journal = {
        "req-d1": {"request": {"method": "GET", "url": "http://doctor.local/", "path": "/",
                               "headers": {}, "body": ""},
                   "response": {"status": 200, "headers": {"set-cookie": "SESS=d1; Path=/"}, "body": ""}},
        "req-d2": {"request": {"method": "GET", "url": "http://doctor.local/x?q=1%20AND%201%3D1",
                               "path": "/x", "headers": {"Cookie": "SESS=d1"}, "body": ""},
                   "response": {"status": 200, "headers": {}, "body": "a"}},
    }
    return {"run_id": "run-doctor", "seed": "s", "scanner": "burhan-core/4.3.0",
            "target": "http://doctor.local",
            "stats": {"request_journal": journal, "digital_twin": {},
                      "action_matrix": {"identities": [{"name": "anonymous", "role": "anonymous"}],
                                        "matrix": {}}},
            "findings": [F("F-doc1", "sql_injection", "proven"),
                         F("F-doc2", "xss_stored", "indicated")],
            "rejected_candidates": [], "unverified_candidates": []}

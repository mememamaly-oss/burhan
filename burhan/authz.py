"""Burhan v2.8.0 — Multi-User Authorization Engine (Phase 56).

The question this engine answers is not "is this input injectable" but
"WHO can do WHAT" — the authorization plane:

  * IDOR / BOLA            — a low-privilege session retrieves ANOTHER
                             account's private object (victim-marker oracle,
                             reproduced with a fresh victim: VR-17).
  * Vertical escalation    — a low-privilege session receives the privileged
                             view of an admin-only surface. Admin-only is
                             derived from the privileged roles' VIEW of the
                             application: links reachable from the privileged
                             account's landing page AND from a bounded replay
                             of the crawl set under each role's session
                             (role-specific menus often render on inner
                             pages, invisible to a landing-only differential
                             and to the low-privilege crawl), plus path hints.
                             Privileged-only surfaces absent from the crawl
                             set are synthesized as GET endpoints — the whole
                             point: the low-privilege crawl cannot discover
                             what it cannot see. The finding requires the
                             full access differential: anonymous gated,
                             privileged 200, low-privilege 200 with the
                             privileged BODY (VR-18 fresh replay).
  * Access matrix          — role x endpoint statuses, the auditable account
                             of who can reach what (feeds the Application Map).

Safety contract: GET-only replays (no state changes), per-engine isolated
sessions (one cookie jar per account — no session cross-contamination),
logout-shaped paths never replayed (a session must not be killed by its own
battery), deterministic candidate ordering, budget caps on every phase, and
honest degradation (0 findings, loud stats) when logins fail or roles are
absent.

False-positive disciplines:
  * the IDOR oracle is a UNIQUE victim marker in the body (an email/username
    only that account owns); a response carrying MULTIPLE account markers is
    a directory/listing surface, not object-level access — skipped.
  * admin reading user objects is plausibly intended: only NON-top-rank
    accounts act as IDOR attackers.
  * vertical requires the low-privilege body to MATCH the privileged body —
    a lower-privilege 200 that is a different (correct) view is healthy
    access control, not escalation.
"""
from __future__ import annotations
import difflib
import re
import urllib.parse
from dataclasses import dataclass, field

from .auth import AuthEngine, AuthProfile
from .core import (Endpoint, Evidence, Finding, FindingStatus, ScopeRule,
                   Severity, Verification)
from .discovery import endpoint_gate_scope as _gate_scope
from .http_engine import RequestEngine, RequestMutation

ROLE_RANK = {"admin": 0, "administrator": 0, "root": 0,
             "manager": 1, "moderator": 1, "supervisor": 1,
             "user": 2, "member": 2, "customer": 2, "client": 2, "viewer": 2,
             "guest": 3, "anonymous": 3}

ADMIN_PATH_RE = re.compile(r"/(admin|manage|management|console|internal|moderation)(/|$|\.)",
                           re.I)
# OWSP-28 (NodeGoat round, live-caught on /dashboard): 'dashboard' demoted
# from the strong set. Every app gives ORDINARY users a dashboard — the name
# alone is not an admin-surface signal (live FP: NodeGoat /dashboard, a
# role-agnostic authenticated page, nominated by the old name heuristic and
# verified by the access differential while the REAL function-level break
# /benefits went unseen). Ambiguous names require DATA-LEVEL corroboration:
# cross-account markers or cross-object state-change forms in the low-role
# view. Strong names (admin|manage|console|...) keep the name+differential
# oracle — that convention is near-universal.
WEAK_ADMIN_PATH_RE = re.compile(r"/(dashboard|settings|configuration|control|system|overview)(/|$|\.)",
                                re.I)
ASSET_EXT_RE = re.compile(
    r"\.(css|js|mjs|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|pdf|zip|gz|map|sql)([?#]|$)", re.I)
LOGOUT_PATH_RE = re.compile(r"(log-?out|log-?off|sign-?out|sign-?off)", re.I)
ID_PARAM_NAMES = {"id", "user_id", "userid", "uid", "account", "account_id", "acct",
                  "customer_id", "profile_id", "doc_id", "order_id", "object_id",
                  "record_id", "employee_id", "member_id"}
# ^ MAX-05b (maximum internal test, live-caught on Juice Shop 20.2.0): plain
#   "id" — THE canonical REST object-param name — was missing from the set,
#   so every /resource/{id} surface was skipped by the IDOR engine even with
#   a full account matrix armed. The strict victim-marker oracle keeps this
#   safe against noise; probes stay bounded by max_idor_endpoints/probes.


def _rank(role: str) -> int:
    return ROLE_RANK.get((role or "").lower(), 2)


@dataclass
class AuthzAccount:
    name: str
    role: str
    username: str
    password: str
    marker: str = ""          # unique substring proving THIS account's data
    object_id: str = ""       # this account's object identifier
    token: str = ""           # V411: token-mode account — the session engine
                              # carries this static token instead of logging in
                              # (API-key / Bearer-JWT identities)
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"


@dataclass
class AuthzConfig:
    login_url: str                     # form-carrying page (AuthProfile semantics)
    accounts: list[AuthzAccount] = field(default_factory=list)
    user_field: str = "uid"
    pass_field: str = "passw"
    success_marker: str = ""
    login_marker: str = "login"
    max_vertical: int = 15
    max_idor_endpoints: int = 40
    max_idor_probes: int = 60
    max_role_view: int = 20       # bounded per-role replay of the crawl set
                                  # (link extraction + access-matrix rows)
    token_validate_url: str = ""  # V411: token-mode validation URL (a page the
                                  # token must open; default = login_url)
    json_login: bool = False      # AUTH-06 for the authz battery: JSON-API
                                  # targets answer the login with 200 + a token
                                  # in the BODY (no cookie session). The login
                                  # runs as AuthProfile(json_login=True); on
                                  # success the harvested token is armed as
                                  # "Authorization: Bearer <token>" on that
                                  # account's session engine, so every later
                                  # replay (matrix, role-view, BFLA's
                                  # differential) carries the identity.

    @classmethod
    def from_dict(cls, d: dict, target_url: str = "") -> "AuthzConfig":
        login = d.get("login_url", "")
        if login and not login.startswith(("http://", "https://")):
            login = target_url.rstrip("/") + (login if login.startswith("/") else "/" + login)
        # MAX-02 (maximum internal test, live-caught on Juice Shop 20.2.0):
        # token_validate_url went through UNRESOLVED — a relative "/rest/basket/1"
        # produced Endpoint(url="/rest/basket/1") -> transport error -> EVERY
        # token-mode account reported "token rejected" and the whole authz
        # matrix silently degraded to ran=false. Resolve exactly like login_url.
        tvurl = str(d.get("token_validate_url", ""))
        if tvurl and not tvurl.startswith(("http://", "https://")):
            tvurl = target_url.rstrip("/") + (tvurl if tvurl.startswith("/") else "/" + tvurl)
        accounts = [AuthzAccount(
            name=str(a.get("name", a.get("username", "acct"))),
            role=str(a.get("role", "user")),
            username=str(a.get("username", "")),
            password=str(a.get("password", "")),
            marker=str(a.get("marker", "")),
            object_id=str(a.get("object_id", "")),
            token=str(a.get("token", "")),
            auth_header=str(a.get("auth_header", "Authorization")),
            auth_scheme=str(a.get("auth_scheme", "Bearer")))
            for a in d.get("accounts", [])]
        return cls(login_url=login, accounts=accounts,
                   user_field=d.get("user_field", "uid"),
                   pass_field=d.get("pass_field", "passw"),
                   success_marker=d.get("success_marker", ""),
                   login_marker=d.get("login_marker", "login"),
                   max_vertical=int(d.get("max_vertical", 15)),
                   max_idor_endpoints=int(d.get("max_idor_endpoints", 40)),
                   max_idor_probes=int(d.get("max_idor_probes", 60)),
                   max_role_view=int(d.get("max_role_view", 20)),
                   token_validate_url=tvurl,
                   json_login=bool(d.get("json_login", False)))


class AuthzEngine:
    """Runs the multi-user authorization battery after discovery."""

    def __init__(self, cfg: AuthzConfig, scope: ScopeRule, bus, timeout: float = 12.0):
        self.cfg, self.scope, self.bus, self.timeout = cfg, scope, bus, timeout
        self.sessions: dict[str, dict] = {}       # name -> {account, engine, landing, rank}
        self._anon = RequestEngine(scope, bus, timeout=timeout)
        self._extra_requests = 0                  # anon-engine honesty counter
        self.matrix: dict[str, dict[str, int]] = {}
        self.errors: list[str] = []
        # OWSP-28: cross-object-management surfaces collected during role-view
        # replay (state-change forms over OTHER accounts' object ids).
        self._crossobj_paths: set[str] = set()

    # ---------------------------------------------------------------- helpers
    def _login_all(self) -> int:
        ok = 0
        for acc in self.cfg.accounts:
            # ---- V411: token-mode account — a static token identity (API key
            # or Bearer JWT). No form login exists for these identities; the
            # engine arms the header and validates once against the
            # configured URL. Landing = the validation page.
            if acc.token:
                eng = RequestEngine(self.scope, self.bus, timeout=self.timeout)
                hv = (acc.token if not acc.auth_scheme
                      else f"{acc.auth_scheme} {acc.token}")
                eng.default_headers[acc.auth_header] = hv
                vurl = self.cfg.token_validate_url or self.cfg.login_url
                valid = True
                if vurl:
                    r = eng.send(RequestMutation(
                        endpoint=Endpoint(url=vurl, method="GET"),
                        note="authz-token-validate"))
                    self._extra_requests += 1
                    valid = r is not None and not r.error and \
                        r.status not in (401, 403)
                if valid:
                    self.sessions[acc.name] = {
                        "account": acc, "engine": eng,
                        "landing": vurl, "rank": _rank(acc.role)}
                    ok += 1
                else:
                    self.errors.append(
                        f"{acc.name}: token rejected by {vurl}")
                continue
            eng = RequestEngine(self.scope, self.bus, timeout=self.timeout)
            profile = AuthProfile(
                login_url=self.cfg.login_url, username=acc.username,
                password=acc.password, user_field=self.cfg.user_field,
                pass_field=self.cfg.pass_field, success_marker=self.cfg.success_marker,
                login_marker=self.cfg.login_marker,
                json_login=self.cfg.json_login)
            auth = AuthEngine(profile, eng, self.bus)
            if auth.login():
                # AUTH-06 json_login: the token arrived in the login response
                # BODY (no cookie session exists on a JSON-API target) — arm
                # it as the account's Bearer header so every later replay
                # (matrix, role-view, the BFLA differential) carries the
                # identity. Reuse modernsec2's body miner (same extraction
                # rule the JWT families use — one bug would hide itself if
                # each site re-implemented it).
                if self.cfg.json_login:
                    from .modernsec2 import _mine_jwt
                    token = _mine_jwt(auth.state.login_response) \
                        if getattr(auth.state, "login_response", None) else None
                    if not token:
                        self.errors.append(
                            f"{acc.name}: json login succeeded but no token "
                            f"harvestable from the login response body")
                        continue
                    eng.default_headers[acc.auth_header] = (
                        token if not acc.auth_scheme
                        else f"{acc.auth_scheme} {token}")
                self.sessions[acc.name] = {"account": acc, "engine": eng,
                                           "landing": auth.state.landing_url,
                                           "rank": _rank(acc.role)}
                ok += 1
            else:
                self.errors.append(f"{acc.name}: {auth.state.last_error[:120]}")
        return ok

    def _gated(self, resp) -> bool:
        """Anonymous gate: 401/403 or a redirect onto the login-marked path."""
        if resp is None or resp.error or not resp.status:
            return False
        if resp.status in (401, 403):
            return True
        marker = self.cfg.login_marker.lower()
        hops = [u for _, u in (resp.redirect_chain or [])] + [resp.hop_location()]
        return any(marker in urllib.parse.urlsplit(u).path.lower() for u in hops if u)

    @staticmethod
    def _similar(a: str, b: str) -> float:
        na = re.sub(r"\s+", " ", a or "")[:600]
        nb = re.sub(r"\s+", " ", b or "")[:600]
        return difflib.SequenceMatcher(None, na, nb).ratio()

    def _landing_links(self, sess) -> set[str]:
        r = sess["engine"].send(RequestMutation(
            endpoint=Endpoint(url=sess["landing"], method="GET"), note="authz-landing"))
        if r.error:
            return set()
        return self._page_links(r.body or "", sess["landing"])

    @staticmethod
    def _page_links(html: str, base_url: str) -> set[str]:
        """Same-host link PATHS parsed out of one page (deterministic set)."""
        try:
            from .discovery import _LinkParser
            hp = _LinkParser()
            hp.feed(html)
        except Exception:
            return set()
        host = urllib.parse.urlsplit(base_url).netloc
        out = set()
        for href in hp.links:
            try:
                p = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, href))
            except Exception:
                continue
            if p.netloc == host and p.path:
                out.add(p.path)
        return out

    def _probeable(self, path: str) -> bool:
        """A surface the battery may GET-replay: not an asset, not a session
        killer (logout-shaped), not the login gate itself, and — V411-DISC-SAFE
        (live-caught on DVGA) — never a destructive/global-reset GET: the
        role-view replay fetched /start_over under every account and re-seeded
        the whole database mid-scan. The planner vocabulary already blocks
        these paths for ACTIVE probes; the same discipline gates the
        matrix/role-view replay.
        OWSP-21: the argument is a GATE SCOPE (path + query) — callers with a
        full URL pass discovery.gate_scope(url); a query-routed command
        (index.php?do=toggle-security / ?do=logout) must be refused here just
        like its path-routed sibling."""
        from .discovery import DESTRUCTIVE_GET_RE, STATE_CHANGE_GET_RE
        if ASSET_EXT_RE.search(path) or LOGOUT_PATH_RE.search(path):
            return False
        if DESTRUCTIVE_GET_RE.search(path) or STATE_CHANGE_GET_RE.search(path):
            return False
        if self.cfg.login_marker and self.cfg.login_marker.lower() in path.lower():
            return False
        return True

    def _role_view_links(self, sess, endpoints: list[Endpoint]) -> set[str]:
        """Bounded role-view replay (v2.8.0 live-test hardening): re-fetch the
        crawl's GET endpoints under THIS role's session, record an access-
        matrix row for each, and collect the links only this role can see.
        Role-specific menus frequently render on inner pages (the testfire
        ADMINISTRATION menu lives on the account page, not the landing), so a
        landing-only differential is blind to them.
        OWSP-28: pages carrying state-change forms over OTHER accounts' object
        ids (the /benefits shape — one POST form per user row with a hidden
        userId input) are collected as cross-object-management surfaces: they
        are nomination candidates for the vertical differential regardless of
        any path-name signal."""
        out: set[str] = set()
        fetched: set[str] = set()
        for ep in sorted(endpoints, key=lambda e: e.url):
            if (ep.method or "GET").upper() != "GET":
                continue
            path = urllib.parse.urlsplit(ep.url).path
            if not path or path in fetched or not self._probeable(_gate_scope(ep)):
                continue
            if len(fetched) >= self.cfg.max_role_view:
                break
            fetched.add(path)
            r = self._fetch(sess["engine"], ep, "authz-roleview")
            self._mx(ep.url, f"role:{sess['account'].role}", r.status, resp=r)
            if r.error or not r.body:
                continue
            if self._cross_object_forms(r.body, sess["account"]):
                self._crossobj_paths.add(path)
            out |= self._page_links(r.body, ep.url)
        return out

    def _cross_object_forms(self, body: str, own_account) -> bool:
        """OWSP-28: TRUE when the page carries a state-changing form whose
        id-named input targets ANOTHER account's object id — an object-
        management surface (live shape: NodeGoat /benefits, <form method=POST
        action=/benefits><input type=hidden name=userId value=2|3> per user
        row, readable and writable by every logged-in role)."""
        others = {a.object_id for a in self.cfg.accounts
                  if a.object_id and a.name != own_account.name}
        if not others:
            return False
        for block in re.split(r"</form>", body, flags=re.I):
            if "<form" not in block.lower():
                continue
            if not re.search(r'<form\b[^>]*method=["\']?(post|put)["\']?', block, re.I):
                continue          # only state-change forms manage objects
            for m in re.finditer(r"<input\b[^>]*>", block, re.I):
                tag = m.group(0)
                nm = re.search(r'name=["\']?([\w.\-]+)', tag, re.I)
                vl = re.search(r'value=["\']?([\w.\-]+)', tag, re.I)
                if not nm or not vl:
                    continue
                n = nm.group(1).lower()
                if n not in ID_PARAM_NAMES and not n.endswith("_id"):
                    continue
                if vl.group(1) in others:
                    return True
        return False

    def _fetch(self, engine, ep, note, param_name="", param_value=""):
        m = RequestMutation(endpoint=ep, note=note,
                            param_name=param_name, param_value=param_value)
        before = engine.requests_sent
        r = engine.send(m)
        if engine is self._anon:
            self._extra_requests += engine.requests_sent - before
        return r

    def _mx(self, url: str, key: str, status, resp=None) -> None:
        # Honesty in the matrix: when the engine FOLLOWED a redirect, record the
        # GATE status (first hop) — a 302-to-login recorded as "200" (the login
        # page it landed on) would misrepresent the access boundary.
        if resp is not None and getattr(resp, "redirect_chain", None):
            status = resp.redirect_chain[0][0]
        self.matrix.setdefault(url.split("?")[0], {})[key] = int(status or 0)

    # ---------------------------------------------------------------- phases
    def _vertical(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings = []
        by_path: dict[str, Endpoint] = {}
        for ep in endpoints:
            if (ep.method or "GET").upper() == "GET" and ep.url.split("?")[0] not in by_path:
                by_path[ep.url.split("?")[0]] = ep
        # differential role-view surfaces: privileged-only links from BOTH the
        # landing page AND the bounded role-view replay of the crawl set
        links_by_name = {n: self._landing_links(s) | self._role_view_links(s, endpoints)
                         for n, s in sorted(self.sessions.items())}
        candidates: set[str] = set()
        names = list(links_by_name)
        for h in names:
            for l in names:
                if self.sessions[h]["rank"] < self.sessions[l]["rank"]:
                    candidates |= (links_by_name[h] - links_by_name[l])
        candidates |= {p for p in by_path if ADMIN_PATH_RE.search(p)}
        # OWSP-28: cross-object-management surfaces (collected during the
        # role-view replay above) are nominated regardless of path naming —
        # NodeGoat's /benefits carries no admin-ish name yet is the real
        # function-level break (POST forms over other users' ids, open to
        # every authenticated role). NOTE: by_path keys are FULL URLs;
        # _crossobj_paths stores PATHS — match on the parsed path.
        candidates |= {u for u in by_path
                       if urllib.parse.urlsplit(u).path in self._crossobj_paths}
        # crawl-set candidates first (they carry discovered parameters), then
        # privileged-only surfaces the crawl never saw — synthesized as GET
        # endpoints so the differential can actually be tested.
        ordered = (sorted(candidates & set(by_path))
                   + [p for p in sorted(candidates - set(by_path))
                      if self._probeable(p)])[:self.cfg.max_vertical]
        origin = ""
        if self.sessions:
            first = sorted(self.sessions.items())[0][1]
            lu = urllib.parse.urlsplit(first["landing"])
            origin = f"{lu.scheme}://{lu.netloc}"
        for p in ordered:
            if p not in by_path and origin:
                by_path[p] = Endpoint(url=origin + p, method="GET")
        top = [s for s in self.sessions.values() if s["rank"] == min(x["rank"] for x in self.sessions.values())]
        lows = [s for s in self.sessions.values() if s["rank"] > top[0]["rank"]]
        if not lows:
            return findings                       # single-role deployment: no ladder to climb
        for path in ordered:
            # OWSP-35 (defensive depth): every fetched candidate passes the
            # probeable gate — logout/destructive/state-change surfaces must
            # never be fetched by the battery itself, whichever nomination
            # source produced them.
            if not self._probeable(path):
                continue
            ep = by_path[path]
            anon = self._fetch(self._anon, ep, "authz-anon")
            self._mx(ep.url, "anonymous", anon.status, resp=anon)
            high = None
            for s in sorted(top, key=lambda x: x["account"].name):
                high = self._fetch(s["engine"], ep, "authz-high")
                self._mx(ep.url, f"role:{s['account'].role}", high.status, resp=high)
                if not high.error and high.ok:
                    break
            if high is None or high.error or not high.ok:
                continue                          # privileged view unavailable: no oracle
            for s in sorted(lows, key=lambda x: (-x["rank"], x["account"].name)):
                low = self._fetch(s["engine"], ep, "authz-low")
                self._mx(ep.url, f"role:{s['account'].role}", low.status, resp=low)
                if low.error or not low.ok:
                    continue
                sim = self._similar(high.body, low.body)
                if not self._gated(anon) or sim < 0.6:
                    continue
                # OWSP-28: ambiguous admin-ish names (dashboard/settings/...)
                # are NOT nominated on the name alone — an ordinary role-
                # agnostic authenticated page passes every step above (live
                # FP: NodeGoat /dashboard). Data-level corroboration is
                # required: another account's marker in the low view, or a
                # cross-object state-change form. Strong-name and
                # cross-object-nominated surfaces keep the plain differential.
                if (WEAK_ADMIN_PATH_RE.search(path) and not ADMIN_PATH_RE.search(path)
                        and urllib.parse.urlsplit(path).path not in self._crossobj_paths):
                    other_markers = [a.marker for a in self.cfg.accounts
                                     if a.marker and a.name != s["account"].name]
                    cross_marker = any(mk in (low.body or "") for mk in other_markers)
                    if not (cross_marker or self._cross_object_forms(low.body or "", s["account"])):
                        continue          # name-only signal, zero privileged data: honest skip
                cand = Finding(
                    "vertical_privilege_escalation", Severity.HIGH, ep.url, "",
                    ep.method or "GET",
                    [Evidence("role_boundary_bypass",
                              f"low-privilege session (role={s['account'].role}, "
                              f"account={s['account'].name}) received the privileged "
                              f"view of an admin-only surface: anonymous -> gated "
                              f"(HTTP {anon.status}), privileged -> 200, "
                              f"role={s['account'].role} -> 200 with body similarity "
                              f"{sim:.2f} to the privileged view", low.request_id)],
                    status=FindingStatus.CANDIDATE)
                cand.authz_context = (f"attacker={s['account'].name}(role={s['account'].role}) "
                                      f"surface=privileged")
                # VR-18: fresh replay with the SAME low-privilege session
                vr = self._fetch(s["engine"], ep, "authz-verify")
                ok = (not vr.error and vr.ok
                      and self._similar(high.body, vr.body) >= 0.6)
                cand.verification = Verification(
                    method="re-test:fresh-privileged-replay", passed=ok,
                    confidence=0.9 if ok else 0.15, rounds=1,
                    notes=f"fresh replay with role={s['account'].role} session "
                          f"still returned the privileged view: {ok}")
                cand.confidence = cand.verification.confidence
                cand.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                findings.append(cand)
                break                             # one finding per surface
        return findings

    def _idor(self, endpoints: list[Endpoint]) -> list[Finding]:
        findings = []
        accounts = [s["account"] for s in self.sessions.values()]
        if len(accounts) < 2:
            return findings
        top_rank = min(_rank(a.role) for a in accounts)
        attackers = [a for a in accounts if _rank(a.role) > top_rank] or accounts
        all_markers = [a.marker for a in accounts if a.marker]
        done = 0
        found_paths: set[str] = set()
        for ep in sorted(endpoints, key=lambda e: e.url):
            if done >= self.cfg.max_idor_endpoints:
                break
            if (ep.method or "GET").upper() != "GET":
                continue
            if ep.url.split("?")[0] in found_paths:
                continue
            p = next((p for p in ep.parameters
                      if ((p.name or "").lower() in ID_PARAM_NAMES
                          or (p.name or "").lower().endswith(("_id", "_num")))
                      and p.kind.value != "token"), None)
            if p is None:
                continue
            done += 1
            hit = False
            for acc in sorted(attackers, key=lambda a: a.name):
                if hit:
                    break
                sess = self.sessions.get(acc.name)
                if sess is None:
                    continue
                for victim in sorted(accounts, key=lambda a: a.name):
                    if victim.name == acc.name or not victim.marker or not victim.object_id:
                        continue
                    probe = self._fetch(sess["engine"], ep, "authz-idor",
                                        param_name=p.name, param_value=victim.object_id)
                    self._mx(ep.url, f"role:{acc.role}", probe.status, resp=probe)
                    if probe.error or not probe.ok or victim.marker not in (probe.body or ""):
                        continue
                    # listing guard: multiple distinct account markers = directory
                    # surface, not object-level access
                    markers_seen = sum(1 for m in all_markers if m in (probe.body or ""))
                    if markers_seen > 1:
                        continue
                    horizontal = " (horizontal, same-role)" if _rank(acc.role) == _rank(victim.role) \
                        else " (cross-role)"
                    cand = Finding(
                        "idor_bola", Severity.HIGH, ep.url, p.name, ep.method or "GET",
                        [Evidence("object_access_broken",
                                  f"account {acc.name} (role={acc.role}) retrieved "
                                  f"account {victim.name}'s private object via "
                                  f"{p.name}={victim.object_id}: victim marker "
                                  f"present in response{horizontal} — no object-level "
                                  "authorization", probe.request_id)],
                        status=FindingStatus.CANDIDATE)
                    cand.authz_context = (f"attacker={acc.name}(role={acc.role}) "
                                          f"victim={victim.name}(role={victim.role})")
                    # VR-17: FRESH victim (different account) with the same attacker
                    others = [v for v in sorted(accounts, key=lambda a: a.name)
                              if v.name not in (acc.name, victim.name)
                              and v.marker and v.object_id]
                    fresh = others[0] if others else victim
                    vr = self._fetch(sess["engine"], ep, "authz-verify",
                                     param_name=p.name, param_value=fresh.object_id)
                    ok = (not vr.error and vr.ok and fresh.marker in (vr.body or ""))
                    cand.verification = Verification(
                        method="re-test:fresh-victim-object", passed=ok,
                        confidence=0.9 if ok else 0.15, rounds=1,
                        notes=f"fresh victim object ({p.name}={fresh.object_id}, "
                              f"account={fresh.name}) also readable by {acc.name}: {ok}")
                    cand.confidence = cand.verification.confidence
                    cand.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                    findings.append(cand)
                    found_paths.add(ep.url.split("?")[0])
                    hit = True
                    break            # one finding per endpoint; next endpoint continues

        # OWSP-33 (NodeGoat round, live-caught on /allocations/:userId): object
        # ids riding as the FINAL PATH SEGMENT have no Parameter at all — the
        # parameter-model loop above never sees them, so the object-level break
        # on /allocations/<id> was structurally invisible (live: user1 read
        # admin's allocations; the scanner said nothing). Synthesize direct
        # URL-substitution probes for id-shaped trailing segments — same strict
        # victim-marker oracle, same listing guard, same VR-17 fresh-victim
        # replay as the parameter path.
        obj_ids = {a.object_id for a in accounts if a.object_id}
        for ep in sorted(endpoints, key=lambda e: e.url):
            if done >= self.cfg.max_idor_endpoints:
                break
            if (ep.method or "GET").upper() != "GET":
                continue
            pu = urllib.parse.urlsplit(ep.url)
            base_path, _, tail = pu.path.rstrip("/").rpartition("/")
            if not base_path or not tail:
                continue
            if not (tail in obj_ids or (tail.isdigit() and len(tail) <= 12)):
                continue          # only id-shaped trailing segments
            if base_path in found_paths:
                continue          # one finding per path template
            # endpoints carrying an id-shaped QUERY param are handled above
            if any(((p.name or "").lower() in ID_PARAM_NAMES) for p in ep.parameters):
                continue
            if not self._probeable(_gate_scope(ep)):
                continue
            done += 1

            def _swap_url(oid: str) -> str:
                np = base_path + "/" + urllib.parse.quote(str(oid), safe="")
                return urllib.parse.urlunsplit((pu.scheme, pu.netloc, np, pu.query, pu.fragment))

            hit = False
            for acc in sorted(attackers, key=lambda a: a.name):
                if hit:
                    break
                sess = self.sessions.get(acc.name)
                if sess is None:
                    continue
                for victim in sorted(accounts, key=lambda a: a.name):
                    if victim.name == acc.name or not victim.marker or not victim.object_id:
                        continue
                    u2 = _swap_url(victim.object_id)
                    probe = self._fetch(sess["engine"], Endpoint(url=u2, method="GET"),
                                        "authz-idor-path")
                    self._mx(u2, f"role:{acc.role}", probe.status, resp=probe)
                    if probe.error or not probe.ok or victim.marker not in (probe.body or ""):
                        continue
                    markers_seen = sum(1 for m in all_markers if m in (probe.body or ""))
                    if markers_seen > 1:
                        continue      # directory surface, not object-level access
                    cand = Finding(
                        "idor_bola", Severity.HIGH, u2, "path_id", "GET",
                        [Evidence("object_access_broken",
                                  f"account {acc.name} (role={acc.role}) retrieved "
                                  f"account {victim.name}'s private object via PATH "
                                  f"SEGMENT substitution ({base_path}/ -> {u2.split('?')[0]}): "
                                  f"victim marker present in response — no object-level "
                                  "authorization on the path-carried object id (OWSP-33)",
                                  probe.request_id)],
                        status=FindingStatus.CANDIDATE)
                    cand.authz_context = (f"attacker={acc.name}(role={acc.role}) "
                                          f"victim={victim.name}(role={victim.role})")
                    # VR-17: FRESH victim (different account), same attacker
                    others = [v for v in sorted(accounts, key=lambda a: a.name)
                              if v.name not in (acc.name, victim.name)
                              and v.marker and v.object_id]
                    fresh = others[0] if others else victim
                    uf = _swap_url(fresh.object_id)
                    vr = self._fetch(sess["engine"], Endpoint(url=uf, method="GET"),
                                     "authz-verify")
                    ok = (not vr.error and vr.ok and fresh.marker in (vr.body or ""))
                    cand.verification = Verification(
                        method="re-test:fresh-victim-object", passed=ok,
                        confidence=0.9 if ok else 0.15, rounds=1,
                        notes=f"fresh victim object ({uf.split('?')[0]}, account={fresh.name}) "
                              f"also readable by {acc.name}: {ok}")
                    cand.confidence = cand.verification.confidence
                    cand.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                    findings.append(cand)
                    found_paths.add(base_path)
                    hit = True
                    break
        return findings

    # ---------------------------------------------------------------- run
    def run(self, endpoints: list[Endpoint]) -> dict:
        logins_ok = self._login_all()
        roles = sorted({s["account"].role for s in self.sessions.values()})
        findings: list[Finding] = []
        if logins_ok >= 2:
            findings.extend(self._vertical(endpoints))
            findings.extend(self._idor(endpoints))
        engine_reqs = sum(s["engine"].requests_sent for s in self.sessions.values())
        return {
            "findings": findings,
            "matrix": self.matrix,
            "stats": {
                "accounts_configured": len(self.cfg.accounts),
                "accounts_logged_in": logins_ok,
                "roles": roles,
                "matrix_endpoints": len(self.matrix),
                "login_errors": self.errors[:5],
                "requests": engine_reqs + self._extra_requests,
                "ran": logins_ok >= 2,
            },
        }

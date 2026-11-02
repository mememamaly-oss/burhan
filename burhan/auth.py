"""Phase 51: Authentication Engine — login, session validation, self-healing re-auth.

Design (three rules, all live-proven on demo.testfire.net):
  AUTH-01  Form-intelligent login: GET the login page (ENG-05 jar primes the
           session cookie), parse the REAL form (action + hidden fields — CSRF
           tokens ride verbatim as TOKEN params, never mutated), POST the
           credentials (ENG-06 serializes the body). Live-caught: a naive
           POST-to-login-URL with hard-coded fields is structurally blind to
           session-bound CSRF tokens and transmits nothing without ENG-06.
  AUTH-02  Deterministic success oracle: success = the login POST's first-hop
           redirect (ENG-01 preserves it even though the engine follows) does
           NOT land on a login-marked path AND (when configured) the landing
           body carries the success marker. The landing URL becomes the
           authenticated crawl seed — the authenticated surface (/bank/* on
           Altoro) is only linked from post-login pages, never from the
           anonymous homepage.
  AUTH-03  Session-loss watchdog: a transparent engine proxy inspects EVERY
           response of the scan; a request to a non-login endpoint that gets
           redirected to a login-marked path means the session died mid-scan.
           The proxy re-authenticates (budget-capped), REPLAYS the exact same
           mutation once, and reports both attempts in events. Deterministic
           self-repair in the same spirit as OP-01: no silent degradation.
"""
from __future__ import annotations
import urllib.parse
from dataclasses import dataclass, field

from .core import Endpoint, EventBus, Parameter, ParamLocation, ScopeRule
from .http_engine import RequestEngine, RequestMutation


@dataclass
class AuthProfile:
    """Declarative description of one login flow. Defaults match AltoroJ
    (demo.testfire.net): GET /login.jsp, POST /doLogin {uid, passw}.
    AUTH-05 (Phase 54): token mode — set `token` and every request carries
    `Authorization: <scheme> <token>` (or a custom header, raw when scheme="").
    login_url doubles as the VALIDATION url in token mode (the page fetched to
    prove the token opens an otherwise-closed door)."""
    login_url: str                    # form: page carrying the login form (GET first); token: validation url
    username: str = ""
    password: str = ""
    user_field: str = "uid"
    pass_field: str = "passw"
    action_url: str = ""              # empty = learn from the form's action
    extra_fields: dict = field(default_factory=dict)   # e.g. {"btnSubmit": "Login"}
    success_marker: str = ""          # substring expected in the landing page body
    login_marker: str = "login"       # a redirect hop whose path contains this = session gate
    max_reauth: int = 5               # AUTH-03 budget cap (prevents credential hammering)
    validate_url: str = ""            # page fetched to confirm the session; default = landing
    # ---- AUTH-06 (owner order follow-up 2026-11-01): JSON API login mode.
    # crAPI-style targets authenticate with POST {user,pass} as a JSON
    # object and answer 200 + a token in the BODY (no redirect, no cookie
    # session) — the form flow's redirect oracle and x-www-form-urlencoded
    # body can never pass there. When json_login is set the credential
    # params ride ParamLocation.JSON (ENG-04: Content-Type application/json)
    # and the oracle is 2xx + success_marker in the response body. The
    # successful login endpoint is stashed (login_endpoint) so the caller
    # can contribute the credentialed surface to the endpoint map — the
    # JWT families harvest their token by REPLAYING exactly this endpoint.
    json_login: bool = False
    # ---- AUTH-05 token mode
    token: str = ""                   # non-empty => token mode (form fields ignored)
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"       # "Bearer x" / "Token x" / "" = raw value

    @property
    def mode(self) -> str:
        return "token" if self.token else "form"

    def header_value(self) -> str:
        v = self.token if not self.auth_scheme else f"{self.auth_scheme} {self.token}"
        return v.strip()


@dataclass
class AuthState:
    authenticated: bool = False
    login_endpoint: object = None      # AUTH-06: the credentialed POST endpoint (json_login)
    login_response: object = None      # AUTH-06: the login Response itself (json_login) —
                                       # a JSON-API login carries the token in the body;
                                       # callers that must ARM the token (the authz
                                       # battery's session engines) mine it from here
    landing_url: str = ""
    logins: int = 0
    reauths: int = 0
    failed_reauths: int = 0
    last_error: str = ""


class AuthEngine:
    """Executes the login flow against a live target using the scan's own
    RequestEngine — the harvested session rides the ENG-05 cookie jar, so every
    later request (discovery, detectors, verifier) automatically carries it."""

    def __init__(self, profile: AuthProfile, engine: RequestEngine, bus: EventBus):
        self.p, self.engine, self.bus = profile, engine, bus
        self.state = AuthState()

    # ---------------------------------------------------------------- helpers
    def _login_marker_hit(self, url: str) -> bool:
        try:
            path = urllib.parse.urlsplit(url).path.lower()
        except Exception:
            return False
        return self.p.login_marker.lower() in path

    # ---------------------------------------------------------------- login
    def login(self) -> bool:
        """AUTH-01 + AUTH-02. Returns True when the session is confirmed."""
        self.state.logins += 1
        base = self.p.login_url
        # 1. prime the session (anonymous GET also reveals the true form)
        r0 = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=base, method="GET"), note="auth-prime"))
        if r0.error:
            self.state.last_error = f"login page unreachable: {r0.error}"
            self.bus.emit("AuthFailed", reason="prime", error=self.state.last_error)
            return False

        # 2. learn the form (action + fields incl. hidden CSRF tokens).
        # AUTH-06 json_login: there is no HTML form on an API login — the
        # credential object is built directly and serialized as JSON.
        if self.p.json_login:
            action_abs = urllib.parse.urljoin(base, self.p.action_url or base)
            loc = ParamLocation.JSON
            params = [Parameter(self.p.user_field, loc, self.p.username),
                      Parameter(self.p.pass_field, loc, self.p.password)]
            params += [Parameter(n, loc, v) for n, v in self.p.extra_fields.items()]
        else:
            action, fields = self._parse_login_form(r0.body or "")
            target = self.p.action_url or action or base
            action_abs = urllib.parse.urljoin(base, target)
            # credential fields first, then profile extras, then the form's own
            # hidden fields (CSRF rides verbatim — Parameter.classify marks it TOKEN)
            params = [Parameter(self.p.user_field, ParamLocation.BODY, self.p.username),
                      Parameter(self.p.pass_field, ParamLocation.BODY, self.p.password)]
            for n, v in self.p.extra_fields.items():
                params.append(Parameter(n, ParamLocation.BODY, v))
            for n, v in fields:
                if n in (self.p.user_field, self.p.pass_field) or any(x.name == n for x in params):
                    continue
                params.append(Parameter(n, ParamLocation.BODY, v).classify())

        # 3. submit (ENG-06 serializes the body; ENG-05 replays the session cookie)
        ep = Endpoint(url=action_abs, method="POST", parameters=params)
        host = urllib.parse.urlsplit(base).hostname or ""
        r = None
        hop = None
        redirected_to_login = False
        for attempt in (1, 2):
            r = self.engine.send(RequestMutation(endpoint=ep, note="auth-submit"))
            if r.error:
                break
            hop = r.hop_location()
            redirected_to_login = bool(hop) and self._login_marker_hit(hop)
            if (not hop or redirected_to_login) and attempt == 1 \
                    and self.engine.cookie_jar.get(host):
                # MAX-10b (maximum internal test, live-caught on WebGoat 8.2.2):
                # a re-auth that replays a DEAD session cookie is rejected by
                # session-fixation-aware logins (Spring Security bounces the
                # POST straight back to /login with correct credentials) — and
                # then fails FOREVER in a death spiral. One clean-jar retry:
                # drop this host's cookies and handshake fresh.
                self.engine.cookie_jar.pop(host, None)
                self.bus.emit("AuthCookieDiet", host=host,
                              note="re-login with stale cookies rejected; retrying cookieless")
                continue
            break
        if r.error:
            self.state.last_error = f"login submit failed: {r.error}"
            self.bus.emit("AuthFailed", reason="submit", error=self.state.last_error)
            return False

        # 4. AUTH-06 json_login oracle: a JSON API login answers 2xx with
        # the token in the BODY — there is no redirect and no cookie landing
        # page to validate; success_marker (required in this mode) is the
        # deterministic oracle on the login response itself.
        if self.p.json_login:
            body = r.body or ""
            if r.status and r.status < 400 and self.p.success_marker \
                    and self.p.success_marker in body:
                self.state.authenticated = True
                # landing = validate_url when given: the crawl seeds from it,
                # so an authenticated surface (the natural post-login page)
                # enters the endpoint map — the JWT differential target.
                self.state.landing_url = (self.p.validate_url or base)
                self.state.login_endpoint = ep
                self.state.login_response = r
                self.bus.emit("AuthSuccess", mode="json", url=base,
                              status=r.status)
                return True
            self.state.last_error = (f"json login rejected: POST {base} -> "
                                     f"status {r.status}, marker "
                                     f"{self.p.success_marker!r} "
                                     f"{'present' if self.p.success_marker in body else 'missing'}")
            self.bus.emit("AuthFailed", reason="json-oracle",
                          error=self.state.last_error)
            return False
        # 4. AUTH-02 deterministic success oracle
        hop = r.hop_location()
        redirected_to_login = bool(hop) and self._login_marker_hit(hop)
        if not hop or redirected_to_login:
            self.state.last_error = (f"login rejected: POST -> {hop or r.url} "
                                      f"(status {r.status}, redirected_to_login={redirected_to_login})")
            self.bus.emit("AuthFailed", reason="credentials", error=self.state.last_error)
            return False
        landing = hop if hop else (self.p.validate_url or base)
        landing = urllib.parse.urljoin(base, landing)

        # 5. confirm the session on the landing page (marker if configured)
        rv = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=landing, method="GET"), note="auth-validate"))
        if rv.error:
            self.state.last_error = f"landing unreachable: {rv.error}"
            self.bus.emit("AuthFailed", reason="landing", error=self.state.last_error)
            return False
        if self.p.success_marker and self.p.success_marker.lower() not in (rv.body or "").lower():
            self.state.last_error = f"success marker missing on landing {landing}"
            self.bus.emit("AuthFailed", reason="marker", error=self.state.last_error)
            return False
        # a landing that bounces straight back to the login page = not authenticated
        if rv.redirect_chain and any(self._login_marker_hit(u) for _, u in rv.redirect_chain):
            self.state.last_error = f"landing {landing} bounced to login"
            self.bus.emit("AuthFailed", reason="bounce", error=self.state.last_error)
            return False

        self.state.authenticated = True
        self.state.landing_url = landing
        self.bus.emit("Authenticated", user=self.p.user_field, landing=landing,
                      logins=self.state.logins)
        return True

    def _parse_login_form(self, html: str) -> tuple[str, list[tuple[str, str]]]:
        """Find the form containing the credential fields; return (action, fields).
        Reuses the discovery HTML parser (same input -> same output)."""
        try:
            from .discovery import _LinkParser
            hp = _LinkParser(); hp.feed(html)
        except Exception:
            return "", []
        want = {self.p.user_field.lower(), self.p.pass_field.lower()}
        for form in hp.forms:
            names = {n.lower() for n, _ in form["params"]}
            if want & names:
                return form.get("action", ""), list(form["params"])
        return "", []

    # ---------------------------------------------------------------- watchdog
    def session_lost(self, m: RequestMutation, r) -> bool:
        """AUTH-03 detection rule: we asked for a non-login endpoint and the
        server answered by sending us to a login-marked path."""
        if r is None or getattr(r, "error", ""):
            return False
        chain = getattr(r, "redirect_chain", []) or []
        if not chain:
            return False
        asked_login = self._login_marker_hit(m.endpoint.url)
        if asked_login:
            return False                      # navigating to login pages is normal
        return any(self._login_marker_hit(u) for _, u in chain)

    def reauth(self) -> bool:
        """Budget-capped re-login. Deterministic throttle: never more than
        max_reauth total, never counts a failed attempt as success."""
        if self.state.reauths >= self.p.max_reauth:
            self.state.failed_reauths += 1
            self.bus.emit("AuthBudgetExhausted", reauths=self.state.reauths)
            return False
        self.state.reauths += 1
        ok = self.login()
        self.bus.emit("AuthReauth", attempt=self.state.reauths, ok=ok)
        return ok


class AuthedEngineProxy:
    """Transparent proxy over RequestEngine. Every send() is inspected for the
    AUTH-03 session-loss signature; on detection the proxy re-authenticates and
    replays the SAME mutation exactly once, so a mid-scan session expiry costs
    one extra request instead of silently degrading the whole authenticated
    surface to anonymous pages (live-caught class of failure)."""
    def __init__(self, inner: RequestEngine, auth: AuthEngine):
        self._inner, self._auth = inner, auth

    def send(self, m: RequestMutation):
        r = self._inner.send(m)
        if not self._auth.state.authenticated:
            return r
        if self._auth.session_lost(m, r):
            self._auth.bus.emit("SessionLostDetected", url=m.endpoint.url,
                                reauths=self._auth.state.reauths)
            if self._auth.reauth():
                r2 = self._inner.send(m)          # one replay with the fresh session
                return r2
        return r

    # ---- everything else delegates to the real engine (cookie jar, counters,
    # scope gate, timeouts — the proxy is invisible to callers)
    def __getattr__(self, name):
        return getattr(self._inner, name)


class TokenAuthEngine:
    """AUTH-05 (Phase 54): static-token authentication — Bearer JWTs, API keys,
    custom X-Auth-Token headers. Three honest differences from form auth:
      1. "login" = VALIDATION, not credential exchange: we fetch the validation
         url WITH the header and require a door that is closed without it (no
         401/403, no redirect to a login gate, optional success marker).
      2. The token rides engine.default_headers — EVERY engine request carries
         it (no per-phase wiring, no drift between discovery/detectors/verifier).
      3. No self-healing: a static token cannot be re-minted. Mid-scan 401/403
         responses are COUNTED honestly (TokenRejected) instead of replayed —
         silently proceeding anonymous would mislabel the surface as clean."""

    def __init__(self, profile: AuthProfile, engine: RequestEngine, bus: EventBus):
        self.p, self.engine, self.bus = profile, engine, bus
        self.state = AuthState()
        self.state.landing_url = profile.login_url
        self.rejections = 0          # 401/403 seen while authenticated (possible expiry)

    def login(self) -> bool:
        """Validate the token, then arm the header on the engine."""
        self.state.logins += 1
        hv = self.p.header_value()
        r = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=self.p.login_url, method="GET"),
            extra_headers={self.p.auth_header: hv}, note="auth-validate-token"))
        if r.error:
            self.state.last_error = f"validation url unreachable: {r.error}"
            self.bus.emit("AuthFailed", reason="validate", error=self.state.last_error)
            return False
        if r.status in (401, 403):
            self.state.last_error = f"token rejected: {self.p.login_url} -> {r.status}"
            self.bus.emit("AuthFailed", reason="token_rejected", error=self.state.last_error)
            return False
        hop = r.hop_location()
        if hop and self.p.login_marker.lower() in urllib.parse.urlsplit(hop).path.lower():
            self.state.last_error = f"validation bounced to login gate: {hop}"
            self.bus.emit("AuthFailed", reason="bounce", error=self.state.last_error)
            return False
        if self.p.success_marker and self.p.success_marker.lower() not in (r.body or "").lower():
            self.state.last_error = f"success marker missing on {self.p.login_url}"
            self.bus.emit("AuthFailed", reason="marker", error=self.state.last_error)
            return False
        # MAX-01 (maximum internal test): the closed-door proof the docstring
        # always promised — fetch the SAME validation url WITHOUT the token.
        # A url that opens just as wide anonymously (Juice Shop's live-caught
        # /rest/user/whoami -> 200 {"user":{}} with ANY token, even garbage)
        # proves NOTHING about the token; accepting it mislabels an anonymous
        # scan as "authenticated". Accept only a real differential: the anon
        # fetch is blocked (401/403, transport error, or login-gate bounce)
        # OR the success marker appears only in the tokened body.
        r_anon = self.engine.send(RequestMutation(
            endpoint=Endpoint(url=self.p.login_url, method="GET"),
            note="auth-validate-anon"))
        anon_blocked = bool(r_anon.error) or r_anon.status in (401, 403)
        if not r_anon.error:
            hop_a = r_anon.hop_location()
            if hop_a and self.p.login_marker.lower() in urllib.parse.urlsplit(hop_a).path.lower():
                anon_blocked = True
        marker_diff = bool(self.p.success_marker) and (
            self.p.success_marker.lower() in (r.body or "").lower()
            and self.p.success_marker.lower() not in (r_anon.body or "").lower())
        if not (anon_blocked or marker_diff):
            self.state.last_error = (f"validation url proves nothing: anonymously "
                                     f"accessible with no marker differential "
                                     f"(anon status={r_anon.status}) on {self.p.login_url}")
            self.bus.emit("AuthFailed", reason="validation_proves_nothing",
                          error=self.state.last_error)
            return False
        # accepted: arm the header on every subsequent engine request
        self.engine.default_headers[self.p.auth_header] = hv
        self.state.authenticated = True
        self.bus.emit("Authenticated", mode="token", header=self.p.auth_header,
                      landing=self.p.login_url, logins=self.state.logins)
        return True


class TokenWatchdogProxy:
    """AUTH-05 honest watchdog: counts 401/403 responses that arrive while the
    token is armed (possible expiry mid-scan). No re-auth is possible — the
    count lands in stats.auth.rejections so the report can say "token surface
    may have degraded after N rejections" instead of claiming a clean scan."""

    def __init__(self, inner: RequestEngine, token_engine: TokenAuthEngine):
        self._inner, self._tok = inner, token_engine

    def send(self, m: RequestMutation):
        r = self._inner.send(m)
        if self._tok.state.authenticated and r is not None and r.status in (401, 403):
            self._tok.rejections += 1
            self._tok.bus.emit("TokenRejected", url=m.endpoint.url, status=r.status,
                               rejections=self._tok.rejections)
        return r

    def __getattr__(self, name):
        return getattr(self._inner, name)

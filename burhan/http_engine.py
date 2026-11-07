"""Phase 2: Request/Response Engine + Phase 3: Scope enforcement.
Scanners never build HTTP requests directly — they emit RequestMutations.
"""
from __future__ import annotations
import http.client, ipaddress, json, re, socket, ssl, time, urllib.parse, uuid
from dataclasses import dataclass, field
from .core import Endpoint, EventBus, ParamKind, ParamLocation, ScopeRule, VERSION, is_private_ip

DEFAULT_TIMEOUT = 12.0
# Engine fingerprint — OAST-channel detectors use it to reject SELF-callbacks
# (ENG-08): the engine follows same-host redirects, so an open-redirect target can
# bounce our probe URL back at the listener and WE fetch it. That callback carries
# this exact UA and must never count as target-side evidence.
USER_AGENT = f"Mozilla/5.0 (compatible; Burhan/{VERSION}; +security-scanner)"

# v4.2.1 request journal bounds: passive raw capture for independent external
# verification packages. JOURNAL_MAX entries per scan (a full v420 testfire scan
# issued 538 requests — 6000 leaves 11x headroom); body excerpts capped at
# JOURNAL_BODY_LIMIT chars per side (request and response independently).
JOURNAL_MAX = 6000
JOURNAL_BODY_LIMIT = 4000

# OWSP-15 (OWASP campaign, live-caught on DVWA 3.x): destructive-pair guard.
# The scanner's BASE request (params at discovered values, both empty) on DVWA's
# CSRF form — GET /vulnerabilities/csrf/?password_new=&password_conf=&Change=Change
# — COMMITTED a password change to md5(''): the app compares the pair for
# equality and empty==empty passes. A scanner must never send equal values for
# password-ish confirm pairs (empty-empty included): the second member is
# deterministically made unequal. Applies to query pairs, form bodies and JSON
# objects at render time — the single choke point every request passes through
# (batteries, baselines, verifier replays, csrf probes alike).
_DESTRUCT_PASS_RE = re.compile(r"(pass(word|wd)?|pwd|secret)", re.I)
_DESTRUCT_CONF_RE = re.compile(r"(conf|confirm|verify|repeat|retype|again|_?2$)", re.I)


def _destructive_pair_guard(pairs):
    """pairs: list[(name, value)] -> guarded list. Deterministic, order-stable."""
    out = list(pairs)
    for i, (ni, vi) in enumerate(out):
        if not _DESTRUCT_PASS_RE.search(ni):
            continue
        for j, (nj, vj) in enumerate(out):
            if j == i or nj == ni:
                continue
            if _DESTRUCT_CONF_RE.search(nj) and str(vj) == str(vi):
                out[j] = (nj, (str(vj) + "-burhan-unequal") if str(vj) else "burhan-unequal-b")
    return out


# ---------------------------------------------------------------- Mutations
@dataclass
class RequestMutation:
    """A single, replayable modification of an endpoint's request."""
    endpoint: Endpoint
    param_name: str = ""
    param_location: ParamLocation = ParamLocation.QUERY
    param_value: str = ""
    method: str = ""
    body_override: str = ""
    extra_headers: dict = field(default_factory=dict)
    note: str = ""
    # OWSP-32 (NodeGoat round, live-caught on /research?url=&symbol=): the
    # target gated its server-side fetch behind `if (req.query.symbol)` while
    # symbol's DISCOVERED base value was EMPTY — every probe that mutated `url`
    # shipped symbol= (falsy) and never executed the fetch code path. When this
    # flag is set (SSRF filler variant), empty sibling QUERY params render with
    # a benign constant, mirroring the DISC-04 body-field fill. Default OFF so
    # every other battery renders byte-identically to before.
    fill_query_siblings: bool = False


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    url: str = ""
    error: str = ""
    request_id: str = ""
    redirect_chain: list = field(default_factory=list)   # ENG-01: [(status, absolute_url)] per followed hop

    @property
    def ok(self): return 200 <= self.status < 300

    def hop_location(self) -> str:
        """ENG-01: first-hop redirect target, whether the engine followed it or not.
        The engine auto-follows same-host redirects and returns the FINAL response —
        the original Location (e.g. a login-bypass oracle 302) used to be destroyed.
        This restores it deterministically without changing follow behavior."""
        if self.redirect_chain:
            return self.redirect_chain[0][1]
        return (self.headers or {}).get("location") or (self.headers or {}).get("Location") or ""


class RequestEngine:
    """Owns transport, timeouts, redirects, scope re-check after every hop.
    ENG-05: session cookie jar — Set-Cookie harvested from responses is replayed
    on subsequent same-host requests, mirroring a real browser session. This is
    the substrate that makes CSRF-protected flows and (Phase 51) authenticated
    scanning reachable; without it the server rejects every request that needs
    a session before the vulnerable code path is ever exercised."""
    def __init__(self, scope: ScopeRule, bus: EventBus, timeout: float = DEFAULT_TIMEOUT,
                 adaptive_timeout: float | None = None, default_headers: dict | None = None,
                 allow_insecure_tls: bool = False):
        self.scope, self.bus, self.timeout = scope, bus, adaptive_timeout or timeout
        self.base_timeout = timeout
        self.requests_sent = 0
        self.cookie_jar: dict[str, dict[str, str]] = {}   # host -> {name: value}
        # OWSP-11 (OWASP campaign, live-caught on the OWASP Benchmark): cookie
        # PATH tracking. The jar used to replay every harvested cookie on every
        # request to the host, ignoring the Set-Cookie Path attribute — an app
        # that sets a per-page cookie (the Benchmark: one cookie per test case,
        # ~3000 of them) flooded every later request with a multi-KB Cookie
        # header, the server 400-rejected it (Tomcat 8KB header limit; measured
        # live: 3895x400 vs 638x200 on big-cookie requests), and the whole
        # active scan produced zero findings while LOOKING complete (257k
        # requests, 100% coverage). RFC 6265 path-match semantics + a bounded
        # jar restore browser-accurate behavior.
        self.cookie_paths: dict[str, dict[str, str]] = {}  # host -> {name: path}
        self.cookie_order: dict[str, list[str]] = {}       # host -> insertion order (LRU cap)
        self.JAR_CAP = 256                                 # per-host cookie cap
        self.jar_evictions = 0                             # honest counter (journal/stats)
        # AUTH-05 (Phase 54): headers injected into EVERY request (Bearer token auth).
        # Applied before per-endpoint/extra headers so a specific probe can override.
        self.default_headers: dict[str, str] = dict(default_headers or {})
        # ENG-09 (Phase 54): rate-limit resilience — 429/503 answers are a WAF/CDN
        # telling us to slow down, not an application response. Hammering through
        # them gets the source IP blocked mid-scan; the scan degrades to errors.
        # Deterministic exponential backoff honoring Retry-After, capped retries.
        self.max_rate_retries = 3
        self.rate_limited = 0          # 429/503 responses seen
        self.rate_limit_retries = 0    # actual retry sleeps performed
        self.rate_limit_recovered = 0  # retries that then got a normal status
        # R15-2: honest transport accounting. A scan where EVERY request died
        # on the network (refused/reset/timeout) used to look identical to a
        # successful empty scan — exit 0, zero findings, no signal. These
        # counters give the caller what it needs to refuse fake success.
        self.transport_errors = 0               # requests ending in error Responses
        self.transport_error_kinds: dict[str, int] = {}  # kind -> count
        # RT-02 fix (audit-rb-1): TLS peer verification is ON by default.
        # The old ctx (check_hostname=False + CERT_NONE) let a live MITM with a
        # self-signed certificate intercept engine requests and capture the
        # Authorization header (proven live, results/audit/). Insecure mode is
        # now an explicit, warned opt-in for targets with genuinely broken
        # certificates — never a silent default.
        self.allow_insecure_tls = allow_insecure_tls
        self._ctx = ssl.create_default_context()
        if allow_insecure_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
            bus.emit("InsecureTLSWarning",
                     msg="allow_insecure_tls=True: TLS certificate verification "
                         "DISABLED for this engine — a man-in-the-middle can "
                         "intercept traffic and capture credentials; use only "
                         "against owned test targets on trusted networks")
        else:
            self._ctx.check_hostname = True
            self._ctx.verify_mode = ssl.CERT_REQUIRED
            self._ctx.load_default_certs()
        # ---- v4.2.1: request journal (supervisor directive 2026-10-03) ----
        # Passive raw capture so scan results carry the raw request/response
        # pair behind every request_id — the substrate for INDEPENDENT external
        # verification packages. NEVER read by any detection/verification code
        # path (zero effect on verdicts; proven by the v4.2.1 gates: bench
        # verdicts bit-identical to v4.2.0, full suite green).
        # Attached to the EventBus: per-scan isolation in serve mode (every
        # engine on the same bus — main, authz identities, workflow fresh
        # sessions, graphql anon — shares ONE journal). Bounded: JOURNAL_MAX
        # entries, oldest-run overflow counted honestly in
        # stats.request_journal_dropped. request = the FIRST request as issued
        # (ENG-09 retries reuse the rid; the FINAL response overwrites).
        if not hasattr(bus, "request_journal"):
            bus.request_journal = {}
            bus.request_journal_dropped = 0

    # ---- build concrete URL/body from mutation
    def _render(self, m: RequestMutation) -> tuple[str, str, dict, str]:
        ep = m.endpoint
        q = [(p.name, p.value) for p in ep.parameters if p.location == ParamLocation.QUERY]
        body = m.body_override
        # ENG-06 (live-caught on demo.testfire.net/doLogin): a request with NO mutation
        # target (param_name empty — baseline fetches, and Phase 51 login requests) used
        # to go out with an EMPTY body even when the endpoint carried BODY/JSON params,
        # so credential POSTs transmitted nothing and the app rejected every one. The
        # engine must serialize the endpoint's own body fields in the request shape the
        # endpoint declares, exactly like a browser submitting that form.
        if not m.param_name and not m.body_override and (m.method or ep.method) in ("POST", "PUT", "PATCH"):
            bfields = [p for p in ep.parameters
                       if p.location in (ParamLocation.BODY, ParamLocation.JSON)]
            if bfields:
                if all(p.location == ParamLocation.JSON for p in bfields):
                    import json as _json
                    _jobj = {p.name: (p.value or "") for p in bfields}
                    _jobj = dict(_destructive_pair_guard(list(_jobj.items())))
                    body = _json.dumps(_jobj)
                else:
                    _bf = _destructive_pair_guard([(p.name, p.value or "") for p in bfields])
                    body = urllib.parse.urlencode(_bf)
        if m.param_name:
            # ENG-02: inherit the param's ACTUAL location from the endpoint definition.
            # Old code trusted m.param_location (default QUERY), so probes aimed at POST
            # body params were sent as URL query with an EMPTY body — the payload never
            # reached the app (live-caught: doLogin auth-bypass oracle invisible).
            eff_loc = m.param_location
            for p in ep.parameters:
                if p.name == m.param_name:
                    eff_loc = p.location
                    break
            hit = False
            q = []
            for p in ep.parameters:
                if p.location == ParamLocation.QUERY:
                    if p.name == m.param_name and eff_loc == ParamLocation.QUERY:
                        q.append((p.name, m.param_value)); hit = True
                    elif (getattr(m, "fill_query_siblings", False)
                          and not (p.value or "") and not p.flow_control
                          and p.kind not in (ParamKind.TOKEN, ParamKind.NUMERIC)
                          and not getattr(p, "is_file", False)):
                        # OWSP-32: empty companions often gate behavior
                        # (`if (req.query.x)`) — a probe that leaves them
                        # empty can structurally never execute the sink.
                        q.append((p.name, "1"))
                    else:
                        q.append((p.name, p.value))
            if not hit and eff_loc == ParamLocation.QUERY:
                q.append((m.param_name, m.param_value))
            if eff_loc == ParamLocation.BODY and not m.body_override:
                # DISC-04 (live-caught on demo.testfire.net/doLogin): sibling body fields
                # with EMPTY default values made apps reject early (Altoro requires a
                # non-empty password before the SQL path is even reached) — the oracle
                # never fired. Deterministic fill: empty sibling body fields get a
                # benign constant so the app processes the request normally.
                fields = [(p.name, p.value or "burhan") for p in ep.parameters
                          if p.location == ParamLocation.BODY]
                if not any(f[0] == m.param_name for f in fields):
                    fields.append((m.param_name, m.param_value))
                fields = [(m.param_name, m.param_value) if f[0] == m.param_name else f for f in fields]
                fields = _destructive_pair_guard(fields)
                body = urllib.parse.urlencode(fields)
            # ENG-04 (live-proven on ginandjuice.shop /catalog/subscribe): JS-built
            # forms POST JSON (JSON.stringify + Content-Type application/json) — a
            # body-param endpoint silently sent x-www-form-urlencoded is rejected
            # by every JSON API, hiding the whole surface. Params with JSON location
            # render as a JSON object; siblings (e.g. harvested CSRF tokens) ride along.
            elif eff_loc == ParamLocation.JSON and not m.body_override:
                obj = {p.name: (p.value if p.value else "") for p in ep.parameters
                       if p.location == ParamLocation.JSON}
                obj[m.param_name] = m.param_value
                obj = dict(_destructive_pair_guard(list(obj.items())))
                import json as _json
                body = _json.dumps(obj)
        parsed = urllib.parse.urlsplit(ep.url)
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        # MAX-11 (maximum internal test, live-caught via the gql fixture):
        # a bare Endpoint(url='...?a=1&b=2') with no parsed parameters used to
        # render WITHOUT its query string — the URL's own query pairs are now
        # preserved for any name the parameter list does not cover (callers
        # like TokenAuthEngine build bare endpoints from URLs that carry state
        # in the query; the auth validation silently degraded to "unknown
        # operation" and MAX-01 then honestly refused the token).
        _covered = {p.name for p in ep.parameters
                    if p.location == ParamLocation.QUERY}
        for _k, _v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if _k not in _covered and _k != m.param_name:
                q.append((_k, _v))
        # MAX-05 (maximum internal test, live-caught on Juice Shop 20.2.0):
        # PATH-located endpoint parameters substitute into the URL template on
        # EVERY render — the endpoint's own value for baseline/passive fetches,
        # the mutation's value when the probe targets that param. Previously
        # only an explicit m.param_location==PATH triggered substitution, which
        # no caller set, so /rest/basket/{id} shipped with literal braces.
        for p in ep.parameters:
            if p.location == ParamLocation.PATH:
                val = m.param_value if (m.param_name == p.name and m.param_value) \
                    else (p.value or "1")
                base = base.replace("{" + p.name + "}",
                                    urllib.parse.quote(str(val), safe=""))
        # OWSP-15: destructive-pair guard on the FINAL query string (GET forms
        # carry password pairs in the URL — DVWA's csrf form is method=GET).
        q = _destructive_pair_guard(q)
        url = base + ("?" + urllib.parse.urlencode(q) if q else "")
        if m.param_location == ParamLocation.PATH and m.param_name:
            url = url.replace("{" + m.param_name + "}", urllib.parse.quote(m.param_value, safe=""))
        headers = {"User-Agent": USER_AGENT}
        headers.update(self.default_headers)   # AUTH-05: session-wide auth headers
        # OWSP-07 (OWASP campaign, live-caught on the OWASP Benchmark): HEADER- and
        # COOKIE-located parameters had NO dispatch branch in _render — a mutation
        # targeting one was silently DROPPED (the scan looked like it ran; the
        # payload never shipped). Declared header params now render as request
        # headers (the mutation's payload when targeted, the declared default
        # otherwise); an explicit param_location on a bare endpoint (verifier
        # replays build bare Endpoints) dispatches the same way.
        for p in ep.parameters:
            if p.location == ParamLocation.HEADER:
                val = m.param_value if (m.param_name == p.name and m.param_value is not None) \
                    else (p.value if p.value is not None else "")
                headers[p.name] = str(val)
        if m.param_name and m.param_location == ParamLocation.HEADER \
                and not any(p.name == m.param_name and p.location == ParamLocation.HEADER
                            for p in ep.parameters):
            headers[m.param_name] = str(m.param_value)
        # OWSP-07 (cont.): COOKIE-located parameters render into the Cookie header.
        # The session jar is the base (ENG-05 semantics preserved — sibling cookies
        # ride along); a mutation's payload ALWAYS wins for its cookie name; a
        # declared default only fills names the jar does not carry (the server-
        # issued value is the truth when it exists). _dispatch's setdefault leaves
        # this explicit Cookie header intact.
        cparams = [p for p in ep.parameters if p.location == ParamLocation.COOKIE]
        if (cparams or (m.param_name and m.param_location == ParamLocation.COOKIE)) \
                and not getattr(m, "skip_jar", False):
            host = urllib.parse.urlsplit(url).hostname or ""
            req_path = urllib.parse.urlsplit(url).path or "/"
            # OWSP-11: path-scoped jar base — only path-matching cookies ride along
            jar = {}
            _full = self.cookie_jar.get(host, {})
            _paths = self.cookie_paths.get(host, {})
            for k, v in _full.items():
                if self._path_match(_paths.get(k, "/"), req_path):
                    jar[k] = v
            for p in cparams:
                if m.param_name == p.name and m.param_value is not None:
                    jar[p.name] = str(m.param_value)
                elif p.name not in jar and p.value:
                    jar[p.name] = str(p.value)
            if m.param_name and m.param_location == ParamLocation.COOKIE \
                    and m.param_name not in jar:
                jar[m.param_name] = str(m.param_value)
            # OWSP-36 (live-caught on the Benchmark cmdi category): cookie VALUES
            # carrying battery payloads ('; echo $((6*7))') went out RAW — the
            # header breaks at the first ';' and Tomcat truncates the value (the
            # payload never reached the servlet). ONLY the characters that break
            # a Cookie header are percent-encoded: the ';' and ',' separators,
            # whitespace, the quote, backslash, '%' (it would read as an encoding)
            # and control bytes. '=' '+' '/' ':' ride RAW (legal value bytes — a
            # broader set rewrote session ids and broke authenticated flows).
            _CK_BREAK = re.compile(r"[;,\s\"\\%\x00-\x1f\x7f]")
            def _ck(v: str) -> str:
                v = str(v)
                return _CK_BREAK.sub(lambda mm: "%%%02X" % ord(mm.group(0)), v)
            headers["Cookie"] = "; ".join(f"{k}={_ck(v)}" for k, v in sorted(jar.items()))
        # ENG-03 (live-caught on demo.testfire.net/doLogin): http.client does NOT add
        # Content-Type for bodies — Tomcat then never parses the POST body, silently
        # hiding the entire POST attack surface. Required per HTML form spec.
        # ENG-04: JSON-location bodies get application/json (the request shape the
        # target's own JavaScript would have produced).
        # ENG-10 (live-caught by the Phase 55 NoSQL detector): the rule used to skip
        # body_override requests entirely — a full-JSON body_override probe (operator
        # injection battery) went out as x-www-form-urlencoded and every JSON API
        # rejected it with 400 before the payload was ever parsed. An override that
        # itself parses as JSON on a JSON-location endpoint IS a JSON request.
        if body and (m.method or ep.method) in ("POST", "PUT", "PATCH"):
            json_ep = any(p.location == ParamLocation.JSON for p in ep.parameters)
            override_is_json = False
            if m.body_override:
                try:
                    import json as _jprobe
                    _jprobe.loads(m.body_override)
                    override_is_json = True
                except Exception:
                    override_is_json = False
            if (json_ep and (not m.body_override or override_is_json)):
                headers.setdefault("Content-Type", "application/json")
            else:
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        headers.update(ep.headers); headers.update(m.extra_headers)
        return url, m.method or ep.method, headers, body

    # ---- scope gate (checked BEFORE request and AFTER every redirect)
    def _scope_ok(self, url: str) -> tuple[bool, str]:
        p = urllib.parse.urlsplit(url)
        if p.scheme not in self.scope.allowed_schemes:
            return False, f"scheme {p.scheme} not allowed"
        host = p.hostname or ""
        # OWSP-22 (OWASP campaign, live-caught on Mutillidae II 2.12.7): the
        # allowed_domains suffix-match was NESTED inside the allowed_hosts
        # branch — with the default scan configuration (allowed_domains=
        # [target host], allowed_hosts=[]) NO host restriction ran at all.
        # A PayPal donation form on the Mutillidae front page became an
        # endpoint and the batteries sent 140 unauthorized POSTs to
        # www.paypal.com production, plus a false VERIFIED SQLi finding
        # against the third party. Both lists now gate INDEPENDENTLY:
        # allowed_hosts (if set) must contain the host; allowed_domains
        # (if set) must suffix-match. Neither set = no host restriction
        # (the pre-existing public-scan semantic, unchanged).
        host_ok = (not self.scope.allowed_hosts) or (host in self.scope.allowed_hosts)
        if host_ok and self.scope.allowed_domains:
            host_ok = any(host == d or host.endswith("." + d)
                          for d in self.scope.allowed_domains)
        if not host_ok:
            return False, f"host {host} outside allowed set"
        if self.scope.allowed_ports and p.port and p.port not in self.scope.allowed_ports:
            return False, f"port {p.port} not allowed"
        for dp in self.scope.denied_paths:
            if p.path.startswith(dp):
                return False, f"path matches denied prefix {dp}"
        if not self.scope.allow_private and is_private_ip(host):
            return False, f"private/localhost host {host} blocked by scope policy"
        return True, ""

    def _pin_target(self, host, scheme, port):
        """RT-01 TOCTOU fix (ORD-001-REMAND item 2): resolve ONCE, validate
        EVERY answer against the RT-01 guard, return (pinned_address, None)
        or (None, reason). Fail-closed on any ambiguity — the same doctrine
        as core.is_private_ip. The caller pins the transport to the returned
        address; http.client never resolves the name again."""
        if not host:
            return None, "empty host"
        bare = host.strip().strip("[]")
        try:
            ipaddress.ip_address(bare)
            addrs = [bare]                     # IP literal: no DNS at all
            literal = True
        except ValueError:
            literal = False
        if not literal:
            try:
                ais = socket.getaddrinfo(
                    bare, port or (443 if scheme == "https" else 80),
                    0, socket.SOCK_STREAM)
            except Exception as exc:
                return None, (f"dns-unresolvable "
                              f"({type(exc).__name__}: {exc})")[:120]
            addrs = [a[4][0] for a in ais if a and a[4]]
            if not addrs:
                return None, "dns-empty-answer"
        if not self.scope.allow_private:
            for a in addrs:
                if is_private_ip(a):
                    return None, (f"resolved {a} unsafe for {host} "
                                  f"(rebind-guard)")[:120]
        if not addrs:
            return None, "no addresses"

        def _order(a):
            try:
                o = ipaddress.ip_address(a)
                return (o.version, int(o))
            except ValueError:
                return (9, 0)

        # deterministic pin: same answer set -> same pinned address,
        # regardless of resolver ordering (bench determinism).
        pinned = sorted(set(addrs), key=_order)[0]
        return pinned, None

    @staticmethod
    def _authority_header(host, scheme, port):
        """Host header value: the ORIGINAL authority — brackets for v6,
        non-default port kept, never the pinned IP."""
        hh = f"[{host}]" if (":" in host and not host.startswith("[")) else host
        default = 443 if scheme == "https" else 80
        if port and port != default:
            hh = f"{hh}:{port}"
        return hh

    def _harvest_cookies(self, getheaders, host: str, req_path: str = "/"):
        """ENG-05: collect every Set-Cookie (http.client yields them as separate
        header tuples — a dict comprehension silently keeps only the LAST one).
        OWSP-11: also record each cookie's Path attribute (RFC 6265 §5.1.4: absent
        Path defaults to the request URI's directory) and bound the jar per host
        (LRU by insertion order, honest eviction counter — a cookie-flooding app
        must never drown every subsequent request)."""
        for k, v in getheaders():
            if k.lower() != "set-cookie":
                continue
            first, _, rest = v.partition(";")
            if "=" not in first:
                continue
            n, _, val = first.partition("=")
            name, value = n.strip(), val.strip()
            # Path attribute (case-insensitive attr name; default = request dir)
            path = None
            for attr in rest.split(";"):
                if "=" not in attr:
                    continue
                a, _, av = attr.partition("=")
                if a.strip().lower() == "path" and av.strip().startswith("/"):
                    path = av.strip()
                    break
            if path is None:
                # RFC 6265 default-path: up to but not including the last '/'
                dp = req_path.rsplit("/", 1)[0]
                path = dp if dp.startswith("/") else "/"
            jar = self.cookie_jar.setdefault(host, {})
            paths = self.cookie_paths.setdefault(host, {})
            order = self.cookie_order.setdefault(host, [])
            if name not in jar:
                order.append(name)
            jar[name] = value
            paths[name] = path
            while len(order) > self.JAR_CAP:
                victim = order.pop(0)
                jar.pop(victim, None)
                paths.pop(victim, None)
                self.jar_evictions += 1

    @staticmethod
    def _path_match(cookie_path: str, req_path: str) -> bool:
        """RFC 6265 §5.1.4 path-match: exact; or cookie-path is a prefix of the
        request path and cookie_path ends with '/'; or cookie-path + '/' is a
        prefix of the request path."""
        if cookie_path == req_path:
            return True
        if req_path.startswith(cookie_path) and cookie_path.endswith("/"):
            return True
        if req_path.startswith(cookie_path + "/"):
            return True
        return False

    def _cookie_header(self, host: str, req_path: str = None) -> str:
        """ENG-05 replay, OWSP-11 path-scoped: only cookies whose Path
        path-matches the request path ride along (absent Path = '/' matches
        everything, preserving pre-OWSP-11 behavior for path-less cookies)."""
        jar = self.cookie_jar.get(host)
        if not jar:
            return ""
        if req_path is None:
            # legacy callers (no path context) keep whole-host replay
            return "; ".join(f"{k}={v}" for k, v in sorted(jar.items()))
        paths = self.cookie_paths.get(host, {})
        out = []
        for k, v in sorted(jar.items()):
            cp = paths.get(k, "/")
            if self._path_match(cp, req_path):
                out.append(f"{k}={v}")
        return "; ".join(out)

    def send(self, m: RequestMutation) -> Response:
        url, method, headers, body = self._render(m)
        ok, why = self._scope_ok(url)
        if not ok:
            self.bus.emit("RequestBlockedByScope", url=url, reason=why)
            return Response(status=0, url=url, error="scope:" + why)
        rid = "req-" + uuid.uuid4().hex[:8]
        # ENG-09: retry loop around the transport. The request is IDENTICAL on every
        # attempt (same rid, same body — determinism preserved); only the schedule
        # changes. Retry-After (seconds form) wins over the exponential ladder; the
        # ladder is 0.4 * 2^n capped at 8s, max 3 retries — then we return the last
        # 429/503 response HONESTLY (the caller sees what the server actually said,
        # never a fabricated error).
        attempt, ladder = 0, 0.4
        while True:
            resp = self._dispatch(url, method, headers, body, rid,
                                  skip_jar=getattr(m, "skip_jar", False))
            if resp is not None and resp.status in (429, 503) and attempt < self.max_rate_retries:
                attempt += 1
                self.rate_limited += 1
                ra_raw = (resp.headers or {}).get("retry-after", "")
                try:
                    delay = float(int(ra_raw)) if ra_raw.strip().isdigit() else min(ladder, 8.0)
                except ValueError:
                    delay = min(ladder, 8.0)
                self.rate_limit_retries += 1
                self.bus.emit("RateLimitedBackoff", url=url, attempt=attempt,
                              delay=round(delay, 2), retry_after=bool(ra_raw.strip()))
                time.sleep(delay)
                ladder *= 2
                continue
            if attempt and resp is not None and resp.status not in (429, 503):
                self.rate_limit_recovered += 1
            elif resp is not None and resp.status in (429, 503):
                self.rate_limited += 1
            return resp

    def _dispatch(self, url: str, method: str, headers: dict, body: str, rid: str,
                  skip_jar: bool = False) -> Response:
        t0 = time.time()
        self.requests_sent += 1
        jr = getattr(self.bus, "request_journal", None)
        try:
            parsed = urllib.parse.urlsplit(url)
            # ENG-05: replay session cookies for this host (browser-equivalent session)
            ck = "" if skip_jar else self._cookie_header(parsed.hostname or "", parsed.path or "/")
            if ck:
                headers.setdefault("Cookie", ck)
            # RT-01 TOCTOU fix (ORD-001-REMAND item 2, Option A): resolve
            # ONCE, validate EVERY answer, pin the transport to the validated
            # address. The original authority rides in Host; http.client never
            # resolves the target name again.
            pinned, pin_err = self._pin_target(
                parsed.hostname, parsed.scheme, parsed.port)
            if pin_err is not None:
                self.bus.emit("RequestBlockedByScope", url=url,
                              reason=f"pin: {pin_err}")
                return Response(status=0, url=url,
                                error=f"scope:pin:{pin_err}",
                                elapsed=time.time() - t0, request_id=rid)
            headers.setdefault("Host", self._authority_header(
                parsed.hostname, parsed.scheme, parsed.port))
            if parsed.scheme == "https":
                conn = _PinnedHTTPSConnection(
                    parsed.hostname, parsed.port, self.timeout, self._ctx, pinned)
            else:
                conn = _PinnedHTTPConnection(
                    parsed.hostname, parsed.port, self.timeout, pinned)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            # v4.2.1 journal: record the request exactly as issued (headers incl.
            # the session Cookie; body capped). Created once per rid — ENG-09
            # retries reuse the rid and never duplicate the entry.
            if jr is not None and rid not in jr:
                self._journal_put(jr, rid, method, url, headers, body, path)
            conn.request(method, path, body=body if method in ("POST", "PUT", "PATCH") else None, headers=headers)
            r = conn.getresponse()
            raw = r.read(2_000_000)
            # GTP-09b (mechanism, live-bisected on the bench fixture): a stateless
            # probe must not HARVEST either — on the fixture it fetched /wf pages
            # anonymously, the server rotated a FRESH session, the jar adopted it,
            # and the authenticated workflow walk lost its session (0 flows vs 3,
            # 8 business_logic FNs). skip_jar = read-only on ALL session state.
            if not skip_jar:
                self._harvest_cookies(r.getheaders, parsed.hostname or "", parsed.path or "/")
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            # ---- redirect handling with scope re-check (Phase 3 requirement)
            hops = 0
            chain = []                                        # ENG-01: preserve oracle info
            while r.status in (301, 302, 303, 307, 308) and "location" in hdrs and hops < self.scope.max_redirects:
                nxt = urllib.parse.urljoin(url, hdrs["location"])
                chain.append((r.status, nxt))
                ok2, why2 = self._scope_ok(nxt)
                if not ok2:
                    self.bus.emit("RedirectBlockedByScope", url=nxt, reason=why2)
                    break
                pu = urllib.parse.urlsplit(nxt)
                if pu.hostname != parsed.hostname and not self.scope.follow_cross_host:
                    break
                conn.close()
                hop_pinned, hop_err = self._pin_target(
                    pu.hostname, pu.scheme, pu.port)
                if hop_err is not None:
                    self.bus.emit("RedirectBlockedByScope", url=nxt,
                                  reason=f"pin: {hop_err}")
                    break
                if pu.scheme == "https":
                    conn = _PinnedHTTPSConnection(
                        pu.hostname, pu.port, self.timeout, self._ctx, hop_pinned)
                else:
                    conn = _PinnedHTTPConnection(
                        pu.hostname, pu.port, self.timeout, hop_pinned)
                # ENG-07 (live-caught via fixture v5 /doLogin): the hop request used to
                # reuse the ORIGINAL request's Cookie header, so cookies issued ON the
                # redirect response (login flows rotate the session: Set-Cookie SESS=s2
                # + AUTH=... on a 302) never reached the landing page — the hop arrived
                # anonymous and bounced straight back to the login gate. Rebuild the
                # Cookie header from the CURRENT jar for every hop, exactly like a
                # browser following a redirect chain.
                hop_headers = dict(headers)
                # RT-01 TOCTOU: the hop re-routes — Host follows the HOP authority
                # (an inherited caller Host would point the virtual host at the
                # wrong origin; overwriting is the honest redirect semantic).
                hop_headers["Host"] = self._authority_header(
                    pu.hostname, pu.scheme, pu.port)
                ck2 = self._cookie_header(pu.hostname or "", pu.path or "/")
                if ck2:
                    hop_headers["Cookie"] = ck2
                conn.request("GET", pu.path + ("?" + pu.query if pu.query else ""), headers=hop_headers)
                r = conn.getresponse(); raw = r.read(2_000_000)
                self._harvest_cookies(r.getheaders, pu.hostname or "", pu.path or "/")
                hdrs = {k.lower(): v for k, v in r.getheaders()}
                url = nxt; hops += 1
            conn.close()
            resp = Response(status=r.status, headers=hdrs, body=raw.decode("utf-8", "replace"),
                            elapsed=time.time() - t0, url=url, request_id=rid,
                            redirect_chain=chain)
            # v4.2.1 journal: the FINAL response as returned to the caller
            # (after redirect hops; the chain preserves the hop URLs/bodies).
            if jr is not None and rid in jr:
                jr[rid]["response"] = {
                    "status": resp.status,
                    "headers": dict(resp.headers or {}),
                    "body": (resp.body or "")[:JOURNAL_BODY_LIMIT],
                    "redirect_chain": [list(hop) for hop in (resp.redirect_chain or [])],
                    "elapsed_ms": round(resp.elapsed * 1000, 1),
                }
            self.bus.emit("ResponseReceived", request_id=rid, url=url, status=r.status,
                          bytes=len(raw), ms=int(resp.elapsed * 1000))
            return resp
        except (socket.timeout, TimeoutError) as e:
            self.bus.emit("RequestTimeout", url=url, timeout=self.timeout)
            self._count_transport_error("timeout")
            if jr is not None and rid in jr:
                jr[rid]["response"] = {"error": f"timeout:{type(e).__name__}"}
            return Response(url=url, error=f"timeout:{type(e).__name__}", elapsed=time.time() - t0, request_id=rid)
        except Exception as e:
            self.bus.emit("RequestError", url=url, error=f"{type(e).__name__}: {e}"[:200])
            # R15-2: classify by family so the honest exit-code logic can tell
            # "target dead" (refused/reset) from "TLS mismatch" from "DNS"
            kind = "refused" if "refused" in str(e).lower() else \
                   "reset" if "reset" in str(e).lower() else \
                   "tls" if "ssl" in type(e).__name__.lower() else "other"
            self._count_transport_error(kind)
            if jr is not None and rid in jr:
                jr[rid]["response"] = {"error": f"{type(e).__name__}: {e}"[:200]}
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200], elapsed=time.time() - t0, request_id=rid)

    def _count_transport_error(self, kind: str) -> None:
        self.transport_errors += 1
        self.transport_error_kinds[kind] = self.transport_error_kinds.get(kind, 0) + 1

    # ---- v4.2.1: journal writer (passive capture, bounded) ----
    # RT-05 fix (audit-rb-1): credential-bearing headers must never land in the
    # journal (and thus in evidence packages / report bundles) in plaintext.
    # The journal is the substrate for EXTERNAL verification — it leaves the
    # machine, so it must carry the request SHAPE, not the secrets inside it.
    _SENSITIVE_HEADERS = frozenset({
        'authorization', 'x-api-key', 'cookie',
        'x-auth-token', 'proxy-authorization',
    })

    def _journal_put(self, jr: dict, rid: str, method: str, url: str,
                     headers: dict, body: str, path: str) -> None:
        if len(jr) >= JOURNAL_MAX:
            self.bus.request_journal_dropped = getattr(self.bus, "request_journal_dropped", 0) + 1
            return
        safe_headers = {
            k: ('[REDACTED]' if k.lower() in self._SENSITIVE_HEADERS
                else v)
            for k, v in headers.items()
        }
        ct = next((v for k, v in headers.items()
                   if k.lower() == "content-type"), "")
        jr[rid] = {
            "request": {
                "method": method,
                "url": url,
                "path": path,
                "headers": safe_headers,
                # RT-05 (headers) + ORD-001-REMAND item 3 (bodies): the
                # journal carries the request SHAPE, never the secrets
                # inside it — on either side of the request.
                "body": sanitize_request_body(
                    (body or "")[:JOURNAL_BODY_LIMIT], ct),
            },
            "response": None,
        }


# ---- RT-01 TOCTOU / DNS-rebinding pin (ORD-001-REMAND item 2, Option A) ----
# The pre-remand engine (post RT-01 string-match fix) still handed the NAME
# to http.client, which resolved DNS a SECOND time at connect — between the
# scope check and the connect the answer could change (DNS rebinding; proven
# RED live in scripts/rt01_toctou_proof.py: the guard resolved a PUBLIC
# address, http.client resolved 127.0.0.1 and the engine fetched the EVIL
# listener's body). The ordered fix: the engine resolves ONCE per request,
# validates EVERY answer against the RT-01 guard, and pins the transport to
# the validated address. The original hostname rides in the Host header
# (http) and in SNI + certificate hostname validation (https —
# wrap_socket(server_hostname=host)) — pinning never breaks TLS SNI, so
# Option A covers both schemes and no HONEST_BOUNDARIES carve-out is needed
# for the TLS case.
class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Socket opens to the VALIDATED address; the Host header (set by
    _dispatch) carries the original authority."""

    def __init__(self, host, port, timeout, pinned):
        super().__init__(host, port, timeout=timeout)
        self._pinned = pinned

    def connect(self):
        self.sock = self._create_connection((self._pinned, self.port),
                                            self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Same pin; TLS keeps SNI + certificate hostname validation bound to
    the ORIGINAL hostname (server_hostname=self.host — the RT-02 CERT_REQUIRED
    fix validates the certificate against the name, never against the IP)."""

    def __init__(self, host, port, timeout, context, pinned):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned = pinned

    def connect(self):
        self.sock = self._create_connection((self._pinned, self.port),
                                            self.timeout)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock,
                                              server_hostname=self.host)


# ---- request-body sanitization (ORD-001-REMAND item 3) ---------------------
# The journal is the substrate for EXTERNAL verification — it leaves the
# machine inside every evidence package, so it must carry the request's
# SHAPE, never the secrets inside it (the same doctrine as the RT-05
# header redaction, extended to bodies). The WIRE request is never
# modified — redaction is journal-side only (auth flows and probes are
# untouched), exactly like the RT-05 headers.
SENSITIVE_BODY_KEYS = frozenset((
    "password", "passwd", "secret", "token", "credit_card", "cvv", "ssn",
))
BODY_REDACTED = "[REDACTED]"
BINARY_BODY_OMITTED = "[BINARY_BODY_OMITTED_FOR_SECURITY]"
_BINARY_CONTENT_TYPES = frozenset((
    "application/octet-stream", "multipart/form-data",
))
_BINARY_KEEP_UNDER = 1024          # the ORDERED exception: < 1KB stays verbatim
_JSON_VALUE_RE = re.compile(
    r'("(?:' + "|".join(sorted(SENSITIVE_BODY_KEYS)) + r')"\s*:\s*)'
    r'("(?:[^"\\]|\\.)*"|[^"\s,\}\]]+)', re.IGNORECASE)


def _redact_json_obj(o):
    if isinstance(o, dict):
        return {k: (BODY_REDACTED if str(k).lower() in SENSITIVE_BODY_KEYS
                    else _redact_json_obj(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_json_obj(x) for x in o]
    return o


def sanitize_request_body(body: str, content_type: str) -> str:
    """Journal-side redaction of request bodies. Ordered families:
    form-urlencoded and JSON -> sensitive-key values become [REDACTED]
    (structural JSON walk with a regex fallback for capped/invalid JSON);
    binary (application/octet-stream) and multipart/form-data -> bodies
    >= 1KB are logged as [BINARY_BODY_OMITTED_FOR_SECURITY], < 1KB stay
    verbatim (the ORDERED exception); every other content type is journaled
    verbatim as before (documented boundary in HONEST_BOUNDARIES.md)."""
    if body is None:
        return ""
    b = body if isinstance(body, str) else str(body)
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct == "application/x-www-form-urlencoded":
        out = []
        for pair in b.split("&"):
            k, sep, v = pair.partition("=")
            key = urllib.parse.unquote_plus(k).strip().lower()
            if sep and key in SENSITIVE_BODY_KEYS:
                out.append(f"{k}={BODY_REDACTED}")
            else:
                out.append(pair)
        return "&".join(out)
    if ct == "application/json":
        try:
            return json.dumps(_redact_json_obj(json.loads(b)),
                              ensure_ascii=False)
        except (ValueError, TypeError):
            # capped or invalid JSON: best-effort regex redaction so a cut
            # body still never carries a secret verbatim
            return _JSON_VALUE_RE.sub(
                lambda m: m.group(1) + f'"{BODY_REDACTED}"', b)
    if ct in _BINARY_CONTENT_TYPES:
        if len(b.encode("utf-8", "replace")) < _BINARY_KEEP_UNDER:
            return b
        return BINARY_BODY_OMITTED
    return b


def make_session_cookie_ep(ep: Endpoint, cookies: dict) -> Endpoint:
    """Phase 6: Session/Auth — clone endpoint with session cookies attached."""
    import copy
    c = copy.deepcopy(ep); c.cookies.update(cookies); c.auth_context = "session"
    return c

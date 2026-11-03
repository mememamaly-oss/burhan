"""Burhan v4.1.1 — GraphQL Intelligence Engine (Phase V41-03 + V411-GL).

GraphQL is the single most common "invisible API" in modern applications: one
endpoint, arbitrary operations, nothing a path-shaped scanner can see. Before
v4.1.0 Burhan was structurally blind to it — a /graphql endpoint was just
another POST surface.

This engine gives GraphQL first-class treatment with the same honesty
discipline as every other Burhan engine:

    DISCOVER     observed endpoints whose path is GraphQL-shaped + JS-extracted
                 fetch/axios URLs + a deterministic probe of well-known paths
    MODEL        introspection (when the target allows it) -> the operation
                 inventory: queries, mutations, arguments, field types
    TEST         a bounded, planner-gated battery:
                   anonymous access          can an unauthenticated client
                                             execute queries at all?
                   BOLA                      can identity B read identity A's
                                             objects by id?
                   field-level authorization do responses carry
                                             sensitive-vocab fields to a
                                             low-privilege identity?
                   mutation authorization    can a mutation execute without
                                             its required privilege?
                   introspection exposure    schema fully readable? (policy-
                                             gated finding, never silent)
    PROVE        every finding carries request->response->verification
                 evidence (the response payload itself, canary-marked)
    BOUNDARY     everything not testable is RECORDED, never guessed:
                   introspection disabled          -> UNTESTABLE schema unavailable
                   mutation needs absent privilege -> UNTESTABLE (explicit)
                   no second identity configured   -> UNTESTABLE BOLA
                   no GraphQL endpoint observed    -> NOT_DISCOVERED

Safety: every operation the engine sends passes the Safe Attack Planner.
Queries are READ_ONLY; mutations are STATE_CHANGING (require --logic-active);
delete-shaped mutations are DESTRUCTIVE and never sent. No finding is ever
based on schema alone — request -> response -> verification or nothing.

Deterministic: fixed probe list, fixed operation ordering, canary values.
"""
from __future__ import annotations

import json
import re
import urllib.parse

from .core import Endpoint, DiscoverySource, Evidence, Finding, Severity, \
    FindingStatus, Verification, ParamKind, ParamLocation, Parameter

# ------------------------------------------------------------------ vocabulary
GQL_PATH_RE = re.compile(r"(graphql|gql|graphi?ql)", re.I)
# V411-GL-06: a static asset whose PATH merely contains "graphql" (e.g.
# /static/jquery/graphql.js — GraphiQL's client bundle) is NOT an endpoint.
# Discovered live on DVGA: the JS file masqueraded as an "observed"
# candidate and poisoned the boundary report with a false
# "introspection disabled" record. Only a URL that can carry a POST
# operation may be a candidate.
STATIC_ASSET_RE = re.compile(
    r"\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|html?|txt|pdf|"
    r"mp[34]|webm|zip|gz|tgz|tar)([?#]|$)", re.I)
WELL_KNOWN_PATHS = ("/graphql", "/api/graphql", "/graphql/v1", "/gql")
PROBE_QUERY = {"query": "{__typename}"}
SENSITIVE_FIELD_RE = re.compile(
    r"(password|passwd|pwd|secret|token|ssn|social|salary|private[_-]?key|"
    r"api[_-]?key|credit[_-]?card|card[_-]?number|iban)", re.I)
ID_ARG_RE = re.compile(r"^(id|.*[_-]id|uid|userid|user[_-]?id|account[_-]?id)$", re.I)

# ---- V411-GL: SQL-injection oracle vocabulary (signatures that a SQL engine,
# not the application, produced the message) and value-shape disciplines.
SQLI_ERROR_RE = re.compile(
    r"(sqlite3\.|mysql|mariadb|psycopg2|postgres|oracle|db2|sqlalchemy|"
    r"\(sqlite3\.|OperationalError|ProgrammingError|IntegrityError|"
    r"you have an error in your sql syntax|unterminated quoted string|"
    r"near \".*\": syntax error|unclosed quotation mark)", re.I)
SQL_ECHO_RE = re.compile(r"\[SQL:|SELECT .+ FROM |INSERT INTO |WHERE .*=", re.I | re.S)
OR_TRUE_PAYLOAD = "x' or '1'='1"
QUOTE_PAYLOAD = "x'''"
# ---- V411-GL-02: command-execution probes. ONLY alphanumeric flag values are
# ever sent (ps/whoami-class read-only diagnostics) — a metacharacter never
# leaves the engine. Detection = OS command output shapes in the response.
CMD_OP_NAME_RE = re.compile(r"(system|debug|diagnos|exec|cmd|run|shell|health)", re.I)
PS_HEADER_RE = re.compile(r"USER\s+PID\s+%CPU|%MEM\s+.*COMMAND|COMMAND\s*$", re.I)
CMD_OUTPUT_RE = re.compile(
    r"(USER\s+PID\s+%CPU|\n\s*\d+\s+\S+\s+\d\d:\d\d\s|"
    r"load average:|^[\w.-]+\s+%CPU\s+|/usr/\S+|\bpts/\d+\b)", re.I | re.M)
# ---- V411-GL-03: a sensitive-named field counts as exposed ONLY when it
# carries a REAL value — masked/placeholder/redacted values are a boundary.
MASKED_VALUE_RE = re.compile(
    r"^(\*+|x+|\.+|-+|null|none|n/?a|redacted|hidden|masked|"
    r"\[?protected\]?|\[?redacted\]?|\[?hidden\]?|not available|unavailable)$", re.I)
STATE_SHAPED_QUERY_RE = re.compile(
    r"(delete|remove|destroy|purge|wipe|drop|reset|burn|truncate|clear)", re.I)
# V411-GL-07: a mutation is EXERCISABLE only when its name is
# additive/auth-shaped (create/register/login/upload class). Everything
# else — edit/update-shaped (overwrites rows), import/fetch-shaped (makes
# the server issue outbound requests), send/post-shaped (side effects on
# other components) — is recorded as BLOCKED_BY_SAFETY and never sent.
# Discovered while hardening for the DVGA live campaign: the previous
# delete|remove|... vocabulary let editPaste-class mutations execute.
ADDITIVE_MUTATION_RE = re.compile(
    r"(create|register|signup|sign[_-]?up|login|signin|sign[_-]?in|"
    r"authenticate|token|upload|add)", re.I)
INTROSPECTION_QUERY = """
query BurhanIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields(includeDeprecated: true) {
        name
        args { name type { kind name ofType { kind name ofType { kind name } } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}"""

# planner note prefixes -> impact classification (planner.py maps wf-* notes;
# gql-* notes are classified here explicitly and gated through planner.gate)
STATE_CHANGING = "STATE_CHANGING"


# ------------------ v4.2.0 VF-04: graphql proof protocol ------------------
# A GraphQL finding's `passed` flag is DERIVED from raw observations by
# _derive_gql(), NEVER stamped by the caller. Every call site MUST pass
# proof={"rule": <closed-set name>, "obs": {...raw...}}; a missing proof,
# an unknown rule, or a failed derivation raises / yields REJECTED —
# mechanism, not convention.
def _derive_gql(proof: dict) -> bool:
    rule, obs = proof["rule"], proof.get("obs") or {}
    if rule == "introspection-enumerated":
        return (obs.get("queries", 0) + obs.get("mutations", 0)) > 0
    if rule == "sql-error-signature":
        return bool(SQLI_ERROR_RE.search(obs.get("body") or ""))
    if rule == "row-differential":
        return (obs.get("or_rows", 0) > obs.get("base_rows", 0)
                and '"errors"' not in (obs.get("or_body") or "")[:80])
    if rule == "cmd-output-pattern":
        v = obs.get("value")
        return isinstance(v, str) and bool(CMD_OUTPUT_RE.search(v))
    if rule == "marker-in-object":
        obj_str, marker = str(obs.get("obj_str") or ""), str(obs.get("marker") or "")
        return bool(obj_str) and (marker in obj_str if marker
                                  else bool(obs.get("no_marker_verdict")))
    if rule == "sensitive-response":
        return (obs.get("exposed", 0) > 0) or (obs.get("hits", 0) > 0)
    if rule == "executed-no-errors":
        return bool(obs.get("data_present")) and not obs.get("errors")
    if rule == "stored-marker-roundtrip":
        # V4.3.3 (DVGA campaign): a mutation-carried HTML marker survived the
        # write->read cycle AND was served back with its tag structure intact
        # (the stored-XSS oracle) — and a FRESH marker reproduced it (2-round).
        return (bool(obs.get("read_marker")) and obs.get("rounds", 0) >= 2
                and bool(obs.get("replay_marker")))
    if rule == "field-suggestion-echo":
        # V4.3.3: a near-miss field name got a "Did you mean <real field>"
        # error — the schema leaks its vocabulary through suggestions
        return (bool(obs.get("suggestion")) and bool(obs.get("real_field"))
                and obs.get("reproduced", False))
    raise ValueError(f"unknown graphql proof rule {rule!r} — add an explicit "
                     "derivation branch in _derive_gql (fail-closed)")


def _gql_finding(vtype: str, severity: Severity, url: str, param: str,
                 evidence: Evidence, notes: str, query: str = "",
                 response: str = "", proof: dict | None = None) -> Finding:
    if not isinstance(proof, dict) or "rule" not in proof or "obs" not in proof:
        raise ValueError(
            "graphql findings REQUIRE an explicit proof: "
            "proof={'rule': ..., 'obs': {...}} — the passed flag is DERIVED "
            "from raw observations by _derive_gql (v4.2.0 VF-04); stamped "
            "passed=True is forbidden")
    delta = _derive_gql(proof)
    f = Finding(vtype, severity, url, param, "POST", [evidence],
                status=FindingStatus.CANDIDATE)
    f.verification = Verification(
        method=f"graphql:response-verification:{proof['rule']}",
        passed=delta, confidence=0.9 if delta else 0.15, rounds=1,
        notes=notes + f" | derived={proof['rule']}")
    f.status = FindingStatus.VERIFIED if delta else FindingStatus.REJECTED
    f.state_before = (query or "")[:160]
    f.state_after = (response or "")[:160]
    return f


def _type_name(t: dict | None) -> str:
    """Resolve a GraphQL introspection type reference to its base name."""
    t = t or {}
    return t.get("name") or _type_name(t.get("ofType"))


def _arg_literal(arg: dict, value) -> str:
    """Render a value as a GraphQL literal for the argument's declared type.
    V411-GL-08 (live-caught against DVGA): an Int/numeric-ID argument MUST
    receive an unquoted literal — json.dumps(str(id)) emitted paste(id: "15"),
    which GraphQL validation rejects (string into Int), silently killing
    every BOLA probe. Numbers go bare, strings stay quoted."""
    t = (arg.get("type") or "").strip()
    s = str(value)
    if t in ("Int", "Int!", "Float", "Float!") \
            or (t in ("ID", "ID!") and s.lstrip("-").isdigit()):
        return s
    return json.dumps(s)


def _unwrap_non_null(t: dict | None) -> dict | None:
    """Strip NON_NULL / LIST wrappers -> the inner type ref."""
    while isinstance(t, dict) and t.get("kind") in ("NON_NULL", "LIST"):
        t = t.get("ofType") or {}
    return t


class GraphqlClient:
    """Transport for GraphQL over the standard request engine (scope-gated,
    cookie-carrying, rate-limit-resilient — never a raw socket).

    ENG-11 (live-caught on DVGA): GraphQL bodies MUST travel as
    application/json. The first implementation created BODY-located params,
    so the engine stamped the request x-www-form-urlencoded and every real
    GraphQL server rejected/ignored the operation — the fixture accepted it
    (it json-parses regardless of Content-Type), which is exactly why only a
    LIVE target could expose this."""

    def __init__(self, engine):
        self.engine = engine

    def query(self, url: str, query: str, variables: dict | None = None,
              note: str = "gql-query", method: str = "POST"):
        body = {"query": query}
        if variables:
            body["variables"] = variables
        params = [Parameter("query", ParamLocation.JSON, json.dumps(body)).classify(),
                  Parameter("variables", ParamLocation.JSON, "").classify()]
        ep = Endpoint(url=url, method=method, source=DiscoverySource.MANUAL,
                      parameters=params)
        from .http_engine import RequestMutation
        m = RequestMutation(endpoint=ep, note=note, body_override=json.dumps(body),
                            method=method,
                            extra_headers={"Content-Type": "application/json"})
        if method == "GET":
            m = RequestMutation(endpoint=Endpoint(
                url=url + "?query=" + urllib.parse.quote(query), method="GET",
                source=DiscoverySource.MANUAL), note=note)
        return self.engine.send(m)


class GraphqlEngine:
    """Discovery + model + bounded planner-gated battery + honest boundaries."""

    def __init__(self, engine, scope, bus, timeout: float = 12.0,
                 planner=None, boundary=None, coverage=None,
                 logic_active: bool = False, report_introspection: bool = True):
        self.engine = engine          # the AUTHENTICATED main engine
        self.scope = scope
        self.bus = bus
        self.timeout = timeout
        self.planner = planner
        self.boundary = boundary
        self.coverage = coverage
        self.logic_active = logic_active
        self.report_introspection = report_introspection
        self.client = GraphqlClient(engine)
        self.requests = 0

    # ------------------------------------------------------------ discovery
    def discover(self, endpoints: list, base_url: str) -> list[dict]:
        """Candidates = observed GraphQL-shaped endpoints (static assets
        excluded, each VALIDATED by a live probe) + a deterministic
        well-known-path probe. Returns [{url, source}] — no dedup against the
        endpoint map here; the orchestrator merges the surfaced endpoints.
        A URL is a candidate ONLY when it actually answered a GraphQL
        operation: a path-shaped guess that fails validation is not a
        GraphQL endpoint and generates no boundary noise."""
        found: dict[str, dict] = {}
        origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(base_url))
        for ep in endpoints:
            path = urllib.parse.urlsplit(ep.url).path or ""
            if not GQL_PATH_RE.search(path):
                continue
            if STATIC_ASSET_RE.search(path):
                continue          # V411-GL-06: asset paths are never endpoints
            url = ep.url.split("?")[0]
            if url in found:
                continue
            base = self._requests(lambda: self.client.query(
                url, PROBE_QUERY["query"], note="gql-validate-observed"))
            if self._looks_graphql(base):
                found[url] = {"url": url, "source": "observed"}
        for p in WELL_KNOWN_PATHS:
            url = origin + p
            if url in found:
                continue
            base = self._requests(lambda: self.client.query(
                url, PROBE_QUERY["query"], note="gql-probe"))
            if self._looks_graphql(base):
                found[url] = {"url": url, "source": "probe"}
        return sorted(found.values(), key=lambda c: c["url"])

    def _looks_graphql(self, r) -> bool:
        if r is None or r.error or not r.body:
            return False
        body = (r.body or "").lstrip()
        if body.startswith("{"):
            try:
                j = json.loads(body)
                # a GraphQL response carries "data" (the __typename probe
                # answers with it); a JSON error body alone is NOT proof —
                # REST APIs answer {"errors": [...]} too
                if isinstance(j, dict) and "data" in j:
                    return True
            except Exception:
                pass
        return False

    def _requests(self, fn):
        before = getattr(self.engine, "requests_sent", 0)
        out = fn()
        self.requests += getattr(self.engine, "requests_sent", 0) - before
        return out

    # ------------------------------------------------------------ model
    def introspect(self, url: str) -> dict | None:
        """Full introspection (authenticated engine). None when disabled."""
        r = self._requests(lambda: self.client.query(
            url, INTROSPECTION_QUERY.strip(), note="gql-introspection"))
        if not self._looks_graphql(r):
            return None
        try:
            payload = json.loads((r.body or "").lstrip())
        except Exception:
            return None
        # "data": null with errors is the SPEC-LEGAL GraphQL error shape
        # (DVGA answers introspection exactly this way, run 41312545521):
        # .get("data", {}) returns None — the key EXISTS with a null
        # value, the default only covers MISSING keys
        if payload.get("errors") and not (payload.get("data") or {}).get("__schema"):
            return None
        schema = ((payload.get("data") or {}).get("__schema") or {})
        if not schema.get("types"):
            return None
        return schema

    def operations(self, schema: dict) -> dict:
        """The operation inventory: queries + mutations with arg shapes and
        selectable fields (the return type's own fields, with their type
        names for V411-GL-12 nested selection building)."""
        types = {t.get("name"): t for t in schema.get("types", [])
                 if isinstance(t, dict)}
        self._schema_types = types          # V411-GL-12: selection recursion
        out = {"queries": [], "mutations": []}
        qname = ((schema.get("queryType") or {}).get("name")) or "Query"
        mname = ((schema.get("mutationType") or {}).get("name")) or "Mutation"
        for kind, tname in (("queries", qname), ("mutations", mname)):
            t = types.get(tname) or {}
            for fld in (t.get("fields") or []):
                if not isinstance(fld, dict) or fld.get("name", "").startswith("__"):
                    continue
                ret = _unwrap_non_null(fld.get("type"))
                ret_name = _type_name(ret)
                ret_type = types.get(ret_name) or {}
                fields_info = []
                for f2 in (ret_type.get("fields") or []):
                    if isinstance(f2, dict) and f2.get("name") \
                            and not f2.get("name").startswith("__"):
                        fields_info.append((f2.get("name"),
                                            _type_name(_unwrap_non_null(f2.get("type")))))
                args = []
                for a in (fld.get("args") or []):
                    if not isinstance(a, dict):
                        continue
                    at = _unwrap_non_null(a.get("type"))
                    args.append({"name": a.get("name"),
                                 "type": _type_name(at),
                                 "kind": at.get("kind")})
                out[kind].append({"name": fld.get("name"), "args": args,
                                  "return_type": ret_name,
                                  "fields": [n for n, _ in fields_info][:6],
                                  "field_types": dict(fields_info[:6])})
            out[kind] = sorted(out[kind], key=lambda o: o["name"])
        return out

    # ------------------------------------------------------------ battery
    def _arg_value_for(self, arg: dict, seq: int) -> str | int | None:
        """A deterministic, harmless value for one argument shape."""
        t = (arg.get("type") or "").lower()
        if t in ("int", "int!", "id", "id!"):
            return seq
        if "string" in t or t in ("id",):
            return "burhan-%d" % seq
        return None

    def _selection(self, op: dict) -> str:
        fields = op.get("fields") or ["__typename"]
        if not fields:
            fields = ["__typename"]
        return " ".join(fields[:4])

    def _selection_set(self, op: dict) -> str:
        """V411-GL-12 (live-caught on DVGA): nested-type selection set.
        Scalar fields render plain; an OBJECT field needs its OWN sub-
        selection — createPaste returns CreatePaste { paste: PasteObject },
        so the valid shape is { paste { id title } }, never { paste } and
        never the parent's field names on the child type. One bounded level
        of recursion (depth 2), deterministic order, __typename fallback.
        V411-GL-12b: the schema's TYPES registry also carries SCALAR entries
        (built-in AND custom like DVGA's DateTime) — kind, not presence in
        the registry, decides plain vs nested (a selection on the custom
        DateTime scalar was a live-caught 400)."""
        types = getattr(self, "_schema_types", {}) or {}
        out = []
        for fname in (op.get("fields") or [])[:4]:
            ftype = (op.get("field_types") or {}).get(fname) or ""
            kind = (types.get(ftype) or {}).get("kind")
            if ftype in self._SCALARS or kind in (None, "SCALAR"):
                out.append(fname)
                continue
            sub = [f2.get("name") for f2 in
                   (types.get(ftype, {}).get("fields") or [])
                   if isinstance(f2, dict) and f2.get("name")
                   and not f2.get("name").startswith("__")][:3]
            out.append("%s { %s }" % (fname,
                                       " ".join(sub) if sub else "__typename"))
        return " ".join(out) if out else "__typename"

    def _args_literal(self, op: dict, seq: int = 1) -> str:
        """V411-GL-13 (live-caught on DVGA): every argument the engine can
        value renders — REQUIRED arguments were being dropped by a flat
        [:3] cap (createPaste's title is arg #4; a selection-perfect
        mutation still 400'd as 'title is required'). Bounded at 8; args
        without a harmless value (objects, booleans) are skipped exactly as
        before."""
        parts = [f"{a['name']}: {json.dumps(self._arg_value_for(a, seq))}"
                 for a in (op.get("args") or [])[:8]
                 if self._arg_value_for(a, seq) is not None]
        return ", ".join(parts)

    def _op_query(self, op: dict, args_literal: str, keyword: str = "query") -> str:
        """V411-GL-11 (live-caught on DVGA): type-aware operation rendering.
        An OBJECT/LIST return REQUIRES a selection set — graphene answers a
        selection-less object query with HTTP 400, so every object-returning
        probe was invisible (createPaste never executed, users/pastes/audits
        never answered anonymously). A SCALAR return must NOT carry one —
        a selection on String is equally a 400 (the systemDebug SQLi probe
        never truly ran). One renderer, every battery, both rules.
        V411-GL-12: the selection itself is nested-type aware."""
        head = "%s(%s)" % (op["name"], args_literal) if args_literal else op["name"]
        if (op.get("return_type") or "") in self._SCALARS:
            return "%s { %s }" % (keyword, head)
        return "%s { %s { %s } }" % (keyword, head, self._selection_set(op))

    @staticmethod
    def _read_shaped(ops: dict) -> list[dict]:
        """V411-GL-09 (live-caught while hardening for DVGA): the read-shaped
        filter MUST gate EVERY battery that constructs queries from the
        operation inventory. The sqli/features/anon-BOLA batteries had it;
        the anonymous, BOLA and field-authz batteries did NOT — on a schema
        whose Query type carries deleteAllPastes / readAndBurn (state
        semantics INSIDE read operations, DVGA's exact shape) they would
        have EXECUTED destructive vocabulary. Uniform gate, one definition."""
        return [q for q in ops["queries"]
                if not STATE_SHAPED_QUERY_RE.search(q["name"] or "")]

    def _record_boundary(self, category, target, state, reason, **kw):
        if self.boundary is not None:
            self.boundary.record(category, target, state, reason,
                                 evidence=kw.get("evidence", ""),
                                 provenance=kw.get("provenance", "graphql"),
                                 remediation=kw.get("remediation", ""))

    def run(self, endpoints: list, base_url: str,
            anonymous_engine=None, low_identity: dict | None = None,
            primary_identity: dict | None = None) -> dict:
        """The full GraphQL pass. Returns {findings, stats, candidates, ops}."""
        stats = {"enabled": True, "candidates": 0, "endpoints": [],
                 "introspected": 0, "queries": 0, "mutations": 0,
                 "tests": 0, "requests": 0, "boundaries": 0}
        findings: list[Finding] = []
        candidates = self.discover(endpoints, base_url)
        ops_by_url: dict[str, dict] = {}
        stats["candidates"] = len(candidates)
        if not candidates:
            self._record_boundary("graphql", base_url, "NOT_DISCOVERED",
                                  "no GraphQL endpoint observed (path-shape, "
                                  "JS extraction and well-known probes all empty)",
                                  provenance="graphql:discovery")
            stats["requests"] = self.requests
            return {"findings": findings, "stats": stats,
                    "candidates": [], "ops": {}}
        for cand in candidates:
            url = cand["url"]
            stats["endpoints"].append({"url": url, "source": cand["source"]})
            if self.coverage is not None:
                ep = Endpoint(url=url, method="POST", source=DiscoverySource.MANUAL)
                self.coverage.discover(ep)
                self.coverage.dim_discover("graphql", url, {"source": cand["source"]})
            schema = self.introspect(url)
            if schema is None:
                # honest boundary: no schema, no operation inventory
                self._record_boundary(
                    "graphql/schema", url, "UNTESTABLE",
                    "introspection disabled or unavailable - the operation "
                    "inventory cannot be learned",
                    remediation="provide the schema (spec seed) or enable "
                                "introspection in a staging environment",
                    provenance="graphql:introspection")
                if self.coverage is not None:
                    self.coverage.dim_untested("graphql", url,
                                               "schema_unavailable")
                stats["boundaries"] += 1
                continue
            stats["introspected"] += 1
            ops = self.operations(schema)
            ops_by_url[url] = ops
            stats["queries"] += len(ops["queries"])
            stats["mutations"] += len(ops["mutations"])
            # introspection exposure (policy-gated, never silent about policy)
            if self.report_introspection:
                f = _gql_finding(
                    "graphql_introspection_enabled", Severity.LOW, url,
                    "__schema",
                    Evidence("schema_introspection_open",
                             "the full schema is readable via introspection: "
                             f"{len(ops['queries'])} queries and "
                             f"{len(ops['mutations'])} mutations enumerated — "
                             "the application's entire API surface is "
                             "disclosable to any client that can query it",
                             ""),
                    "introspection query succeeded and was parsed",
                    response=f"{len(ops['queries'])} queries / "
                             f"{len(ops['mutations'])} mutations enumerated",
                    proof={"rule": "introspection-enumerated",
                           "obs": {"queries": len(ops['queries']),
                                   "mutations": len(ops['mutations'])}})
                findings.append(f)
            findings += self._battery(url, ops, anonymous_engine,
                                      low_identity, primary_identity, stats)
        stats["requests"] = self.requests
        stats["tests_run"] = stats["tests"]
        return {"findings": findings, "stats": stats, "candidates": candidates,
                "ops": ops_by_url}

    # ------------------------------------------------------------ tests
    # V411-GL-03: value-aware sensitive-field detection. A sensitive-named
    # key counts as EXPOSED only when it carries a real (unmasked) value.
    # Returns (exposed_pairs, masked_names) — both honest, both recorded.
    @staticmethod
    def _sensitive_fields(payload_str: str):
        exposed, masked = [], []
        try:
            obj = json.loads(payload_str)
        except Exception:
            return exposed, masked

        def walk(node, path=""):
            if isinstance(node, dict):
                for k, v in node.items():
                    p = f"{path}.{k}" if path else str(k)
                    if SENSITIVE_FIELD_RE.search(str(k)):
                        vs = "" if v is None else str(v)
                        if v is None or vs == "" or MASKED_VALUE_RE.match(vs.strip()):
                            masked.append(str(k))
                        else:
                            exposed.append((str(k), vs[:80]))
                    walk(v, p)
            elif isinstance(node, list):
                for item in node[:5]:
                    walk(item, path)
        walk(obj)
        return exposed, sorted(set(masked))

    # V411-GL-01: SQL injection through the GraphQL transport. Read-shaped
    # QUERY string arguments only — never mutations (a quote can write
    # through an INSERT/UPDATE argument), never state-shaped names.
    def _sqli_battery(self, url, ops, stats) -> list[Finding]:
        findings: list[Finding] = []
        queries = [q for q in ops["queries"]
                   if not STATE_SHAPED_QUERY_RE.search(q["name"] or "")]
        if not queries:
            return findings
        if len(queries) > 6:
            # FM-05 (first-match audit): the [:6] cap was silent — read-shaped
            # queries beyond the sixth left the battery without a recorded
            # trace (the ZOMBIE_PROBE_CAP leftover-boundary pattern, applied).
            self._record_boundary(
                "graphql/sqli", url, "NOT_SUPPORTED",
                f"{len(queries) - 6} read-shaped queries left unprobed "
                f"(battery cap 6, documented)",
                provenance="graphql:sqli-cap")
        for q in queries[:6]:
            str_args = [a for a in q["args"]
                        if "string" in (a.get("type") or "").lower()
                        or (a.get("type") or "") in ("ID",)]
            if not str_args:
                continue
            arg = str_args[0]
            # baseline (no match expected) — a deterministic benign value
            base_val = "burhannomatch%d" % 1
            qt = self._op_query(q, "%s: %s" % (arg["name"], json.dumps(base_val)))
            r_base = self._requests(lambda: self.client.query(
                url, qt, note="gql-sqli-base"))
            stats["tests"] += 1
            base_body = (r_base.body or "") if r_base is not None else ""
            base_rows = self._row_count(base_body, q["name"])
            # (a) error-signature probe: a quote triple that breaks SQL syntax
            qt_err = self._op_query(q, "%s: %s" % (arg["name"], json.dumps(QUOTE_PAYLOAD)))
            r_err = self._requests(lambda: self.client.query(
                url, qt_err, note="gql-sqli-error"))
            stats["tests"] += 1
            err_body = (r_err.body or "") if r_err is not None else ""
            m = SQLI_ERROR_RE.search(err_body)
            if m:
                echo = bool(SQL_ECHO_RE.search(err_body))
                findings.append(_gql_finding(
                    "graphql_sql_injection", Severity.CRITICAL, url,
                    "%s.%s" % (q["name"], arg["name"]),
                    Evidence("sql_error_signature_in_graphql_response",
                             "the string argument '%s' of query '%s' broke the "
                             "backend SQL (error signature '%s'%s) — the "
                             "response carries the database engine's own "
                             "message: %s" % (
                                 arg["name"], q["name"], m.group(0),
                                 " with the SQL statement echoed" if echo else "",
                                 err_body[:240]),
                             ""),
                    "quote-break probe returned a database error signature "
                    "through the GraphQL error payload (error-based oracle)",
                    query=qt_err, response=err_body[:240],
                    proof={"rule": "sql-error-signature", "obs": {"body": err_body}}))
                continue                      # error oracle proven — enough
            # (b) boolean differential: OR-TRUE vs baseline row count
            qt_or = self._op_query(q, "%s: %s" % (arg["name"], json.dumps(OR_TRUE_PAYLOAD)))
            r_or = self._requests(lambda: self.client.query(
                url, qt_or, note="gql-sqli-boolean"))
            stats["tests"] += 1
            or_body = (r_or.body or "") if r_or is not None else ""
            or_rows = self._row_count(or_body, q["name"])
            # a genuine differential: the OR-TRUE payload returns rows the
            # benign baseline cannot (and is not an error body)
            if or_rows > base_rows and "errors" not in (or_body or "")[:80]:
                findings.append(_gql_finding(
                    "graphql_sql_injection", Severity.CRITICAL, url,
                    "%s.%s" % (q["name"], arg["name"]),
                    Evidence("boolean_differential_oracle",
                             "the string argument '%s' of query '%s' changes "
                             "the result set when a tautology is injected: "
                             "baseline (benign value) = %d result item(s), "
                             "OR-TRUE payload '%s' = %d result item(s) — the "
                             "argument reaches a SQL predicate unsanitized "
                             "(boolean-based blind oracle)" % (
                                 arg["name"], q["name"], base_rows,
                                 OR_TRUE_PAYLOAD, or_rows),
                             ""),
                    "OR-TRUE payload produced a larger result set than the "
                    "benign baseline (boolean differential verified)",
                    query=qt_or, response=or_body[:240],
                    proof={"rule": "row-differential",
                           "obs": {"base_rows": base_rows, "or_rows": or_rows,
                                   "or_body": or_body}}))
                continue
            if r_base is not None:
                self._record_boundary(
                    "graphql/injection", "%s.%s" % (url, q["name"]), "TESTED",
                    "quote-break and OR-TRUE probes produced no SQL error "
                    "signature and no boolean differential on the first "
                    "string argument",
                    evidence=(err_body or base_body)[:120],
                    provenance="graphql:sqli-probe")
        return findings

    @staticmethod
    def _row_count(body: str, field: str) -> int:
        try:
            payload = json.loads((body or "").lstrip())
        except Exception:
            return -1
        data = (payload.get("data") or {}).get(field)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            return 1
        return 0 if data is None else 1

    # V411-GL-02: command execution through system/debug-shaped query
    # arguments. ONLY safe alphanumeric flag values are transmitted ("aux",
    # "whoami" class) — the engine never sends a metacharacter.
    _SCALARS = {"String", "Int", "Float", "Boolean", "ID"}

    def _cmdexec_battery(self, url, ops, stats) -> list[Finding]:
        findings: list[Finding] = []
        for q in ops["queries"]:
            if not CMD_OP_NAME_RE.search(q["name"] or ""):
                continue
            scalar_ret = (q.get("return_type") or "") in self._SCALARS
            for a in q["args"][:2]:
                t = (a.get("type") or "").lower()
                if "string" not in t:
                    continue
                qt = ('query { %s(%s: "aux") }' % (q["name"], a["name"]) ) \
                    if scalar_ret else \
                    ('query { %s(%s: "aux") { __typename } }'
                     % (q["name"], a["name"]))
                r = self._requests(lambda: self.client.query(
                    url, qt, note="gql-cmdexec"))
                stats["tests"] += 1
                body = (r.body or "") if r is not None else ""
                try:
                    payload = json.loads((body or "").lstrip())
                    value = (payload.get("data") or {}).get(q["name"])
                except Exception:
                    value = None
                if isinstance(value, str) and CMD_OUTPUT_RE.search(value):
                    findings.append(_gql_finding(
                        "graphql_command_execution", Severity.CRITICAL, url,
                        "%s.%s" % (q["name"], a["name"]),
                        Evidence("os_command_output_in_response",
                                 "query '%s' answered with operating-system "
                                 "command output when its argument was set to "
                                 "the read-only flag 'aux' — response value: "
                                 "%s — the argument reaches an OS command "
                                 "execution sink (no metacharacter was sent; "
                                 "the output alone proves execution)" % (
                                     q["name"], value[:240]),
                                 ""),
                        "safe flag probe returned OS process-list output "
                        "(command-execution sink verified)",
                        query=qt, response=value[:240],
                        proof={"rule": "cmd-output-pattern", "obs": {"value": value}}))
                    break
            if findings:
                break
        if not findings:
            self._record_boundary(
                "graphql/command-execution", url, "TESTED",
                "no system/debug-shaped query answered with OS command output "
                "for safe flag probes",
                provenance="graphql:cmdexec-probe")
        return findings

    # V411-GL-04: exercise the protocol surface once — variables, fragments,
    # aliases and a nested selection. Not a finding: a COVERAGE account of
    # which GraphQL operation features the endpoint actually processed.
    def _features_probe(self, url, ops, stats) -> None:
        queries = [q for q in ops["queries"]
                   if not STATE_SHAPED_QUERY_RE.search(q["name"] or "")]
        # V411-GL-11: fragments spread on OBJECT types only — a scalar-return
        # query cannot carry one (a selection on String is a validation error)
        queries = [q for q in queries
                   if (q.get("return_type") or "") not in self._SCALARS]
        if not queries:
            self._record_boundary("graphql/features", url, "NOT_APPLICABLE",
                                  "no read-shaped object-returning query "
                                  "available for the operation-features probe "
                                  "(fragments require an object type)",
                                  provenance="graphql:features")
            return
        # FM-06 (first-match audit): the probe used the FIRST object-returning
        # query in schema order — an accident when a later query carries the
        # string/ID argument that exercises the variables feature. Prefer the
        # first arg-carrying query (deterministic shape preference, still ONE
        # request); an arg-less schema still gets the no-arg variant.
        q = next((c for c in queries
                  if any("string" in (a.get("type") or "").lower()
                         or (a.get("type") or "") in ("ID",)
                         for a in (c.get("args") or []))), queries[0])
        arg = next((a for a in q["args"]
                    if "string" in (a.get("type") or "").lower()
                    or (a.get("type") or "") in ("ID",)), None)
        if arg is not None:
            qvar = ('query F($v: String) { alias1: %s(%s: $v) { ...burhanF } } '
                    'fragment burhanF on %s { %s }'
                    % (q["name"], arg["name"],
                       q.get("return_type") or "__typename", self._selection_set(q)))
            r = self._requests(lambda: self.client.query(
                url, qvar, variables={"v": "burhanvar1"}, note="gql-features"))
            stats["tests"] += 1
            ok_vars = r is not None and not r.error and \
                '"errors"' not in (r.body or "")[:200]
        else:
            qvar = ('query { alias1: %s { ...burhanF } } '
                    'fragment burhanF on %s { %s }'
                    % (q["name"], q.get("return_type") or "__typename",
                       self._selection_set(q)))
            r = self._requests(lambda: self.client.query(
                url, qvar, note="gql-features"))
            stats["tests"] += 1
            ok_vars = r is not None and not r.error and \
                '"errors"' not in (r.body or "")[:200]
        state = "TESTED" if ok_vars else "REFUTED"
        reason = ("the endpoint processed a query using variables + fragment "
                  "+ alias in one operation"
                  if ok_vars else
                  "the endpoint rejected the variables/fragment/alias "
                  "operation (features restricted or unsupported)")
        if self.coverage is not None:
            self.coverage.dim_tested("graphql", url + "#features")
        self._record_boundary("graphql/features", url, state, reason,
                              evidence=(r.body or "")[:120] if r is not None else "",
                              provenance="graphql:features-probe")

    # V411-GL-05: state-shaped QUERY operations (readAndBurn / deleteAllPastes
    # class) — observed, honestly never exercised when destructive-vocab.
    def _state_query_boundary(self, url, ops) -> None:
        for q in ops["queries"]:
            if STATE_SHAPED_QUERY_RE.search(q["name"] or ""):
                self._record_boundary(
                    "graphql/state-query", "%s#%s" % (url, q["name"]),
                    "BLOCKED_BY_SAFETY",
                    "query operation '%s' carries state-changing vocabulary "
                    "(server-side write semantics inside a read operation) — "
                    "Burhan does not exercise it" % q["name"],
                    remediation="verify the operation's authorization manually "
                                "on a staging copy",
                    provenance="graphql:vocabulary-gate")

    # ------------------------------------------------------------ V4.3.3
    _GQL_ADDITIVE_WRITE_RE = None      # compiled lazily below
    _GQL_WRITE_WORDS = ("create", "add", "post", "submit", "new", "publish")
    _GQL_TEXT_SLOTS = ("content", "body", "text", "value", "message",
                       "comment", "title", "name", "description")
    _GQL_READ_QUERIES = ("pastes", "paste", "search", "searchpaste", "list",
                         "listpastes", "items", "posts", "messages",
                         "comments", "all", "find", "query")

    def _stored_xss_battery(self, url, ops, stats) -> list:
        """V4.3.3 (DVGA campaign, live-caught): stored XSS through the
        GraphQL transport. Red-team proof on DVGA 2026-10-08 (raw urllib,
        zero engine code): createPaste(content: "<b id=MK>..</b>") then
        pastes(filter: title) serves the marker back WITH its tag structure
        intact — the write->read oracle the HTTP xss_stored battery has, now
        through mutations. Safety: additive-write mutations only (the
        destructive vocabulary — edit/delete/update/remove/reset/import/
        upload/password — is never exercised here), one text slot per
        mutation, bounded read fan-out, and a FRESH-marker verification
        round on the same transport (re-execution contract)."""
        import random as _random
        rand = _random.Random(20261008)
        if self._GQL_ADDITIVE_WRITE_RE is None:
            import re as _re
            self.__class__._GQL_ADDITIVE_WRITE_RE = _re.compile(
                "|".join(self._GQL_WRITE_WORDS), _re.I)

        client = GraphqlClient(self.engine)
        findings: list[Finding] = []
        mutations = ops.get("mutations") or []
        queries = ops.get("queries") or []
        read_q = [q for q in queries
                  if q.get("name", "").lower() in self._GQL_READ_QUERIES]
        if not read_q:
            # fallback: any list-shaped query (return type plural-ish or a
            # filter arg exists) — still schema-driven, never guessed
            read_q = [q for q in queries
                      if any(a.get("name") == "filter"
                             for a in (q.get("args") or []))][:3] \
                or queries[:3]
        read_q = read_q[:3]
        write_muts = []
        for m in mutations:
            name = (m.get("name") or "").lower()
            if not self._GQL_ADDITIVE_WRITE_RE.search(name):
                continue
            if any(w in name for w in ("delete", "update", "remove", "edit",
                                       "reset", "import", "upload", "password",
                                       "passwd", "burn")):
                continue            # destructive/import/upload — never probed here
            slots = [a.get("name") for a in (m.get("args") or [])
                     if (a.get("type") or "") == "String"
                     and (a.get("name") or "").lower() in self._GQL_TEXT_SLOTS]
            if slots:
                write_muts.append((m, slots[0]))
        if not write_muts or not read_q:
            self._record_boundary(
                "graphql/stored-xss", url, "UNTESTABLE",
                "no additive-write mutation with a text slot paired with a "
                "read query in the schema inventory — the write->read "
                "roundtrip cannot be shaped",
                provenance="graphql:stored-xss-shape-gate")
            return findings

        marker_html = None
        for mut, slot in write_muts[:2]:
            mk = "GQLSX" + "".join(rand.choice("0123456789abcdef")
                                   for _ in range(8))
            marker_html = f"<b id={mk}>s</b>"
            # every String arg gets a benign value; the SLOT carries the
            # marker, the FIRST other String arg carries the bare marker key
            # (the read filter — DVGA's `title`, the fixture's `email`)
            string_args = [a.get("name") for a in (mut.get("args") or [])
                           if (a.get("type") or "") == "String"]
            key_arg = next((a for a in string_args if a != slot), None)

            def _lit():
                out = []
                for an in string_args:
                    if an == slot:
                        val = marker_html
                    elif an == key_arg:
                        val = mk
                    else:
                        val = "burhan"
                    out.append(f'{an}: "{val}"')
                return ", ".join(out)

            sel = self._selection_set(mut) or "id"
            write_q = 'mutation { %s(%s) { %s } }' % (
                mut.get("name"), _lit(), sel)
            r = client.query(url, write_q, note="gql-storedxss-write")
            stats["tests"] += 1
            self.requests += 1
            if not r or r.error or '"errors"' in (r.body or "")[:200]:
                continue
            # read fan-out: find the marker through the read queries
            read_body = ""
            for rq in read_q:
                rsel = self._selection_set(rq) or "id"
                rargs = []
                for a in (rq.get("args") or [])[:3]:
                    if (a.get("type") or "") == "String":
                        rargs.append(f'{a.get("name")}: "{mk}"')
                rq_q = '{ %s(%s) { %s } }' % (rq.get("name"),
                                              ", ".join(rargs), rsel)
                rr = client.query(url, rq_q, note="gql-storedxss-read")
                stats["tests"] += 1
                self.requests += 1
                if rr and not rr.error and mk in (rr.body or ""):
                    read_body = rr.body or ""
                    break
            if not read_body or marker_html not in read_body:
                continue
            # verification round: a FRESH marker, same write->read cycle
            mk2 = "GQLSX" + "".join(rand.choice("0123456789abcdef")
                                    for _ in range(8))
            marker2 = f"<b id={mk2}>s</b>"
            key_arg2 = key_arg

            def _lit2():
                out = []
                for an in string_args:
                    if an == slot:
                        val = marker2
                    elif an == key_arg2:
                        val = mk2
                    else:
                        val = "burhan"
                    out.append(f'{an}: "{val}"')
                return ", ".join(out)

            w2 = 'mutation { %s(%s) { %s } }' % (mut.get("name"),
                                                 _lit2(),
                                                 self._selection_set(mut) or "id")
            r2 = client.query(url, w2, note="gql-storedxss-verify-write")
            stats["tests"] += 1
            self.requests += 1
            replay_ok = False
            if r2 and not r2.error and '"errors"' not in (r2.body or "")[:200]:
                for rq in read_q:
                    rargs = []
                    for a in (rq.get("args") or [])[:3]:
                        if (a.get("type") or "") == "String":
                            rargs.append(f'{a.get("name")}: "{mk2}"')
                    rq_q = '{ %s(%s) { %s } }' % (
                        rq.get("name"), ", ".join(rargs),
                        self._selection_set(rq) or "id")
                    rr2 = client.query(url, rq_q, note="gql-storedxss-verify-read")
                    stats["tests"] += 1
                    self.requests += 1
                    if rr2 and not rr2.error and marker2 in (rr2.body or ""):
                        replay_ok = True
                        break
            findings.append(_gql_finding(
                "xss_stored", Severity.HIGH, url, slot,
                Evidence("gql_stored_marker_roundtrip",
                         f"mutation {mut.get('name')}({slot}=...) carried an "
                         f"HTML marker that survived the write->read cycle "
                         f"and was served back with its tag structure intact: "
                         f"{marker_html!r} present in the read reply — the "
                         f"content is stored and rendered raw", ""),
                "stored marker reproduced with a FRESH marker on the same "
                "transport (2-round write->read)",
                query=write_q[:160],
                response=(read_body or "")[:160],
                proof={"rule": "stored-marker-roundtrip",
                       "obs": {"marker": marker_html,
                               "read_marker": True,
                               "replay_marker": replay_ok,
                               "rounds": 2}}))
            if replay_ok:
                break               # one verified finding is the honest cap
        if not findings:
            self._record_boundary(
                "graphql/stored-xss", url, "TESTED",
                "additive-write mutations probed with HTML markers; no "
                "roundtripped marker with intact tag structure",
                provenance="graphql:stored-xss-battery")
        return findings

    def _field_suggestions_probe(self, url, ops, stats) -> list:
        """V4.3.3 (DVGA campaign, live-caught): GraphQL field suggestions.
        A near-miss field name (one edit from a REAL schema field) answers
        `Did you mean "<real field>"?` — the schema vocabulary leaks through
        error messages even when introspection is disabled (DVGA solution
        #8). Bounded: ONE typo probe per endpoint + one verification replay;
        the typo is DERIVED from the introspected field names (never
        guessed)."""
        queries = ops.get("queries") or []
        if not queries:
            return []
        real = None
        for q in queries:
            if len(q.get("name") or "") >= 4:
                real = q["name"]
                break
        if not real:
            return []
        typo = real[:-1] + ("z" if not real.endswith("z") else "x")
        client = GraphqlClient(self.engine)
        probe = "{ %s }" % typo
        r = client.query(url, probe, note="gql-field-suggestion")
        stats["tests"] += 1
        self.requests += 1
        body = (r.body or "") if r else ""
        import re as _re2
        # the suggestion text rides INSIDE a JSON string — the quotes around
        # the field name arrive BACKSLASH-ESCAPED (\"audits\") in the raw
        # body; accept both the escaped and the plain form
        m = _re2.search(r'Did you mean \\?"([A-Za-z0-9_]+)\\?"', body)
        if not m:
            self._record_boundary(
                "graphql/field-suggestions", url, "TESTED",
                f"near-miss field probe '{typo}' answered without a "
                "suggestion — field suggestions appear disabled",
                evidence=body[:120],
                provenance="graphql:suggestion-probe")
            return []
        suggestion = m.group(1)
        # verification replay (re-execution contract)
        r2 = client.query(url, probe, note="gql-field-suggestion-verify")
        stats["tests"] += 1
        self.requests += 1
        reproduced = bool(
            r2 and not r2.error
            and _re2.search(r'Did you mean \\?"%s\\?"' % suggestion,
                            (r2.body or "")))
        return [_gql_finding(
            "graphql_field_suggestions", Severity.LOW, url, typo,
            Evidence("gql_field_suggestion",
                     f"the near-miss field '{typo}' answered "
                     f"'Did you mean \"{suggestion}\"?' — the schema's field "
                     f"vocabulary leaks through error suggestions (the real "
                     f"field '{real}' was confirmed present by the reply)",
                     ""),
            "suggestion echo reproduced on a fresh request (2-round)",
            query=probe,
            response=body[:160],
            proof={"rule": "field-suggestion-echo",
                   "obs": {"suggestion": suggestion,
                           "real_field": real,
                           "reproduced": reproduced}})]

    def _battery(self, url, ops, anonymous_engine, low_identity,
                 primary_identity, stats) -> list[Finding]:
        findings: list[Finding] = []
        queries = ops["queries"]

        # ---- V411-GL: honest record of state-shaped query operations FIRST
        # (they are never exercised — the boundary is recorded before any
        # probe so the vocabulary gate is auditable even if later steps fail)
        self._state_query_boundary(url, ops)

        # ---- V411-GL-01: SQL injection through read-query string arguments
        findings += self._sqli_battery(url, ops, stats)

        # ---- V411-GL-02: command execution through system/debug-shaped args
        findings += self._cmdexec_battery(url, ops, stats)

        # ---- V4.3.3 (DVGA campaign, live-caught): STORED XSS through
        # GraphQL mutations — the write->read marker roundtrip (the DVGA
        # createPaste solution #12). The battery is gated on the operation
        # inventory: only additive-write mutations, only string-arg slots,
        # never destructive vocabulary, and a fresh-marker verification
        # round on the SAME transport.
        findings += self._stored_xss_battery(url, ops, stats)

        # ---- V4.3.3: GraphQL FIELD SUGGESTIONS — a near-miss field name
        # (one edit away from a REAL field) answers "Did you mean <field>?"
        # and leaks the schema vocabulary even when introspection is off.
        findings += self._field_suggestions_probe(url, ops, stats)

        # ---- V411-GL-04: variables / fragments / aliases / nested selection
        self._features_probe(url, ops, stats)

        # ---- 1. anonymous access: an unauthenticated engine executing real
        # queries. A finding ONLY when anonymous data is SENSITIVE — a public
        # catalog query answering anonymously is normal API design, not a
        # defect (no fabricated impact).
        # V411-GL-09: read-shaped only (the uniform state-vocabulary gate);
        # V411-GL-10: schema-driven ordering — queries whose return type
        # carries sensitive-vocab fields are probed FIRST, so the bounded
        # budget always covers the highest-value carriers.
        anon_hits: list[tuple[str, str]] = []      # sensitive (query, body) hits
        anon_any = ""
        anon_bodies: list[str] = []                # V411-GL-03b: every answered body
        anon_queries = []
        if anonymous_engine is not None and queries:
            read_q = self._read_shaped(ops)
            sensitive_q = [q for q in read_q
                           if any(SENSITIVE_FIELD_RE.search(f or "")
                                  for f in (q.get("fields") or []))]
            plain_q = [q for q in read_q if q not in sensitive_q]
            anon_queries = (sensitive_q + plain_q)[:8]
        if anonymous_engine is not None and anon_queries:
            anon = GraphqlClient(anonymous_engine)
            for q in anon_queries:
                qtext = self._op_query(q, self._args_literal(q))
                r = self._requests(lambda: anon.query(url, qtext,
                                                       note="gql-anon-query"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                try:
                    payload = json.loads((r.body or "").lstrip()) \
                        if r and r.body else {}
                    data = (payload.get("data") or {}).get(q["name"])
                    has_data = data is not None and not (
                        payload.get("errors") and not payload.get("data"))
                except Exception:
                    has_data = False
                if has_data:
                    anon_any = body
                    anon_bodies.append(body)
                    # V411-GL-03: value-aware — a masked password ('******')
                    # is a boundary, not an exposure
                    exposed, masked = self._sensitive_fields(body)
                    if exposed:
                        anon_hits.append((q["name"], body))
                        break
            if self.coverage is not None and anon_any:
                self.coverage.dim_tested("graphql", url)
        if anon_hits:
            qname, body = anon_hits[0]
            findings.append(_gql_finding(
                "graphql_anonymous_access", Severity.HIGH, url, qname,
                Evidence("anonymous_sensitive_data",
                         f"an UNAUTHENTICATED client executed query '{qname}' "
                         f"and received sensitive-named data — response: "
                         f"{body[:220]} — sensitive operations are reachable "
                         "without authentication", ""),
                "anonymous query returned sensitive data (response verified)",
                response=body[:220],
                proof={"rule": "sensitive-response", "obs": {"hits": len(anon_hits)}}))
        elif anonymous_engine is not None and queries:
            self._record_boundary("graphql/anonymous", url, "TESTED",
                                  "anonymous queries limited to public "
                                  "operations (no sensitive data without auth)"
                                  if anon_any else
                                  "all queries rejected for unauthenticated "
                                  "callers (authentication enforced)",
                                  evidence=anon_any[:120] or "errors/401 only",
                                  provenance="graphql:anonymous-probe")
            # V411-GL-03: masked sensitive-named fields seen anonymously are
            # recorded as an honest boundary (field present, value protected)
            if anon_bodies:
                # V411-GL-03b: masking is audited across EVERY anonymous
                # response, not just the last one (the users-masking
                # observation was silently lost when a later public query
                # answered last — live-caught on DVGA)
                _masked_all: list[str] = []
                for _b in anon_bodies:
                    _ex, _m = self._sensitive_fields(_b)
                    _masked_all.extend(_m)
                masked = sorted(set(_masked_all))
                if masked:
                    self._record_boundary(
                        "graphql/sensitive-masking", url, "TESTED",
                        "sensitive-named field(s) %s returned to an anonymous "
                        "caller with MASKED values — the server protects the "
                        "value; field-level masking is functioning" %
                        ", ".join(masked[:4]),
                        evidence=anon_any[:120],
                        provenance="graphql:anonymous-probe")

        # ---- 2. BOLA: the LOW identity queries the PRIMARY identity's object
        # V411-GL-14 (live-caught on DVGA): a self-read is NOT BOLA — when the
        # wired low identity IS the primary identity (single-account wiring),
        # the honest state is UNTESTABLE, never a mis-attributed finding.
        bola_probe = ""
        if low_identity and primary_identity and queries and \
                low_identity.get("engine") is not None and \
                low_identity.get("name") != primary_identity.get("name"):
            victim_id = primary_identity.get("object_id") or ""
            marker = primary_identity.get("marker") or ""
            done = False
            for q in self._read_shaped(ops):
                id_arg = next((a for a in q["args"]
                               if ID_ARG_RE.match(a.get("name") or "")), None)
                if id_arg is None or victim_id == "":
                    continue
                qtext = self._op_query(q, "%s: %s" % (id_arg["name"],
                                                       _arg_literal(id_arg, victim_id)))
                low_client = GraphqlClient(low_identity["engine"])
                r = self._requests(lambda: low_client.query(
                    url, qtext, note="gql-bola"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                bola_probe = body
                try:
                    payload = json.loads((r.body or "").lstrip()) if r and r.body else {}
                    obj = (payload.get("data") or {}).get(q["name"])
                    obj_str = json.dumps(obj) if obj is not None else ""
                except Exception:
                    obj_str = ""
                if obj and (marker in obj_str if marker else True):
                    findings.append(_gql_finding(
                        "graphql_bola", Severity.HIGH, url, id_arg["name"],
                        Evidence("cross_identity_object_read",
                                 f"identity '{low_identity.get('name', 'low')}' "
                                 f"(role={low_identity.get('role', '?')}) read the "
                                 f"object of identity "
                                 f"'{primary_identity.get('name', 'primary')}' "
                                 f"({id_arg['name']}={victim_id}) via query "
                                 f"'{q['name']}' — response: {obj_str[:220]} — "
                                 "object-level authorization is not enforced", ""),
                        "low-identity query returned the primary identity's "
                        "object data (marker present)",
                        query=qtext, response=obj_str[:220],
                        proof={"rule": "marker-in-object",
                               "obs": {"obj_str": obj_str, "marker": marker,
                                       "no_marker_verdict": True}}))
                    done = True
                    break
                done = False
            if not findings or not any(f.type == "graphql_bola" for f in findings):
                self._record_boundary(
                    "graphql/bola", url, "TESTED" if bola_probe else "UNTESTABLE",
                    ("cross-identity query refused or returned no other-identity "
                     "object (object-level authorization holds)")
                    if bola_probe else
                    "no id-bearing query available for cross-identity testing",
                    evidence=bola_probe[:120],
                    provenance="graphql:bola-probe")
        elif low_identity and primary_identity and \
                low_identity.get("name") == primary_identity.get("name"):
            self._record_boundary(
                "graphql/bola", url, "UNTESTABLE",
                "the only wired identity IS the primary identity — a self-read "
                "is not a cross-identity test",
                remediation="configure a DISTINCT second account "
                            "(--authz accounts) to enable cross-identity "
                            "object testing",
                provenance="graphql:bola")
        elif not (low_identity and primary_identity
                  and low_identity.get("engine") is not None):
            self._record_boundary("graphql/bola", url, "UNTESTABLE",
                                  "required second identity unavailable",
                                  remediation="configure a second account "
                                              "(--authz accounts) to enable "
                                              "cross-identity object testing",
                                  provenance="graphql:bola")

        # ---- V411-GL-05b: ANONYMOUS BOLA — an unauthenticated caller reading
        # the PRIMARY identity's object. DVGA-class targets expose private
        # objects to anonymous readers via id-bearing queries; without this
        # probe the defect was attributed only to logged-in low identities.
        if primary_identity and queries and anonymous_engine is not None:
            victim_id = primary_identity.get("object_id") or ""
            marker = primary_identity.get("marker") or ""
            if victim_id:
                anon_bola_probe = ""
                for q in queries:
                    if STATE_SHAPED_QUERY_RE.search(q["name"] or ""):
                        continue
                    id_arg = next((a for a in q["args"]
                                   if ID_ARG_RE.match(a.get("name") or "")), None)
                    if id_arg is None:
                        continue
                    qtext = self._op_query(
                        q, "%s: %s" % (id_arg["name"],
                                        _arg_literal(id_arg, victim_id)))
                    anon_client = GraphqlClient(anonymous_engine)
                    r = self._requests(lambda: anon_client.query(
                        url, qtext, note="gql-anon-bola"))
                    stats["tests"] += 1
                    anon_bola_probe = (r.body or "")[:400] if r is not None else ""
                    try:
                        payload = json.loads((r.body or "").lstrip()) \
                            if r and r.body else {}
                        obj = (payload.get("data") or {}).get(q["name"])
                        obj_str = json.dumps(obj) if obj is not None else ""
                    except Exception:
                        obj_str = ""
                    if obj and (marker in obj_str if marker else False):
                        findings.append(_gql_finding(
                            "graphql_bola", Severity.HIGH, url, id_arg["name"],
                            Evidence("anonymous_cross_identity_object_read",
                                     f"an ANONYMOUS caller (no credentials at "
                                     f"all) read the object of identity "
                                     f"'{primary_identity.get('name', 'primary')}' "
                                     f"({id_arg['name']}={victim_id}) via query "
                                     f"'{q['name']}' — response: {obj_str[:220]} "
                                     f"— the object is readable without any "
                                     "authentication; object-level "
                                     "authorization is missing for anonymous "
                                     "callers", ""),
                            "anonymous query returned the primary identity's "
                            "object data (marker present)",
                            query=qtext, response=obj_str[:220],
                            proof={"rule": "marker-in-object",
                                   "obs": {"obj_str": obj_str, "marker": marker,
                                           "no_marker_verdict": False}}))
                        break
                else:
                    self._record_boundary(
                        "graphql/anonymous-bola", url,
                        "TESTED" if anon_bola_probe else "UNTESTABLE",
                        "anonymous object reads refused or returned no "
                        "other-identity object (anonymous object-level access "
                        "does not leak the primary identity's data)"
                        if anon_bola_probe else
                        "no id-bearing query available for anonymous "
                        "cross-identity testing",
                        evidence=anon_bola_probe[:120],
                        provenance="graphql:anon-bola-probe")

        # ---- 3. field-level authorization: sensitive-vocab fields in the
        # low-identity (or main) response for the identity's OWN object
        field_probe = ""
        if queries and low_identity and low_identity.get("engine") is not None:
            own_id = low_identity.get("object_id") or ""
            for q in self._read_shaped(ops):
                id_arg = next((a for a in q["args"]
                               if ID_ARG_RE.match(a.get("name") or "")), None)
                if id_arg is None or not own_id:
                    continue
                qtext = self._op_query(q, "%s: %s" % (id_arg["name"],
                                                       _arg_literal(id_arg, own_id)))
                low_client = GraphqlClient(low_identity["engine"])
                r = self._requests(lambda: low_client.query(
                    url, qtext, note="gql-field-authz"))
                stats["tests"] += 1
                body = (r.body or "")[:400] if r is not None else ""
                field_probe = body
                # V411-GL-03: value-aware — masked values are NOT an exposure
                exposed_pairs, masked_names = self._sensitive_fields(body) \
                    if body else ([], [])
                if exposed_pairs:
                    findings.append(_gql_finding(
                        "graphql_field_authorization", Severity.MEDIUM, url,
                        q["name"],
                        Evidence("sensitive_fields_exposed",
                                 f"query '{q['name']}' returns sensitive-named "
                                 f"fields WITH REAL VALUES ({', '.join(k for k, _ in exposed_pairs[:4])}) "
                                 f"to a role={low_identity.get('role', '?')} identity "
                                 f"for its own object — response: {body[:200]} — "
                                 "field-level authorization/exposure is missing",
                                 ""),
                        "own-object response carries sensitive-named fields "
                        "with real values",
                        query=qtext, response=body[:200],
                        proof={"rule": "sensitive-response",
                               "obs": {"exposed": len(exposed_pairs)}}))
                    break
                elif masked_names:
                    self._record_boundary(
                        "graphql/field-authorization", url, "TESTED",
                        "sensitive-named field(s) %s present but MASKED for a "
                        "low-privilege identity — field-level masking is "
                        "functioning" % ", ".join(masked_names[:4]),
                        evidence=field_probe[:120],
                        provenance="graphql:field-probe")
                    break
            else:
                self._record_boundary("graphql/field-authorization", url, "TESTED",
                                      "own-object queries carry no sensitive-named "
                                      "fields", evidence=field_probe[:120],
                                      provenance="graphql:field-probe")

        # ---- 4. mutation authorization (planner-gated: STATE_CHANGING).
        # V411-GL-07: only ADDITIVE/auth-shaped mutations are ever exercised
        # (create/register/login/upload class); edit/update/import/send-shaped
        # vocabulary is recorded BLOCKED_BY_SAFETY — never sent.
        mut_probe = ""
        exercisable = [m for m in ops["mutations"]
                       if ADDITIVE_MUTATION_RE.search(m["name"] or "")]
        blocked_shape = [m for m in ops["mutations"] if m not in exercisable]
        if not ops["mutations"]:
            self._record_boundary("graphql/mutation", url, "NOT_APPLICABLE",
                                  "schema declares no mutations",
                                  provenance="graphql:schema")
        elif blocked_shape:
            self._record_boundary(
                "graphql/mutation-vocabulary", url, "BLOCKED_BY_SAFETY",
                "mutation(s) %s carry non-additive vocabulary (edit/update/"
                "import/delete class — overwrite, outbound-fetch or destroy "
                "semantics) — Burhan never sends them" %
                ", ".join(m["name"] for m in blocked_shape[:5]),
                remediation="verify these mutations' authorization manually "
                            "on a staging copy",
                provenance="graphql:planner-gate")
        if exercisable:
            m = exercisable[0]
            gated = True
            if self.planner is not None:
                verdict = self.planner.gate(url, "POST",
                                            fields=[("query", m["name"])],
                                            note="gql-mutation")
                gated = verdict.get("allowed", False)
            if not gated:
                # never a silent skip: a planner refusal is an auditable
                # boundary, not an invisible one
                self._record_boundary(
                    "graphql/mutation", url, "BLOCKED_BY_SAFETY",
                    "the Safe Attack Planner refused the mutation probe "
                    "(state-changing operation outside the authorized "
                    "attack policy)",
                    remediation="re-run with --logic-active on an authorized "
                                "staging copy",
                    provenance="graphql:planner-gate")
            elif not self.logic_active:
                self._record_boundary(
                    "graphql/mutation", url, "BLOCKED_BY_PERMISSION",
                    "mutation testing is STATE_CHANGING — requires --logic-active",
                    remediation="re-run with --logic-active to authorize "
                                "state-changing mutation probes",
                    provenance="graphql:planner-gate")
            else:
                mtext = self._op_query(m, self._args_literal(m), keyword="mutation")
                # anonymous engine first (mutation without auth is the defect);
                # fall back to the low identity when no anonymous engine exists
                eng = anonymous_engine or low_identity.get("engine") \
                    if low_identity else anonymous_engine
                if eng is not None:
                    client = GraphqlClient(eng)
                    r = self._requests(lambda: client.query(
                        url, mtext, note="gql-mutation-authz"))
                    stats["tests"] += 1
                    mut_probe = (r.body or "")[:400] if r is not None else ""
                    auth_required = bool(
                        r is not None and (getattr(r, "status", 0) == 401 or re.search(
                            r"(not authenticated|unauthenticated|authenticate|"
                            r"login required|credentials|sign in)",
                            (mut_probe or "") + " " + str(getattr(r, "status", "")),
                            re.I)))
                    try:
                        payload = json.loads((r.body or "").lstrip()) \
                            if r and r.body else {}
                        errors = payload.get("errors") or []
                        data = (payload.get("data") or {}).get(m["name"])
                        executed = data is not None and not errors
                    except Exception:
                        executed = False
                    if executed:
                        findings.append(_gql_finding(
                            "graphql_mutation_authorization", Severity.HIGH, url,
                            m["name"],
                            Evidence("mutation_without_authorization",
                                     f"mutation '{m['name']}' EXECUTED without "
                                     "its required privilege (unauthenticated or "
                                     f"low-privilege caller) — response: "
                                     f"{mut_probe[:200]} — mutation authorization "
                                     "is not enforced", ""),
                            "mutation returned data with no errors from a "
                            "non-privileged caller",
                            query=mtext, response=mut_probe[:200],
                            proof={"rule": "executed-no-errors",
                                   "obs": {"data_present": data is not None,
                                           "errors": errors}}))
                    elif auth_required:
                        # the mutation demands authentication the caller does
                        # not hold: the test could not exercise it — an honest
                        # UNTESTABLE, never a refuted claim
                        self._record_boundary(
                            "graphql/mutation", url, "UNTESTABLE",
                            "authentication required — the mutation could not "
                            "be exercised by the available caller",
                            evidence=mut_probe[:120],
                            remediation="configure an account holding the "
                                        "mutation's privilege",
                            provenance="graphql:mutation-probe")
                    else:
                        self._record_boundary(
                            "graphql/mutation", url, "TESTED",
                            "mutation refused or errored for a non-privileged "
                            "caller (authorization enforced)",
                            evidence=mut_probe[:120],
                            provenance="graphql:mutation-probe")
                else:
                    self._record_boundary(
                        "graphql/mutation", url, "UNTESTABLE",
                        "no unauthenticated or low-privilege engine available "
                        "to exercise the mutation",
                        remediation="run without --auth-token or configure "
                                    "--authz accounts",
                        provenance="graphql:mutation-probe")
        return findings

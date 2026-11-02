"""Burhan — Deterministic DAST Platform.
Core domain models (Phase 1: Core Engine).
Every scan is reproducible: RunID + Seed + Version + ConfigHash.
"""
from __future__ import annotations
import dataclasses, hashlib, json, os, time, uuid
from enum import Enum
from typing import Optional
from urllib.parse import urlsplit

VERSION = "5.0.0"  # v5.0.0 = the breaking brand rename release
SCANNER_VERSION = "burhan-core/" + VERSION


class Severity(str, Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"; VERIFIED = "verified"; REJECTED = "rejected"; QUARANTINED = "quarantined"


class DiscoverySource(str, Enum):
    SEED = "seed"; CRAWL_HTML = "crawl:html"; CRAWL_FORM = "crawl:form"; ROBOTS = "robots.txt"
    JS_STATIC = "js:static"; SITEMAP = "sitemap"; MANUAL = "manual"
    DOM = "dom:browser"     # Phase 50: discovered only by rendering in a real browser
    AUTH = "auth:login"     # AUTH-06: the credentialed login endpoint observed in flight


# ---------------------------------------------------------------- Target / Scope
@dataclasses.dataclass
class Target:
    url: str
    name: str = ""

    @property
    def host(self): return urlsplit(self.url).hostname or ""


@dataclasses.dataclass
class ScopeRule:
    """Phase 3: Scope Engine rule set. Deny-by-default for private space."""
    allowed_hosts: list = dataclasses.field(default_factory=list)
    allowed_domains: list = dataclasses.field(default_factory=list)   # suffix match
    allowed_schemes: list = dataclasses.field(default_factory=lambda: ["http", "https"])
    allowed_ports: list = dataclasses.field(default_factory=list)     # empty = all public
    denied_paths: list = dataclasses.field(default_factory=list)
    denied_params: list = dataclasses.field(default_factory=list)
    allow_private: bool = False          # localhost/RFC1918/metadata — must be explicit
    allow_metadata_svc: bool = False     # 169.254.169.254 etc.
    max_redirects: int = 5
    follow_cross_host: bool = False


PRIVATE_V4 = [("10.",), ("192.168.",), ("172.",)]  # 172.16-31 handled precisely below  # legacy: kept for reference; is_private_ip no longer uses it
META_V4 = ("169.254.", "100.100.", "fd00:", "fe80:")  # legacy: kept for reference; is_private_ip no longer uses it

import ipaddress, socket

_CGNAT = ipaddress.ip_network("100.64.0.0/10")

def _addr_unsafe(a) -> bool:
    if (a.is_private or a.is_loopback or
        a.is_link_local or a.is_reserved or
        a.is_multicast or a.is_unspecified):
        return True
    if getattr(a, 'version', 0) == 4 and \
       a in _CGNAT:
        return True
    for mapped in (getattr(a, 'ipv4_mapped', None),
                   getattr(a, 'sixtofour', None)):
        if mapped and _addr_unsafe(mapped):
            return True
    return False

def is_private_ip(ip: str) -> bool:
    if not ip:
        return True
    h = ip.strip()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    # أشكال IPv4 المتحررة (ثماني/عشري/سداسي)
    try:
        import struct
        packed = socket.inet_aton(h)
        return _addr_unsafe(
            ipaddress.IPv4Address(packed))
    except OSError:
        pass
    # عناوين حرفية v4/v6
    try:
        return _addr_unsafe(ipaddress.ip_address(h))
    except ValueError:
        pass
    # أسماء مضيف: حل DNS وفحص كل عنوان
    try:
        addrs = socket.getaddrinfo(
            h, None, 0, socket.SOCK_STREAM)
        return any(
            _addr_unsafe(ipaddress.ip_address(
                a[4][0]))
            for a in addrs)
    except Exception:
        return True  # أي غموض = رفض


def pin_transport_address(host, port, allow_private=False):
    """RAW-SOCKET TRANSPORT GATE (SSRF fix 2026-10-31, owner order part 2.2).

    Resolve a hostname ONCE, validate EVERY answer against the private-
    address policy, and return (pinned_ip, None) or (None, reason).
    Fail-closed on any ambiguity — the same doctrine as is_private_ip and
    http_engine._pin_target. Every raw-socket transport (the websocket
    client, the modernsec timing probes) MUST call this and connect to the
    returned address: the DNS name is never re-resolved at connect time
    (rebind-proof), and private/metadata answers are refused unless the
    caller holds an explicit allow_private scope.

    Proven necessary 2026-10-31: a live scan of a loopback target WITHOUT
    --allow-private sent 0 HTTP requests (the HTTP scope gate held) yet the
    websocket well-known-path probes connected 9 times over raw sockets —
    the WS layer had NO private-address policy at all, and modernsec's
    smuggling probe even carried an explicit 127.0.0.1/localhost carve-out.
    """
    if not host:
        return None, "empty host"
    bare = host.strip().strip("[]")
    literal = False
    addrs = []
    try:
        ipaddress.ip_address(bare)
        addrs = [bare]
        literal = True
    except ValueError:
        pass
    if not literal:
        try:
            ais = socket.getaddrinfo(bare, port or 80, 0, socket.SOCK_STREAM)
        except Exception as exc:
            return None, ("dns-unresolvable (%s: %s)" % (type(exc).__name__, exc))[:120]
        addrs = [a[4][0] for a in ais if a and a[4]]
        if not addrs:
            return None, "dns-empty-answer"
    if not allow_private:
        for a in addrs:
            if is_private_ip(a):
                return None, ("resolved %s unsafe for %s (rebind-guard)" % (a, host))[:120]
    if not addrs:
        return None, "no addresses"

    def _order(a):
        try:
            o = ipaddress.ip_address(a)
            return (o.version, int(o))
        except ValueError:
            return (9, 0)

    return sorted(set(addrs), key=_order)[0], None


# ---------------------------------------------------------------- Parameter / Endpoint
class ParamLocation(str, Enum):
    QUERY="query"; PATH="path"; BODY="body"; JSON="json"; HEADER="header"; COOKIE="cookie"; MULTIPART="multipart"


class ParamKind(str, Enum):
    NUMERIC="numeric"; IDENTIFIER="identifier"; URL="url"; PATH="path"; EMAIL="email"
    SEARCH="search"; HTML="html"; JSON="json"; TOKEN="token"; FILENAME="filename"; GENERIC="generic"
    # Phase 56 (v2.8.0): value-shape kinds from the Smart Testing Engine — a param
    # whose observed value IS a JSON object gets its own kind: the planner has NO
    # rule for it, so string batteries (sqli/xss/traversal) are never wasted on it.
    JSON_OBJECT="json_object"


@dataclasses.dataclass
class Parameter:
    name: str
    location: ParamLocation = ParamLocation.QUERY
    value: str = ""
    kind: ParamKind = ParamKind.GENERIC
    # OWSP-03 (OWASP campaign, live-caught on WrongSecrets 1.8.1): submit-button
    # pairs (action=submit & co.) are FLOW CONTROL — the route's params filter
    # demands the exact literal, so replacing the value with a payload makes
    # every probe 405 before application logic runs. Carried verbatim as
    # siblings (like TOKEN), never an injection target. Set by the discovery
    # form parser for the form's first submit control.
    flow_control: bool = False
    # OWSP-18 (OWASP campaign, live-caught on DVWA 3.x): the param is a FILE
    # input of a multipart form — the upload detector builds a real multipart
    # body for it; text batteries must not treat it as a string field.
    is_file: bool = False

    def classify(self) -> "Parameter":
        # LIVE-CAUGHT (crAPI live run 41424841547): a spec/crawl source can
        # hand a NON-STRING value (OpenAPI "example": 30 is a JSON int).
        # Coerce before touching string methods — a bad example value must
        # degrade to "", never kill the whole scan.
        if not isinstance(self.value, str):
            self.value = "" if self.value is None else str(self.value)
        v, n = (self.value or "").strip(), (self.name or "").lower()
        # Phase 50: CSRF/anti-CSRF tokens are flow-control values, never injection
        # targets — mutating them breaks the request (token mismatch) and can only
        # produce noise. They are carried verbatim as siblings so protected flows
        # stay reachable (live-proven on ginandjuice.shop /catalog/subscribe).
        if any(k in n for k in ("csrf", "token", "nonce", "authenticity")):
            self.kind = ParamKind.TOKEN
            return self
        if any(k in n for k in ("url", "redirect", "return", "next", "goto", "dest", "continue")): self.kind = ParamKind.URL
        elif any(k in n for k in ("file","path","page","template","item","doc","load")): self.kind = ParamKind.FILENAME
        elif any(k in n for k in ("id","uid","pid","ref","num")) and v.isdigit(): self.kind = ParamKind.NUMERIC
        elif v.isdigit(): self.kind = ParamKind.NUMERIC
        elif v.startswith(("http://","https://","//")): self.kind = ParamKind.URL
        elif "@" in v and "." in v: self.kind = ParamKind.EMAIL
        elif any(k in n for k in ("q","search","query","keyword","name")): self.kind = ParamKind.SEARCH
        return self


@dataclasses.dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: list = dataclasses.field(default_factory=list)
    headers: dict = dataclasses.field(default_factory=dict)
    cookies: dict = dataclasses.field(default_factory=dict)
    source: DiscoverySource = DiscoverySource.SEED
    auth_context: str = "anonymous"
    tags: list = dataclasses.field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        if not self.id:
            # OWSP-25 (OWASP campaign, live-caught on Mutillidae II 2.12.7):
            # identity was method|url|sorted param NAMES — a query-routed app
            # serves MANY logical surfaces through one url (index.php?page=X)
            # and two forms with identical name sets are DIFFERENT surfaces.
            # Live proof: user-info.php and user-info-xpath.php share the
            # exact param names username/password/user-info-php-submit-button
            # (Mutillidae's own copy-paste button name) — one Endpoint.id, the
            # first-crawled twin (xpath) won the page value, every battery
            # fired in the WRONG context (1,131 username SQLi probes under
            # page=user-info-xpath.php, ZERO under page=user-info.php where
            # the classic SQLi lives; request-level proof from the target's
            # own access log). File-shaped router param VALUES now join the
            # identity — the same insight as OWSP-23's fetch-cap key: a value
            # shaped like a script filename selects a different actual page.
            # Params without file-shaped values are unaffected (material
            # byte-identical -> same id -> zero behavioral change).
            router_vals = sorted(
                f"{p.name}={p.value}" for p in self.parameters
                if str(p.value or "").lower().endswith(
                    (".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".js")))
            material = f"{self.method}|{self.url}|{sorted(p.name for p in self.parameters)}"
            if router_vals:
                material += "|" + "&".join(router_vals)
            self.id = hashlib.sha1(material.encode()).hexdigest()[:12]

    def param(self, name: str) -> Optional[Parameter]:
        return next((p for p in self.parameters if p.name == name), None)


# ---------------------------------------------------------------- Evidence / Finding
@dataclasses.dataclass
class Evidence:
    kind: str            # e.g. "response_diff", "marker_in_body", "header_value", "db_error"
    detail: str
    request_id: str = ""
    raw_snippet: str = ""

    def fingerprint_material(self) -> str:
        return f"{self.kind}:{self.detail[:120]}"


@dataclasses.dataclass
class Verification:
    method: str = ""                 # e.g. "re-test:variant", "oracle:2round"
    passed: bool = False
    confidence: float = 0.0
    rounds: int = 0
    notes: str = ""


@dataclasses.dataclass
class Finding:
    type: str                        # e.g. "sql_injection", "xss_reflected"
    severity: Severity = Severity.MEDIUM
    endpoint_url: str = ""
    parameter: str = ""
    method: str = "GET"
    evidence: list = dataclasses.field(default_factory=list)
    verification: Optional[Verification] = None
    confidence: float = 0.0
    status: FindingStatus = FindingStatus.CANDIDATE
    scanner: str = SCANNER_VERSION
    run_id: str = ""
    first_seen: float = dataclasses.field(default_factory=time.time)
    id: str = ""
    # Phase 56 (v2.8.0): authorization context — for authz-engine findings this
    # records WHICH role/victim pair produced the evidence. Empty elsewhere.
    authz_context: str = ""
    # v4.0.0 (ENG-18): workflow-oracle state pair — the before/after snapshots
    # the proof file carries for stateful classes (workflow/authz); empty for
    # request-level classes whose proof IS the differential.
    state_before: str = ""
    state_after: str = ""
    # RP-3 (replay fidelity, 2026-10-31): the producing detector's NAME. One
    # vuln_type can be produced by several detectors probing different input
    # channels (path_traversal: traversal / trav_hname / trav_pname;
    # command_injection: cmdi / cmdi_echo) — routing a replay by type name
    # alone probes the WRONG channel and the proof dies as
    # REPRODUCTION_FAILED. Detectors with ambiguous types set this; the proof
    # records it and replay_finding routes by it (falling back to the
    # historical type map when empty — legacy proofs unchanged).
    detector: str = ""

    def __post_init__(self):
        if not self.id:
            base = f"{self.type}|{self.method}|{self.endpoint_url}|{self.parameter}"
            self.id = "F-" + hashlib.sha1(base.encode()).hexdigest()[:10]

    def fingerprint(self) -> str:
        """Phase 16: dedup fingerprint = asset + endpoint + parameter + vuln + normalized evidence.
        Normalized evidence = sorted unique evidence KINDS (details vary per request instance)."""
        ev = "|".join(sorted({e.kind for e in self.evidence}))[:120]
        base = f"{self.type}|{self.method}|{self.endpoint_url.split('?')[0]}|{self.parameter}|{ev}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "severity": self.severity.value,
            "status": self.status.value, "confidence": round(self.confidence, 3),
            "method": self.method, "url": self.endpoint_url, "parameter": self.parameter,
            "evidence": [{"kind": e.kind, "detail": e.detail[:300]} for e in self.evidence],
            "verification": self.verification and {
                "method": self.verification.method, "passed": self.verification.passed,
                "confidence": round(self.verification.confidence, 3), "rounds": self.verification.rounds,
                "notes": self.verification.notes[:300]},
            "scanner": self.scanner, "run_id": self.run_id,
            **({"authz_context": self.authz_context} if self.authz_context else {}),
        }


# ---------------------------------------------------------------- Events (Phase 20)
class EventBus:
    """Structured event log — the substrate for failure memory & learning."""
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.events: list[dict] = []

    def emit(self, kind: str, **data):
        ev = {"t": round(time.time(), 3), "run": self.run_id, "kind": kind, **data}
        self.events.append(ev)
        return ev

    def by_kind(self, kind: str) -> list:
        return [e for e in self.events if e["kind"] == kind]


def new_run_id(seed: Optional[str] = None) -> tuple[str, str]:
    """Deterministic reproduction: RunID derived from seed (Phase 36).
    ORD-001-REMAND (RT-03): the DEFAULT run seed is os.urandom(32) hex —
    256-bit entropy, 64 chars. Never dates/timestamps/serial ids; short
    operator seeds are rejected downstream (audit fail-closed + the CLI
    parser gate), never silently accepted."""
    seed = seed or os.urandom(32).hex()
    return "run-" + hashlib.sha1(seed.encode()).hexdigest()[:10], seed

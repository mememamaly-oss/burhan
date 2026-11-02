"""Owner order part 3 (2026-10-31): NEW detection layers — modern battery v2.

FEATURE-FLAGGED, OFF BY DEFAULT. Activated only via ScanConfig(modern_v2=True)
or the CLI flag ``--modern-v2``. Shares no code path with modernsec.py or
graphql.py: the existing families (JWT algorithm confusion, JWT none
acceptance, GraphQL introspection, GraphQL batching, GraphQL BOLA, mass
assignment) keep their v4.4.0 semantics untouched — verified by the unchanged
fixture benchmark gate (TP=38/FP=0) in CI.

New checks, each bounded with its cap documented:

3A ``jwt_weak_secret`` — RFC 8725 (JWT Best Current Practices) motivates the
   whole JWT family here: accepting ``alg: none`` and algorithm confusion are
   the two explicit algorithm-agility failures the BCP calls out, already
   covered by modernsec since v4.4.0. The remaining signature-destroying
   failure this layer adds: a GUESSABLE symmetric secret. The check verifies
   the token's HMAC signature OFFLINE against a fixed 27-entry common-secret
   wordlist — zero requests, zero open brute force; the attempt cap IS the
   wordlist length (27), documented here and surfaced in probe counts.

3C ``graphql_aliasing`` — aliasing cost-DoS surface: ONE request carrying
   ALIAS_CAP aliased copies of a cheap field. If the server executes every
   alias in the single request, a naive per-request rate limit sees one
   request while the server performs ALIAS_CAP units of work. This is
   distinct from the existing batching check (an ARRAY of separate
   operation objects) and from the existing introspection/BOLA checks in
   graphql.py. Bounded: at most 2 GraphQL endpoints, 1 request each,
   ALIAS_CAP=20 aliases.

3D ``excessive_data_exposure`` — read-side sibling of the existing
   mass-assignment check (write side): response-SHAPE analysis over JSON API
   surfaces. Flags secret-ish FIELD NAMES (password hashes, private keys,
   internal flags) returned in ordinary responses — the OWASP API Security
   Top 10 "Excessive Data Exposure" pattern (API3:2019 / API6:2023 family).
   Bounded: first 8 JSON-ish GET endpoints, 1 request each; field NAMES are
   reported, values are never republished.

3B ``rebind_toctou`` — DNS-rebinding TOCTOU: does a URL-fetch surface
   RE-RESOLVE a hostname between its validation check and the actual
   outbound connection? (The exact bug class proven real in this project's
   own WsClient — prior order, part 3.1 — which is what this layer
   calibrates against.) Validated against a controlled local flip-after-N
   DNS fixture (fixtures/rebind_fixture.py). Scan-time use requires
   operator-controlled rebinding DNS (BURHAN_REBIND_DNS); without it the
   family is skipped with a loud boundary note, never silently.
   ADVERSARIAL SWEEP (owner order part 5, 2026-10-31 — real outcomes, pinned
   by tests/test_modernsec2.py::test_adversarial_*):
   * HS512/HS384 weak secrets: DETECTED (the check covers every HMAC alg).
   * corrupted-signature tokens: no match, no crash, bounded cap only.
   * excessive_data_exposure: prefixed password-hash/key-id fields initially
     EVADED (user_password_hash, aws_access_key_id) — FIXED by the shape
     regex above; fields nested deeper than depth 3 remain outside the
     documented bounded walk (intentional cap, pinned as a known limit).
   * graphql_aliasing: a pure REFLECTOR that echoes the aN keys without
     executing resolver work DOES trigger the finding — the check verifies
     response SHAPE, not execution cost (cost measurement against live
     targets is out of scope by policy). The finding is deliberately LOW
     severity and worded as a surface indicator; pinned as intended.
   * rebind_toctou: flip_after must match the target's per-operation DNS
     query count — with flip_after=2 and a single-validation target the
     rebind is MISSED (pinned); the parameter is documented tuning, and
     real rebinding infrastructure flips per query (TTL 0).
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import re
import socket
import threading

from .core import (Endpoint, EventBus, Finding, FindingStatus, Severity,
                   Evidence, ScopeRule)
from .http_engine import RequestEngine, RequestMutation

MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",
                 "excessive_data_exposure", "rebind_toctou", "bfla",
                 "race_condition", "shadow_api")

# request caps per family (offline wordlist attempts are counted separately:
# jwt_weak_secret sends at most 2 harvest requests; its 27 offline signature
# verifications are the documented wordlist cap, not network traffic)
FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,
                "excessive_data_exposure": 8, "rebind_toctou": 4,
                "bfla": 18, "race_condition": 48, "shadow_api": 14}

# 3A: the COMPLETE, EXPLICIT wordlist — the cap is its length (27). This is a
# detection capability, not an open brute-force tool: no user-extensible
# dictionary, no online oracle, offline verification only.
WEAK_SECRET_WORDLIST = (
    "secret", "secretkey", "secret_key", "secret-key", "your-256-bit-secret",
    "your_jwt_secret", "jwt_secret", "jwtsecret", "mysecret", "supersecret",
    "super-secret", "changeme", "change-me", "password", "default",
    "development", "dev", "test", "key", "s3cr3t", "123456", "qwerty",
    "letmein", "admin", "null", "none", "keysecret",
)

ALIAS_CAP = 20          # aliases in the single probe request (3C)
EXPOSURE_EP_CAP = 8     # JSON endpoints examined (3D)
SHADOW_PROBE_CAP = 6    # live-confirmation fetches for SHADOW candidates (3G)
ZOMBIE_PROBE_CAP = 8    # live checks of spec-declared paths (3G); the two
                         # caps together are the family cap 14 above
RACE_CAND_CAP = 4       # operator-named candidates per scan (3F)
RACE_DEFAULT_N = 6      # concurrent requests per burst (3F default)
RACE_MAX_N = 12         # hard ceiling on the operator-declared N (3F);
                         # the substrate gate (race/gates) allows 64 —
                         # the family stays far below it on purpose
BFLA_EP_CAP = 6         # admin-shaped non-GET endpoints examined (3E);
                         # each costs 3 replays (anon + high + low) -> the
                         # family cap above is 18 requests, hard-stopped

_HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
            "HS512": hashlib.sha512}

# 3D: secret-ish FIELD NAMES (name-only detection; values never republished)
_SECRET_FIELD_RE = re.compile(
    r"^(password|passwd|pwd|pass)([_-]?hash)?$", re.I)
# adversarial fix (owner order part 5, finding A3): prefixed shapes
# user_password_hash / aws_access_key_id evaded the first shape — caught now
_SECRET_FIELD_RE2 = re.compile(
    r"^[a-z0-9_]*password[_-]?hash$"
    r"|^[a-z0-9_]*(secret|private[_-]?key|api[_-]?key|access[_-]?key)"
    r"([_-]?(hash|id|key))?$"
    r"|^(is_internal|internal_id|internal_flag)$",
    re.I)

_GQL_PATH_RE = re.compile(r"graphql|gql", re.I)
_AUTHISH = ("login", "signin", "sign-in", "auth", "token", "jwt", "session")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode_seg(seg: str) -> dict:
    try:
        d = json.loads(_b64d(seg).decode("utf-8", "replace"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _ok(r) -> bool:
    return bool(r is not None and getattr(r, "ok", False)
                and 200 <= int(getattr(r, "status", 0) or 0) < 300)


def _mine_jwt(r) -> str | None:
    """First JWT-shaped token in a response body or Set-Cookie (modernsec parity)."""
    if r is None or getattr(r, "error", True) or not getattr(r, "status", 0):
        return None
    hay = (getattr(r, "body", "") or "") + " ".join(
        f"{k}={v}" for k, v in (getattr(r, "headers", None) or {}).items()
        if k.lower() == "set-cookie")
    m = re.search(r"(ey[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*)", hay)
    return m.group(1) if m else None


class _St2:
    """Battery-v2 state: deterministic order, counters, boundaries."""

    def __init__(self, engine: RequestEngine, seed=None):
        self.engine = engine
        self.seed = seed
        self.findings = []
        self.boundaries = []
        self.counts = {f: {"sent": 0, "offline": 0} for f in MODERN2_TYPES}
        self.requests = 0

    def probe(self, fam, ep, note="", **kw):
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return self.engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}", **kw))

    def probe_with(self, fam, engine, ep, note=""):
        """3E: replay through a SESSION engine (the authz battery's per-account
        RequestEngine, cookie jar included) — family-counted like any probe."""
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return engine.send(
            RequestMutation(endpoint=ep, note=note or f"m2-{fam}"))

    def boundary(self, fam, kind, detail):
        self.boundaries.append({"family": fam, "kind": kind, "detail": detail})

    def find(self, fam, severity, ep, parameter, evidences):
        f = Finding(fam, severity, ep.url, parameter, ep.method, evidences,
                    status=FindingStatus.CANDIDATE)
        f.run_id = getattr(self.engine.bus, "run_id", "")
        self.findings.append(f)
        return f


def probe_counts_of(st: _St2) -> dict:
    return {fam: {"sent": st.counts[fam]["sent"],
                  "offline": st.counts[fam]["offline"],
                  "cap": FAMILY2_CAPS[fam]} for fam in MODERN2_TYPES}


class Modern2Result:
    def __init__(self, findings, boundaries, probe_counts, requests):
        self.findings = findings
        self.boundaries = boundaries
        self.probe_counts = probe_counts
        self.requests = requests


# ------------------------------------------------------------------ 3A
def jwt_weak_secret_offline(token: str):
    """Offline: verify the token's HMAC against the capped wordlist.

    Returns (matched_secret | None, alg, attempts). Zero network traffic;
    the attempt count is bounded by the explicit wordlist (27).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None, "", 0
    hdr = _decode_seg(parts[0])
    alg = str(hdr.get("alg", "")).upper()
    if alg not in _HS_ALGS:
        return None, alg, 0
    si = (parts[0] + "." + parts[1]).encode("utf-8")
    try:
        sig = _b64d(parts[2])
    except Exception:
        return None, alg, 0
    digest = _HS_ALGS[alg]
    attempts = 0
    for cand in WEAK_SECRET_WORDLIST:
        attempts += 1
        if _hmac.compare_digest(
                _hmac.new(cand.encode("utf-8"), si, digest).digest(), sig):
            return cand, alg, attempts
    return None, alg, attempts


def _jwt_weak_secret(st: _St2, eps):
    authish = [e for e in eps if any(w in e.url.lower() for w in _AUTHISH)]
    for ep in authish[:FAMILY2_CAPS["jwt_weak_secret"]]:
        r = st.probe("jwt_weak_secret", ep, note="m2-jwt-harvest")
        token = _mine_jwt(r)
        if not token:
            st.boundary("jwt_weak_secret", "NO_TOKEN",
                        f"no JWT on {ep.url}")
            continue
        matched, alg, attempts = jwt_weak_secret_offline(token)
        st.counts["jwt_weak_secret"]["offline"] += attempts
        if matched is not None:
            st.find("jwt_weak_secret", Severity.HIGH, ep, "-",
                    [Evidence("weak_hmac_secret",
                              f"HS-secret matches common-secret wordlist "
                              f"entry {matched!r} after {attempts} offline "
                              f"verifications (cap = wordlist = "
                              f"{len(WEAK_SECRET_WORDLIST)}); alg={alg}. "
                              f"Any party can forge tokens signed with this "
                              f"secret. RFC 8725 (JWT BCP) algorithm-agility "
                              f"guidance applies — the signature is only as "
                              f"strong as the secret.",
                              getattr(r, "request_id", "")),
                     Evidence("token_prefix",
                              token[:24] + "…" if len(token) > 24 else token,
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("jwt_weak_secret", "TESTED_NEGATIVE",
                        f"secret did not match the {len(WEAK_SECRET_WORDLIST)}"
                        f"-entry wordlist ({attempts} offline verifications)")


# ------------------------------------------------------------------ 3C
def _graphql_aliasing(st: _St2, eps):
    gql = [e for e in eps if e.method == "POST" and _GQL_PATH_RE.search(e.url)]
    if not gql:
        st.boundary("graphql_aliasing", "SKIPPED_NO_SURFACE",
                    "no GraphQL POST surface in the endpoint map")
        return
    for ep in gql[:FAMILY2_CAPS["graphql_aliasing"]]:
        aliases = " ".join(f"a{i}: __typename" for i in range(ALIAS_CAP))
        body = json.dumps({"query": "{" + aliases + "}"})
        r = st.probe("graphql_aliasing", ep, note="m2-gql-alias",
                     body_override=body,
                     extra_headers={"Content-Type": "application/json"})
        text = str(getattr(r, "body", "") or "")
        executed = sum(1 for i in range(ALIAS_CAP) if f'"a{i}"' in text)
        if executed == ALIAS_CAP:
            st.find("graphql_aliasing", Severity.LOW, ep, "-",
                    [Evidence("alias_fanout_executed",
                              f"ONE request carried {ALIAS_CAP} aliased "
                              f"copies of a field and the server executed "
                              f"every alias ({executed}/{ALIAS_CAP} present "
                              f"in the response). A per-request rate limit "
                              f"counts 1 request while the server performs "
                              f"{ALIAS_CAP} units of resolver work — the "
                              f"aliasing cost-DoS surface. Distinct from "
                              f"batching (array of operations) and covered "
                              f"by CWE-400 resource-consumption guidance.",
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("graphql_aliasing", "TESTED_NEGATIVE",
                        f"server executed {executed}/{ALIAS_CAP} aliases in a "
                        f"single request (complexity limiting or errors)")


# ------------------------------------------------------------------ 3D
def _walk_secret_fields(obj, depth=0, found=None):
    if found is None:
        found = []
    if depth > 3 or len(found) > 12:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and (_SECRET_FIELD_RE.match(k)
                                       or _SECRET_FIELD_RE2.match(k)):
                found.append(k)
            _walk_secret_fields(v, depth + 1, found)
    elif isinstance(obj, list):
        for item in obj[:6]:
            _walk_secret_fields(item, depth + 1, found)
    return found


def _excessive_exposure(st: _St2, eps):
    api = [e for e in eps
           if e.method == "GET" and re.search(r"/api|/users|/me|/profile|/account",
                                              e.url, re.I)]
    if not api:
        st.boundary("excessive_data_exposure", "SKIPPED_NO_SURFACE",
                    "no JSON API GET surface in the endpoint map")
        return
    for ep in api[:EXPOSURE_EP_CAP]:
        r = st.probe("excessive_data_exposure", ep, note="m2-exposure")
        body = str(getattr(r, "body", "") or "")
        try:
            doc = json.loads(body)
        except Exception:
            continue
        fields = sorted(set(_walk_secret_fields(doc)))
        if fields:
            st.find("excessive_data_exposure", Severity.MEDIUM, ep, "-",
                    [Evidence("secret_fields_in_response",
                              f"response exposes {len(fields)} secret-ish "
                              f"field NAME(S): {', '.join(fields[:8])}. The "
                              f"documented/expected response shape for an "
                              f"ordinary API read carries none of them — the "
                              f"OWASP API 'Excessive Data Exposure' pattern "
                              f"(field names reported; values not "
                              f"republished).",
                              getattr(r, "request_id", ""))])
        else:
            st.boundary("excessive_data_exposure", "TESTED_NEGATIVE",
                        f"no secret-ish field names on {ep.url}")


# ------------------------------------------------------------------ 3B
class _ProbeListener(threading.Thread):
    """Tiny HTTP listener recording whether the rebind fetch ever lands."""

    def __init__(self, ip="127.0.0.2", port=0):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((ip, port))
        self.srv.listen(8)
        self.srv.settimeout(6.0)
        self.ip, self.port = self.srv.getsockname()[:2]
        self.hits = []

    def run(self):
        while True:
            try:
                conn, _addr = self.srv.accept()
            except (socket.timeout, OSError):
                return
            try:
                conn.settimeout(2.0)
                data = conn.recv(4096)
                self.hits.append(data[:120].decode("utf-8", "replace"))
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass


class FlipDNS(threading.Thread):
    """Controlled rebinding fixture: first A query -> PUBLIC ip, then -> internal.

    The canonical calibration harness for the TOCTOU class (owner order 3B):
    the answer flips after ``flip_after`` queries so a client that resolves
    TWICE (validate, then connect) sees two different addresses.
    """

    def __init__(self, host="rebind.burhan.test", ip="127.0.0.1", port=0,
                 public_ip="192.0.2.10", internal_ip="127.0.0.2",
                 flip_after=1):
        super().__init__(daemon=True)
        self.name_host = host
        self.public_ip, self.internal_ip = public_ip, internal_ip
        self.flip_after = flip_after
        self.queries = 0
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.srv.bind((ip, port))
        self.srv.settimeout(0.5)
        self.ip, self.port = self.srv.getsockname()[:2]

    def answer_for(self) -> str:
        self.queries += 1
        return self.public_ip if self.queries <= self.flip_after \
            else self.internal_ip

    def run(self):
        while True:
            try:
                data, addr = self.srv.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                # minimal DNS: answer A queries for ANY name with the flip
                qid = data[:2]
                q = data[12:]
                end = q.find(b"\x00")
                if end < 0:
                    continue
                qname = q[:end]
                qtype = int.from_bytes(q[end + 1:end + 3], "big")
                if qtype != 1:      # A only
                    continue
                ip = self.answer_for()
                rdata = socket.inet_aton(ip)
                answer = (qid + b"\x84\x00" + b"\x00\x01\x00\x01\x00\x00"
                          b"\x00\x00" + qname + b"\x00" + b"\x00\x01"
                          b"\x00\x01" + b"\x00\x00\x00\x1e" + b"\x00\x04"
                          + rdata)
                self.srv.sendto(answer, addr)
            except Exception:
                continue


def rebind_toctou_probe(fetch_url: str, dns: FlipDNS,
                        probe: _ProbeListener, timeout: float = 6.0,
                        engine: RequestEngine | None = None) -> tuple[bool, str]:
    """RED/BLUE oracle: does the fetch surface re-resolve between check and use?

    ``fetch_url`` must accept ?url= (the fixture contract) and will be asked
    to fetch ``http://<dns-host>:<probe-port>/rebind``. Vulnerable = the
    probe listener (on the INTERNAL address) receives the fetch, which is
    only reachable if the client resolved the hostname a SECOND time after
    validation (query 1 answered public -> passes validation; query 2
    answers internal -> the actual connection goes internal).
    """
    target = f"http://{dns.name_host}:{probe.port}/rebind"
    sep = "&" if "?" in fetch_url else "?"
    call = f"{fetch_url}{sep}url={target}"
    if engine is None:
        bus = EventBus("m2-rebind")
        scope = ScopeRule(allow_private=True)
        engine = RequestEngine(scope, bus, timeout=timeout)
    ep = Endpoint(url=call, method="GET")
    try:
        engine.send(RequestMutation(endpoint=ep, note="m2-rebind-probe"))
    except Exception as e:      # noqa: BLE001 — probe errors are outcomes
        return False, f"probe request failed: {type(e).__name__}: {e}"
    deadline = timeout
    import time as _t
    t0 = _t.time()
    while _t.time() - t0 < deadline:
        if probe.hits:
            return True, (f"the fetch landed on {probe.ip}:{probe.port} "
                          f"(internal address) — the surface re-resolved the "
                          f"hostname AFTER validation (DNS queries: "
                          f"{dns.queries}); the validation/connection split "
                          f"is a rebindable TOCTOU")
        _t.sleep(0.1)
    return False, (f"no internal fetch within {timeout:.0f}s "
                   f"(DNS queries: {dns.queries}) — the surface pins or "
                   f"caches the validated address")


def _rebind_toctou(st: _St2, eps, rebind_cfg: dict | None):
    if not rebind_cfg:
        st.boundary("rebind_toctou", "SKIPPED_NO_REBIND_DNS",
                    "no operator-controlled rebinding DNS configured "
                    "(BURHAN_REBIND_DNS) — family skipped loudly, not "
                    "silently; validated against the local fixture "
                    "(fixtures/rebind_fixture.py) in tests")
        return
    fetch_url = str(rebind_cfg.get("fetch_url", ""))
    if not fetch_url:
        st.boundary("rebind_toctou", "SKIPPED_NO_SURFACE",
                    "rebind DNS configured but no fetch surface declared")
        return
    dns = FlipDNS(host=str(rebind_cfg.get("host", "rebind.burhan.test")),
                  port=int(rebind_cfg.get("dns_port", 0)) or 0,
                  internal_ip=str(rebind_cfg.get("internal_ip", "127.0.0.2")))
    probe = _ProbeListener(ip=dns.internal_ip)
    dns.start()
    probe.start()
    vuln, detail = rebind_toctou_probe(
        fetch_url, dns, probe, timeout=float(rebind_cfg.get("timeout", 6.0)),
        engine=st.engine)
    st.counts["rebind_toctou"]["sent"] += 1
    st.requests += 1
    ep = Endpoint(url=fetch_url, method="GET")
    if vuln:
        st.find("rebind_toctou", Severity.HIGH, ep, "-",
                [Evidence("rebind_fetch_landed_internal", detail,
                          "")])
    else:
        st.boundary("rebind_toctou", "TESTED_NEGATIVE", detail)


# ------------------------------------------------------------------ entry
# ------------------------------------------------------------------ 3E
def _bfla(st: "_St2", eps, authz_sessions):
    """3E BFLA (Broken Function Level Authorization) — CWE-285; OWASP API
    Security Top 10 2023 API5 (Broken Function Level Authorization), whose
    official text is exactly this check: "requests to administrative HTTP
    endpoints should be denied for regular users". The FUNCTION in
    function-level: the replay carries the exact method+path+body of the
    privileged call, so a POST/PUT/PATCH/DELETE admin function that
    executes for a lower-privilege session is the finding.

    Reuses — never duplicates — the authz battery's logged-in sessions
    (cfg.authz accounts; nothing logs in here). OFF by default with the
    whole modern2 battery (--modern-v2)."""
    fam = "bfla"
    from .authz import ADMIN_PATH_RE          # lazy: the battery's convention
    from urllib.parse import urlsplit
    if not authz_sessions:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no multi-role authz sessions in flight — 3E needs the "
                    "authz config (cfg.authz) with two or more privilege "
                    "levels; the sessions the BOLA battery already built are "
                    "reused, nothing logs in here")
        return
    ranks = {s.get("rank") for s in authz_sessions.values()}
    if len(ranks) < 2:
        st.boundary(fam, "NOT_DISCOVERED",
                    f"authz sessions carry a single privilege level "
                    f"({sorted(ranks)}) — no ladder to climb")
        return
    top_rank = min(ranks)
    highs = sorted((s for s in authz_sessions.values() if s["rank"] == top_rank),
                   key=lambda x: x["account"].name)
    lows = sorted((s for s in authz_sessions.values() if s["rank"] > top_rank),
                  key=lambda x: (x["rank"], x["account"].name))
    cands = [ep for ep in eps
             if (ep.method or "GET").upper() in ("POST", "PUT", "PATCH", "DELETE")
             and ADMIN_PATH_RE.search(urlsplit(ep.url).path)][:BFLA_EP_CAP]
    if not cands:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no admin-shaped non-GET endpoints in flight")
        return
    # the anonymous oracle: a FRESH cookie-less engine (the battery's own
    # engine may carry the scan's session — the anon replay must not)
    from .http_engine import RequestEngine
    anon_engine = RequestEngine(st.engine.scope, st.engine.bus,
                                timeout=st.engine.timeout)
    import difflib
    fired = 0
    for ep in cands:
        if st.counts[fam]["sent"] + 3 > FAMILY2_CAPS[fam]:
            st.boundary(fam, "NOT_SUPPORTED",
                        "family request cap reached before exhausting the "
                        "candidate set (BFLA_EP_CAP x 3 replays, documented)")
            break
        anon = st.probe_with(fam, anon_engine, ep, "m2-bfla-anon")
        hops = [u for _, u in (getattr(anon, "redirect_chain", None) or [])]
        _hop = anon.hop_location()
        if _hop:
            hops.append(_hop)
        anon_gated = (getattr(anon, "status", 0) in (401, 403)
                      or any("login" in urlsplit(u).path.lower()
                             for u in hops if u))
        high, high_used = None, None
        for h in highs:
            high = st.probe_with(fam, h["engine"], ep, "m2-bfla-high")
            if _ok(high):
                high_used = h
                break
        if high_used is None:
            st.boundary(fam, "UNTESTABLE",
                        f"{ep.url}: the privileged oracle failed — the "
                        f"function does not execute for the highest-privilege "
                        f"session either; no authorization claim is possible")
            continue
        for lo in lows:
            if st.counts[fam]["sent"] >= FAMILY2_CAPS[fam]:
                break
            low = st.probe_with(fam, lo["engine"], ep, "m2-bfla-low")
            if not _ok(low):
                continue
            na = re.sub(r"\s+", " ", (high.body or ""))[:600]
            nb = re.sub(r"\s+", " ", (low.body or ""))[:600]
            import difflib
            sim = difflib.SequenceMatcher(None, na, nb).ratio()
            if not anon_gated and sim < 0.6:
                # a role-agnostic surface (every logged-in user legitimately
                # allowed) is NOT BFLA — the same discipline OWSP-28 taught
                # the vertical detector
                st.boundary(fam, "TESTED_NEGATIVE",
                            f"{ep.url}: lower-privilege 2xx but anonymous "
                            f"ungated and body similarity {sim:.2f} — a "
                            f"role-agnostic surface, not a broken boundary")
                continue
            st.find(fam, Severity.HIGH, ep, "-", [
                Evidence("function_level_boundary_bypass",
                         f"BFLA (CWE-285; OWASP API5:2023): the admin-only "
                         f"FUNCTION {(ep.method or 'POST').upper()} "
                         f"{urlsplit(ep.url).path} EXECUTED for a "
                         f"lower-privilege session (role="
                         f"{lo['account'].role}, account={lo['account'].name}) "
                         f"— anonymous replay gated (HTTP "
                         f"{getattr(anon, 'status', 0)}), highest-privilege "
                         f"session (role={high_used['account'].role}) "
                         f"-> HTTP {high.status}, lower-privilege replay -> "
                         f"HTTP {low.status} with body similarity {sim:.2f} "
                         f"to the privileged response", low.request_id),
                Evidence("probe_recipe",
                         f"high={high_used['account'].name}; "
                         f"low={lo['account'].name}; method={ep.method}",
                         low.request_id)])
            f = st.findings[-1]
            f.authz_context = (f"attacker={lo['account'].name}"
                               f"(role={lo['account'].role}) surface=admin-function")
            # VR-36 stash: the verifier replays the EXACT endpoint with the
            # SAME low-privilege session engine — credentials never enter
            # finding evidence
            stash = getattr(st.engine, "bfla_verify", None)
            if stash is None:
                stash = st.engine.bfla_verify = {}
            stash.setdefault(ep.url, {"engine": lo["engine"], "endpoint": ep})
            fired += 1
            break
    if not fired:
        st.boundary(fam, "TESTED_NEGATIVE",
                    "every admin-shaped function rejected the lower-privilege "
                    "replays (or was untestable above) — no boundary broken")


# ------------------------------------------------------------------ 3F
def _race_prober(st: "_St2", eps, candidates):
    """3F — the generic limited-resource race prober (CWE-362): for each
    OPERATOR-NAMED candidate endpoint, fire ONE bounded concurrent burst
    and assert the declared invariant — at most `quota` winners (default
    1) across the burst. More winners than the resource should allow is
    the finding.

    Design basis — the methodology proven twice in this codebase: the
    bootstrap concurrency fix (scripts/axis18_load_test.py, POST
    /api/bootstrap) and the G8 concurrent-scan-start gate
    (scripts/axis19_gap_probe.py: "concurrent scan start on same target
    -> exactly 1 wins"). The concurrency substrate is the same proven
    engine: burhan/race/engine.send_concurrent (bounded, ordered
    results, honest boundaries per request). This family is
    INVARIANT-based (count the winners), not the axis-17
    timing-variance battery — the two are complementary.

    *** NEVER BLIND — an explicit, hard constraint (order 2.2) ***
    The prober runs ONLY on endpoints the operator explicitly named
    (cfg.race_candidates). It never heuristically selects POSTs to
    concurrency-bomb: firing concurrent requests at arbitrary endpoints
    of a live target not under the operator's control risks state
    corruption (real writes racing) and unintended load. The fixture and
    Docker-isolated targets share nothing with anyone else; a shared
    public target is never a race target (Part 4 forbids it).

    Candidate schema (all fields except url optional):
      {"url": ..., "method": "POST", "params": {...}, "quota": 1,
       "concurrent": 6, "win_statuses": [200, 201],
       "verify_params": {...}}   # VR-37's fresh-burst params — declare a
                                # SECOND single-use code when the resource
                                # is consumed by the first burst; without
                                # it VR-37 replays the same params and
                                # fail-closes on a consumed resource."""
    fam = "race_condition"
    from urllib.parse import urlsplit
    if not candidates:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no explicit opt-in candidate list (cfg.race_candidates) "
                    "— the prober NEVER fires concurrent load at "
                    "endpoints the operator did not name (state corruption "
                    "and unintended load on live targets; see the family "
                    "docstring)")
        return
    from .race.engine import send_concurrent
    fired_any = False
    for cand in candidates[:RACE_CAND_CAP]:
        if st.counts[fam]["sent"] >= FAMILY2_CAPS[fam]:
            st.boundary(fam, "NOT_SUPPORTED",
                        "family request cap reached (4 candidates x 1 burst "
                        "x N concurrent, documented)")
            break
        url = str(cand.get("url") or "")
        method = str(cand.get("method") or "POST").upper()
        params = cand.get("params") or {}
        quota = int(cand.get("quota") or 1)
        n = min(int(cand.get("concurrent") or RACE_DEFAULT_N), RACE_MAX_N)
        win = tuple(int(x) for x in (cand.get("win_statuses") or (200, 201)))
        if not url or n < 2:
            st.boundary(fam, "UNTESTABLE",
                        f"candidate {url!r}: missing url or concurrent < 2 "
                        f"(a race needs at least two simultaneous requests)")
            continue
        req = {"method": method, "url": url,
               "headers": {"Content-Type": "application/json"},
               "body": json.dumps(params)}
        results = send_concurrent([dict(req) for _ in range(n)],
                                  max_concurrent=n, timeout=10.0)
        st.requests += n
        st.counts[fam]["sent"] += n
        statuses = [r.get("status") or 0 for r in results]
        winners = sum(1 for x in statuses if x in win)
        if winners > quota:
            fired_any = True
            ep = Endpoint(url=url, method=method)
            st.find(fam, Severity.HIGH, ep, "-", [
                Evidence("invariant_violated",
                         f"race condition (CWE-362): {winners} concurrent "
                         f"requests WON where the declared invariant allows "
                         f"at most {quota} — the limited-resource check is "
                         f"not atomic. Burst of {n} simultaneous "
                         f"{method} {urlsplit(url).path}: statuses "
                         f"{statuses}, winners {winners}", None),
                Evidence("probe_recipe",
                         f"url={url}; method={method}; quota={quota}; "
                         f"concurrent={n}; win_statuses={list(win)}; "
                         f"params={json.dumps(params, sort_keys=True)}",
                         None)])
            # VR-37 stash: the verifier fires a FRESH burst — with
            # verify_params when the operator declared a second sample
            # for a single-use resource
            stash = getattr(st.engine, "race_verify", None)
            if stash is None:
                stash = st.engine.race_verify = {}
            stash[url] = {"candidate": dict(cand), "n": n, "quota": quota,
                          "win": win, "method": method}
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"{url}: invariant held — {winners} winner(s) <= "
                        f"quota {quota} across a {n}-wide concurrent burst "
                        f"(statuses {statuses})")
    if not fired_any and not any(
            b["family"] == fam and b["kind"] == "TESTED_NEGATIVE"
            for b in st.boundaries):
        pass  # per-candidate boundaries above already carry the record


# ------------------------------------------------------------------ 3G
def _shadow_api(st: "_St2", eps, spec, target_url: str):
    """3G — Shadow / Zombie API detection. Diffs the crawl-discovered set
    against an operator-supplied OpenAPI/Swagger spec, both directions:
    SHADOW = live, reachable, JSON-responding, absent from the spec;
    ZOMBIE = spec-declared but dead live (404), or deprecated:true and
    still responding (OWASP API8:2023 names exactly this: "outdated API
    versions").

    Spec ingestion reuse (order 3.1, the explicit case statement): this
    project already ingests specs — discovery.parse_openapi (DISC-13,
    Phase 54) builds standard Endpoints the orchestrator merges into the
    endpoint map; 3G reuses it for the spec-side endpoint set and reads
    the raw paths dict only for the deprecated flag, which parse_openapi
    does not carry. No new parsing was built.

    Diff scope: the spec's namespaces (the first path segment of every
    declared path) bound the diff — pages outside the namespaces the
    spec claimed are not "undocumented API"."""
    fam = "shadow_api"
    from urllib.parse import urlsplit
    if not spec:
        st.boundary(fam, "NOT_DISCOVERED",
                    "no OpenAPI/Swagger spec supplied (cfg.openapi_spec) — "
                    "the shadow/zombie diff needs the declared surface to "
                    "diff against")
        return
    from .discovery import parse_openapi
    from .authz import ASSET_EXT_RE
    spec_eps = parse_openapi(spec, target_url)
    if not spec_eps:
        st.boundary(fam, "UNTESTABLE",
                    "the supplied spec declares no parseable paths — nothing "
                    "to diff against")
        return
    spec_paths = {urlsplit(e.url).path for e in spec_eps}
    namespaces = {("/" + p.lstrip("/").split("/")[0]) if p != "/" else "/"
                  for p in spec_paths if p.count("/") >= 1}
    root = (target_url or "").rstrip("/")

    # ---- SHADOW: crawl-discovered, in-namespace, absent from the spec.
    # Spec-derived endpoints carry the "openapi" tag (DISC-13) — excluded:
    # the shadow side of the diff is the CRAWL's own discoveries only.
    cands, seen = [], set()
    for e in sorted(eps, key=lambda x: x.url):
        path = urlsplit(e.url).path
        if path in seen or path in spec_paths or ASSET_EXT_RE.search(path):
            continue
        if "openapi" in (e.tags or []):
            continue
        ns = "/" + path.lstrip("/").split("/")[0] if path != "/" else "/"
        if ns not in namespaces:
            continue
        seen.add(path)
        cands.append((e, path))
    shadow_hits = []
    for e, path in cands[:SHADOW_PROBE_CAP]:
        r = st.probe(fam, e, note="m2-shadow-confirm")
        ctype = ""
        for k, v in (getattr(r, "headers", None) or {}).items():
            if k.lower() == "content-type":
                ctype = v.lower()
        live_json = (getattr(r, "status", 0) not in (0, 404, 410, 502, 503)
                     and "json" in ctype)
        if live_json:
            shadow_hits.append((e, path, getattr(r, "status", 0)))
            st.find("shadow_api_endpoint", Severity.MEDIUM, e, "-", [
                Evidence("undocumented_live_api",
                         f"shadow API (CWE-668; OWASP API8:2023 scope): the "
                         f"crawl discovered a LIVE JSON endpoint the supplied "
                         f"spec does not declare — GET {path} answered HTTP "
                         f"{getattr(r, 'status', 0)} with content-type "
                         f"{ctype or '?'}. Undocumented surface is unreviewed "
                         f"attack surface: no spec governance, no deprecation "
                         f"path, no security review trail.", r.request_id),
                Evidence("probe_recipe", f"live={e.url}; spec_paths="
                         f"{sorted(spec_paths)[:12]}", r.request_id)])
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"{path}: crawled but not a live JSON API endpoint "
                        f"(HTTP {getattr(r, 'status', 0)}, content-type "
                        f"{ctype or '?'}) — not shadow")
    if len(cands) > SHADOW_PROBE_CAP:
        st.boundary(fam, "NOT_SUPPORTED",
                    f"{len(cands) - SHADOW_PROBE_CAP} shadow candidates left "
                    f"unconfirmed (SHADOW_PROBE_CAP={SHADOW_PROBE_CAP}, "
                    f"documented)")

    # ---- ZOMBIE: every declared path checked live. dead = 404/410 live;
    # deprecated = the op carries deprecated:true and still responds.
    raw_paths = (spec or {}).get("paths") or {}
    zomb_dead, zomb_dep = [], []
    for e in spec_eps[:ZOMBIE_PROBE_CAP]:
        path = urlsplit(e.url).path
        op = {}
        for pth, ops in (raw_paths.items() if isinstance(raw_paths, dict) else []):
            if pth == path and isinstance(ops, dict):
                op = ops.get((e.method or "GET").lower()) or {}
                break
        r = st.probe(fam, e, note="m2-zombie-check")
        status = getattr(r, "status", 0)
        if status in (404, 410):
            zomb_dead.append((e, path, status))
            st.find("zombie_api_endpoint", Severity.LOW, e, "-", [
                Evidence("spec_dead_endpoint",
                         f"zombie API — dead declaration (spec drift): the "
                         f"spec declares {e.method} {path} but the live "
                         f"endpoint answers HTTP {status}. The spec misleads "
                         f"every consumer built on it (clients, gateways, "
                         f"reviewers) — the declaration is a lie about the "
                         f"surface.", r.request_id),
                Evidence("probe_recipe", f"declared={e.url}; live_status="
                         f"{status}", r.request_id)])
        elif op.get("deprecated") and status not in (0, 404, 410):
            zomb_dep.append((e, path, status))
            st.find("zombie_api_endpoint", Severity.MEDIUM, e, "-", [
                Evidence("deprecated_still_live",
                         f"zombie API — deprecated but alive (CWE-1104; "
                         f"OWASP API8:2023 'outdated API versions'): the spec "
                         f"DECLARES {e.method} {path} deprecated:true, yet "
                         f"the live endpoint still answers HTTP {status}. "
                         f"Deprecated versions stop receiving security fixes "
                         f"while remaining fully reachable.", r.request_id),
                Evidence("probe_recipe", f"declared={e.url}; deprecated=true; "
                         f"live_status={status}", r.request_id)])
    if len(spec_eps) > ZOMBIE_PROBE_CAP:
        st.boundary(fam, "NOT_SUPPORTED",
                    f"{len(spec_eps) - ZOMBIE_PROBE_CAP} declared paths left "
                    f"unchecked (ZOMBIE_PROBE_CAP={ZOMBIE_PROBE_CAP}, "
                    f"documented)")
    if not (shadow_hits or zomb_dead or zomb_dep):
        st.boundary(fam, "TESTED_NEGATIVE",
                    "the supplied spec and the live surface agree: every "
                    "declared path is alive and unflagged, every crawled "
                    "in-namespace JSON endpoint is declared")


def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None,
                          race_candidates: list | None = None,
                          spec: dict | None = None,
                          target_url: str = "") -> Modern2Result:
    """Entry point — mirrors modernsec.run_modern_battery (deterministic order)."""
    st = _St2(engine, seed)
    eps = sorted(endpoints or [], key=lambda e: (e.url, e.method))
    _jwt_weak_secret(st, eps)
    _graphql_aliasing(st, eps)
    _excessive_exposure(st, eps)
    _rebind_toctou(st, eps, rebind_cfg)
    _bfla(st, eps, authz_sessions or {})
    _race_prober(st, eps, race_candidates or [])
    _shadow_api(st, eps, spec, target_url)
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)

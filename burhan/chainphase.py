"""Burhan v4.3.0 — hash/crypto artifact chain phase (GTP-10, upgraded GTP-12c).

Two whole Benchmark categories (hash: 236, crypto: 246) never put the
digest/ciphertext in the response — the servlet WRITES it to a server-side
artifact (passwordFile.txt in the app's working directory) and echoes only
the plaintext. Black-box the value is invisible... unless the same app
carries a FILE-READ primitive, in which case the artifact is readable
through it. This phase chains the two:

  leg 0 (truncate): GTP-12c — the read primitive's window is the artifact's
                  FIRST 1000 bytes and every request to a hash/crypto
                  servlet APPENDS a line, so the scan's own battery traffic
                  exhausts the window mid-scan (the round-4 bound: chain
                  validated end-to-end on a controlled pair, 0 findings on
                  the full target). A VERIFIED write-capable sink
                  (FileOutputStream family, append=false) pointed at the
                  artifact opens it and closes WITHOUT writing — the open
                  alone truncates the file to zero (live-proven: read after
                  truncate returns 'Range [0, 0 + -1] out of bounds'). The
                  app's own launcher truncates the same artifact at boot
                  (GTP-10 fixture hygiene); this is the same operation,
                  on demand, before every probe cycle.
  leg 1 (write):  submit a KNOWN marker value to a hash/crypto-shaped
                  endpoint ("hashed and stored" / "encrypted and stored"
                  response gates — real apps say the same words).
  leg 2 (read):   read the artifact through a VERIFIED path-traversal
                  file-read primitive on the same app, from a bounded
                  wordlist of conventional artifact names.
  oracle (hash):  the artifact's appended hash_value line base64-decodes to
                  EXACTLY md5(K) or sha1(K) computed locally — a digest
                  match is cryptographic proof of the weak algorithm
                  (SHA-256+ endpoints never match either).
  oracle (crypto): GTP-12c three-tier block analysis on the fresh
                  secret_value line:
                    T1  16-byte plaintext -> 24-byte ciphertext = an 8-byte
                        BLOCK cipher (DES/DESede family) on direct-param
                        surfaces;
                    T2  8/16/24-byte plaintexts whose ciphertexts are ALL
                        length==0 (mod 8) with EXACT +8 steps = the 8-byte
                        block signature on ANY input shape (the raw-stream
                        servlets prepend 'name=' to the body — absolute
                        lengths shift, the signature does not; AES-GCM/CCM
                        answers pt+tag, never 0 mod 8 on these lengths);
                    T3  64-byte uniform plaintext -> any REPEATED 8- or
                        16-byte ciphertext block = ECB mode (deterministic,
                        pattern-preserving — DES/ECB and AES/ECB alike).

VR-27/VR-28 re-execute the full chain with fresh markers (truncate
included); every finding cites BOTH legs (write endpoint + read primitive)
in its evidence chain.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse

from .core import Endpoint, EventBus, Evidence, Finding, FindingStatus, Severity
from .http_engine import RequestMutation
from .detect import command_shaped_endpoint

ARTIFACT_WORDLIST = ["passwordFile.txt", "passwords.txt", "secret.txt", "secrets.txt",
                     "hashes.txt", "dump.txt", "data.txt", "output.txt", "users.txt",
                     "log.txt"]
HASH_GATE = re.compile(r"hashed and stored", re.I)
CRYPTO_GATE = re.compile(r"encrypted and stored", re.I)
K1 = "burhan-hash-probe-01"
P8 = "B" * 8
P16 = "A" * 16
P24 = "C" * 24
P64 = "D" * 64


def _extract_value(body: str, prefix: str) -> bytes | None:
    """GTP-12c: ESAPI encodeForBase64(..., true) LINE-WRAPS the base64 at 76
    chars — the value spans multiple physical lines and a naive
    [A-Za-z0-9+/=]+ match stops at the first newline (live-caught: 57 of 88
    ciphertext bytes on BenchmarkTest00019). This extracts the wrapped value
    from 'prefix=...' to the next 'name=' line or EOF, strips ALL whitespace,
    and decodes."""
    i = body.find(prefix + "=")
    if i < 0:
        return None
    seg = body[i + len(prefix) + 1:]
    # value ends at the next artifact line (word=...) at line start or EOF
    m = re.search(r"\n\s*\w+=", seg)
    if m:
        seg = seg[:m.start()]
    seg = re.sub(r"\s+", "", seg)
    if not seg:
        return None
    try:
        return base64.b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:
        return None


# CR-2 (crypto recall round, 2026-10-12): the five Benchmark input channels
# the declared/body write legs never reach (all shapes live-proven on the
# target this round — see results/verify_cr2/).
_CR2_CHANNELS = ("header", "hdrname", "cookie", "qs", "valmatch")


def chain_channel_mutation(ep, channel: str, value: str):
    """CR-2: the RequestMutation that submits VALUE to a hash/crypto-shaped
    endpoint through one of the five input channels the declared/body legs
    miss (the live-proven Benchmark shapes):
      header   : request.getHeader("<test-id>") — the test-id-named header's
                 VALUE is the plaintext (24+ crypto FNs).
      hdrname  : the first NON-STANDARD header's NAME is the plaintext — the
                 app's commonHeaders filter skips user-agent/accept/etc.
                 (live-proven by PT-2's traversal battery on the same shape).
      cookie   : the test-id-named cookie's VALUE (getCookies loop).
      qs       : everything after "<test-id>=" in the RAW query string
                 (getQueryString().substring shape).
      valmatch : the param NAME whose VALUE equals the test id
                 (getParameterNames value-matching loop — the PT-3 shape's
                 value side; the NAME is the plaintext).
    The probes ride PARAM-BARE endpoint copies (the PT-2 pollution lesson:
    the spec's decoy header param otherwise steals the first-non-standard
    slot and probe==control goes byte-identical)."""
    from .core import Endpoint, ParamLocation
    seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
    if not seg:
        return None
    bare = Endpoint(url=ep.url, method="POST")
    if channel == "header":
        return RequestMutation(endpoint=bare, param_name=seg,
                               param_location=ParamLocation.HEADER,
                               param_value=value, note="chain-write-header")
    if channel == "hdrname":
        return RequestMutation(endpoint=bare, param_name=value,
                               param_location=ParamLocation.HEADER,
                               param_value="1", note="chain-write-hdrname")
    if channel == "cookie":
        return RequestMutation(endpoint=bare, param_name=seg,
                               param_location=ParamLocation.COOKIE,
                               param_value=value, note="chain-write-cookie")
    if channel == "qs":
        return RequestMutation(endpoint=bare, param_name=seg,
                               param_location=ParamLocation.QUERY, method="POST",
                               param_value=value, note="chain-write-qs")
    if channel == "valmatch":
        return RequestMutation(endpoint=bare, param_name=value,
                               param_location=ParamLocation.BODY, method="POST",
                               param_value=seg, note="chain-write-valmatch")
    return None


class HashCryptoChainPhase:
    name = "hashchain"

    def __init__(self, engine, bus: EventBus):
        self.engine = engine
        self.bus = bus

    # ---------------------------------------------------------------- utils
    def _read_primitive(self, endpoints, findings):
        """A VERIFIED content-read path_traversal finding -> (Endpoint, param).
        Only file_marker evidence counts (the exists-oracle cannot read)."""
        eps = {ep.url: ep for ep in endpoints}
        for f in findings:
            if f.type != "path_traversal" or f.status != FindingStatus.VERIFIED:
                continue
            if not any(e.kind == "file_marker" for e in f.evidence):
                continue
            ep = eps.get(f.endpoint_url)
            if ep is None:
                continue
            param = f.parameter or next((p.name for p in ep.parameters
                                         if p.kind.value != "token" and not p.flow_control), None)
            if param:
                return ep, param
        return None

    def _prim_loc(self, ep, param) -> str:
        """GTP-12c: the param's ACTUAL location (verifier replays build bare
        Endpoints — without the explicit location the write leg ships as a
        query string and never reaches a cookie/header sink; live-caught:
        every VR-27/VR-28 replay rejected with the payload in the URL)."""
        for p in ep.parameters:
            if p.name == param:
                return p.location.value
        return "query"

    def _write_primitive(self, endpoints, findings):
        """GTP-12c: a VERIFIED write-capable path_traversal finding (the
        writability_oracle family — FileOutputStream sinks) -> (Endpoint,
        param). Truncation leg of the chain."""
        eps = {ep.url: ep for ep in endpoints}
        for f in findings:
            if f.type != "path_traversal" or f.status != FindingStatus.VERIFIED:
                continue
            if not any(e.kind == "writability_oracle" for e in f.evidence):
                continue
            ep = eps.get(f.endpoint_url)
            if ep is None:
                continue
            param = f.parameter or next((p.name for p in ep.parameters
                                         if p.kind.value != "token" and not p.flow_control), None)
            if param:
                return ep, param
        return None

    def _read_artifact(self, read_ep, read_param, name) -> str | None:
        r = self.engine.send(RequestMutation(endpoint=read_ep, param_name=read_param,
                                             param_value=name, note=f"artifact-read:{name}"))
        if r is None or r.error or not r.status:
            return None
        # GTP-10b (wave 3, live-caught on the pair mini-scan): the read
        # primitive echoes the artifact ENTITY-ENCODED (ESAPI: '=' as &#x3d;,
        # '+' as &#x2b;) — 'hash_value=&lt;b64&gt;' never matched the raw body
        # and the chain never even discovered its artifact. Normalize.
        from .detect import entity_normalize
        return entity_normalize(r.body or "")

    def _truncate_artifact(self, write_ep, write_param, artifact_name) -> bool:
        """GTP-12c: the truncation leg. A FileOutputStream sink opens the
        artifact with append=false and closes without writing — the OPEN
        alone zeroes it (live-proven). The app's own stack launcher performs
        the identical truncate at boot; this is the on-demand form."""
        if write_ep is None:
            return False
        r = self.engine.send(RequestMutation(endpoint=write_ep, param_name=write_param,
                                             param_value=artifact_name,
                                             note=f"artifact-truncate:{artifact_name}"))
        return r is not None and not r.error and bool(r.status)

    def _find_artifact(self, read_ep, read_param) -> tuple[str, str] | None:
        """(artifact name, current body) for the first wordlist hit carrying
        our value= lines."""
        for name in ARTIFACT_WORDLIST:
            body = self._read_artifact(read_ep, read_param, name)
            if body and ("hash_value=" in body or "secret_value=" in body):
                return name, body
        return None

    def _submit(self, ep: Endpoint, value: str):
        """Returns (response, write_param) — the param name the write rode.
        GTP-12f: prefer the param NAMED AFTER the URL's last segment — the
        Benchmark servlets read their OWN test-name parameter
        (getParameterValues("BenchmarkTestNNNNN")) and the drifted spec lists
        it among other decoys (password/username); the first-param choice
        hashed the decoy and the digest never matched."""
        seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
        p = next((x for x in ep.parameters if x.name == seg and x.kind.value != "token"
                  and not x.flow_control), None) \
            or next((x for x in ep.parameters
                     if x.kind.value != "token" and not x.flow_control and x.name), None)
        if p is not None:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=p.name,
                                                     param_value=value, note="chain-write")),
                    p.name)
        if seg:
            return (self.engine.send(RequestMutation(endpoint=ep, param_name=seg,
                                                     param_value=value, note="chain-write")), seg)
        return None, ""

    def _write_param_of(self, ep: Endpoint) -> str:
        seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
        p = next((x for x in ep.parameters if x.name == seg and x.kind.value != "token"
                  and not x.flow_control), None) \
            or next((x for x in ep.parameters
                     if x.kind.value != "token" and not x.flow_control and x.name), None)
        return p.name if p is not None else seg

    @staticmethod
    def _new_lines(before: str, after: str) -> list[str]:
        """Count-aware line diff: submitting the SAME marker twice appends an
        IDENTICAL line — set-membership diff would miss it (the second write
        is invisible). A line is new when its COUNT grew."""
        from collections import Counter
        cb, ca = Counter(before.splitlines()), Counter(after.splitlines())
        out = []
        for ln, n in ca.items():
            extra = n - cb.get(ln, 0)
            if extra > 0:
                out.extend([ln] * extra)
        return out

    def _gate_endpoints(self, endpoints):
        """Endpoints whose base response carries the write-gate text.
        MAX-10a: logout/destructive/command-shaped surfaces are never opened."""
        hash_eps, crypto_eps = [], []
        for ep in endpoints:
            if (ep.method or "GET").upper() not in ("GET", "POST"):
                continue
            if command_shaped_endpoint(ep):
                continue
            r = self.engine.send(RequestMutation(endpoint=ep, note="chain-gate"))
            if r is None or r.error or not r.status:
                continue
            body = r.body or ""
            if HASH_GATE.search(body):
                hash_eps.append(ep)
            elif CRYPTO_GATE.search(body):
                crypto_eps.append(ep)
        return hash_eps, crypto_eps

    # -------------------------------------------------------------- probe kit
    def _probe(self, ep, value, read_ep, read_param, artifact_name,
               write_ep=None, write_param=None, channel="declared") -> bytes | None:
        """GTP-12c: the bounded probe cycle — truncate (when a write sink
        exists), write the marker, read the artifact, return the FIRST
        fresh value (digest or ciphertext) as raw bytes. With truncation the
        window is deterministic: everything after the truncate is ours.
        GTP-12f: channel='body' rides the form body with the URL's last
        segment as the field name — the Benchmark servlets read their OWN
        test-name parameter (getParameterValues("BenchmarkTestNNNNN")) while
        the shipped openapi.yaml declares nothing (or a drifted decoy) on
        the POST surface; the declared-channel write hashed the EMPTY string
        and the digest never matched (96 hash / 80 crypto FNs live-caught)."""
        if write_ep is not None:
            # GTP-12g(h): a FAILED truncate must ABORT the probe — the read
            # would see the PREVIOUS probe's stale line (the last FP of the
            # round-5 re-measurement, BenchmarkTest01975: the P15 read saw
            # the stale 24B P16 line and 'confirmed' a block multiple on an
            # AES/GCM servlet)
            if not self._truncate_artifact(write_ep, write_param, artifact_name):
                return None
        if channel == "body":
            seg = (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
            if not seg:
                return None
            from .core import ParamLocation
            # GTP-12f: GET-with-body is structurally dead — the transport only
            # ships a body for POST/PUT/PATCH (http_engine._dispatch line 507),
            # so the form-body channel FORCES POST.
            r = self.engine.send(RequestMutation(endpoint=ep, param_name=seg,
                                                 param_location=ParamLocation.BODY,
                                                 method="POST",
                                                 param_value=value, note="chain-write-body"))
        elif channel in _CR2_CHANNELS:
            # CR-2: the five Benchmark input channels (param-bare copies —
            # the PT-2 pollution lesson)
            m = chain_channel_mutation(ep, channel, value)
            if m is None:
                return None
            r = self.engine.send(m)
        else:
            r, _wp = self._submit(ep, value)
        if r is None or r.error:
            return None
        body = self._read_artifact(read_ep, read_param, artifact_name)
        if not body:
            return None
        for prefix in ("hash_value", "secret_value"):
            v = _extract_value(body, prefix)
            if v is not None:
                # CR-3: keep the response of the LAST WRITE THAT LANDED — the
                # constant-family oracle reads the echoed plaintext from it
                # (probes that never wrote — e.g. the qs servlets' early
                # return on a missing query param — must not clobber it;
                # live-caught on BenchmarkTest01634).
                self._last_write_body = r.body or ""
                return v
        return None

    # -------------------------------------------------------------- phases
    def run(self, endpoints: list[Endpoint], findings: list):
        prim = self._read_primitive(endpoints, findings)
        if prim is None:
            return []
        read_ep, read_param = prim
        read_loc = self._prim_loc(read_ep, read_param)
        # GTP-12c: the truncation sink (may be None — the chain still runs
        # in the old before/after mode when no write primitive verified)
        wprim = self._write_primitive(endpoints, findings)
        write_ep, write_param = (wprim if wprim else (None, None))
        write_loc = self._prim_loc(write_ep, write_param) if write_ep else "query"
        out = []
        hash_eps, crypto_eps = self._gate_endpoints(endpoints)

        # ---- artifact DISCOVERY: a fresh app's artifact is EMPTY until the
        # first write. With a write sink: truncate + write + read each
        # candidate directly (the fresh window is deterministic). Without:
        # the original before/after diff.
        # FM-29 (full-repo first-match sweep, 2026-11-03): the writer used
        # to be ONE gate endpoint (the first hash gate) — if that surface
        # was down/readonly the whole 10-name wordlist burned on the dead
        # writer and the family returned [] SILENTLY while other gate
        # writers sat untried. Every gate writer is now swept (bounded,
        # deterministic order; one artifact is all the chain needs).
        writers = hash_eps + crypto_eps
        if len(writers) > 3:
            self.bus.emit(
                "ChainPhaseLeftovers",
                note=f"{len(writers) - 3} gate endpoints left unswept as "
                     f"writers (writer sweep cap 3, documented)")
            writers = writers[:3]
        artifact_name = None
        for writer in writers:
            if write_ep is not None:
                for name in ARTIFACT_WORDLIST:
                    v = self._probe(writer, K1, read_ep, read_param, name,
                                    write_ep, write_param)
                    if v is not None:
                        artifact_name = name
                        break
            else:
                for name in ARTIFACT_WORDLIST:
                    before = self._read_artifact(read_ep, read_param, name) or ""
                    wr = self._submit(writer, K1)[0] if hash_eps else self._submit(writer, P16)[0]
                    if wr is None or wr.error:
                        continue
                    after = self._read_artifact(read_ep, read_param, name) or ""
                    new_lines = self._new_lines(before, after)
                    if any("hash_value=" in ln or "secret_value=" in ln for ln in new_lines):
                        artifact_name = name
                        break
            if artifact_name is not None:
                break
        if artifact_name is None:
            if writers:
                self.bus.emit(
                    "ChainPhaseBoundary",
                    note=f"no artifact line appeared after sweeping "
                         f"{len(writers)} gate writers x {len(ARTIFACT_WORDLIST)} "
                         f"names — the write side of the chain is not observable "
                         f"on these surfaces (family honestly untested)")
            return []
            return []

        # ---- hash: exact-digest oracle --------------------------------
        import json as _json
        md5_k = hashlib.md5(K1.encode()).digest()
        sha1_k = hashlib.sha1(K1.encode()).digest()
        K2M = "burhan-hash-probe-02"
        for ep in hash_eps[:260]:
            d = None
            chan, wloc = "declared", self._prim_loc(ep, self._write_param_of(ep))
            if write_ep is not None:
                d = self._probe(ep, K1, read_ep, read_param, artifact_name,
                                write_ep, write_param)
                if d not in (md5_k, sha1_k):
                    # GTP-12f: the body-channel fallback (spec drift)
                    d2 = self._probe(ep, K1, read_ep, read_param, artifact_name,
                                     write_ep, write_param, channel="body")
                    if d2 in (md5_k, sha1_k):
                        d, chan, wloc = d2, "body", "body"
                    elif d2 is not None and d is None:
                        d, chan, wloc = d2, "body", "body"
            hit = None
            const_hit = None
            if d is not None and d not in (md5_k, sha1_k) and write_ep is not None:
                # GTP-12h (live-caught: 20 of the 76 remaining hash FNs): the
                # CONSTANT-DIGEST family — a switch/if on the safe path feeds
                # the digest a hardcoded value ('bob'); the input never
                # arrives. The ALGORITHM is still identifiable black-box: the
                # artifact line is byte-identical across two DISTINCT inputs
                # and its decoded length is the MD-family (16B) or SHA-1
                # (20B) output size — both cryptographically broken. SHA-256+
                # answers 32B+ and never fires.
                c2 = self._probe(ep, K2M, read_ep, read_param, artifact_name,
                                 write_ep, write_param, channel=chan)
                if c2 is not None and c2 == d and len(d) in (16, 20):
                    algo = "MD5/MD-family (16-byte digest)" if len(d) == 16 \
                        else "SHA-1 (20-byte digest)"
                    const_hit = algo
            if const_hit and not hit:
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan == "body"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": write_loc})
                out.append(Finding(type="weak_hash", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("digest_length_const",
                                 f"the artifact's hash_value line is INPUT-INDEPENDENT — "
                                 f"byte-identical across two distinct submissions "
                                 f"({K1!r} / {K2M!r}) — and decodes to {len(d)} bytes: the "
                                 f"{const_hit} output size. The hashed input is "
                                 "server-controlled (a constant on this path), but the "
                                 "ALGORITHM is identifiable by its digest length and it is "
                                 "a broken hash (CWE-327); SHA-256+ answers 32B+",
                                 None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))
                continue
            if d is not None:
                if d == md5_k:
                    hit = ("MD5", d)
                elif d == sha1_k:
                    hit = ("SHA-1", d)
            elif write_ep is None:
                # legacy mode (no write sink): before/after diff
                before = self._read_artifact(read_ep, read_param, artifact_name) or ""
                r, wparam = self._submit(ep, K1)
                if r is None or r.error:
                    continue
                after = self._read_artifact(read_ep, read_param, artifact_name) or ""
                for ln in self._new_lines(before, after):
                    m = re.search(r"hash_value=([A-Za-z0-9+/=]+)", ln)
                    if not m:
                        continue
                    try:
                        dd = base64.b64decode(m.group(1))
                    except Exception:
                        continue
                    if dd == md5_k:
                        hit = ("MD5", dd)
                        break
                    if dd == sha1_k:
                        hit = ("SHA-1", dd)
                        break
            if hit:
                algo, d = hit
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan == "body"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": write_loc})
                out.append(Finding(type="weak_hash", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("digest_match",
                                 f"known input {K1!r} submitted to this endpoint is stored as "
                                 f"{algo} — the artifact line 'hash_value={base64.b64encode(d).decode()}' "
                                 f"read back through a verified file-read primitive matches the "
                                 f"locally computed {algo} digest exactly; {algo} is a broken "
                                 "hash (CWE-327)", None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url}; read leg: {read_ep.url}?"
                                 f"{read_param}={artifact_name} (verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))

        # ---- crypto: three-tier block oracle (GTP-12g: P15 boundary gate) --
        P15 = "E" * 15
        def _is_block_cipher(cts: list[bytes | None]) -> bool:
            """GTP-12g (live-caught on the round-5 re-measurement: 25 verified
            weak_crypto FPs on AES/GCM servlets): a BARE length curve cannot
            separate an 8-byte block cipher from a stream+tag mode — AES/GCM
            with an 8-byte tag answers ct = pt + 8, which lands on EXACTLY the
            same all-multiples-of-8 +8-step curve as DES (16/24/32 for
            8/16/24-byte plaintexts). The decisive discriminator is the
            OFF-BOUNDARY probe: a block cipher pads EVERY length to a block
            multiple (a 15-byte plaintext still answers 0 mod 8), while
            pt+tag answers 15+8=23 (live-measured: 00058 GCM -> 23, 00005
            DES -> 16, 00019 DES-stream -> 40, 00345 CCM -> 42)."""
            return all(c is not None and len(c) % 8 == 0 for c in cts)

        # CR-2: the channel LADDER — declared, body, then the five Benchmark
        # input channels (header / header-name / cookie / query-string /
        # value-match). The first channel whose ciphertext LENGTH follows the
        # marker length (the input provably arrives) runs the full three-tier
        # oracle; a channel whose ct ignores the input is a constant candidate
        # (the CR-3 family) and the ladder moves on. Live-proven this round:
        # 23 of the 75 crypto FNs are controllable ONLY through these channels
        # (header-name 9, value-match 6, header-value 6, cookie 3, qs 4); the
        # 116 secure twins are ALL GCM/CCM (pt+tag curves) and die on the P15
        # off-boundary gate (live: 00058 16/24 + 15->23; 01227 24/32/40 +
        # 15->31) — zero DES/ECB exists in the secure set (static inventory of
        # all 246 crypto tests), so a fired block oracle cannot be a secure
        # twin on this surface.
        _WLOC = {"body": "body", "header": "header", "hdrname": "header",
                 "cookie": "cookie", "qs": "query", "valmatch": "body"}
        for ep in crypto_eps[:260]:
            if write_ep is None:
                continue      # legacy before/after mode cannot bound the window
            live = None       # (chan, ct8, ct16)
            const_ct = None   # CR-3: an input-INDEPENDENT ct (the constant family)
            const_chan = None
            for chan in ("declared", "body") + _CR2_CHANNELS:
                ct8 = self._probe(ep, P8, read_ep, read_param, artifact_name,
                                  write_ep, write_param, channel=chan)
                ct16 = self._probe(ep, P16, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if ct8 is None and ct16 is None:
                    continue
                # liveness = the ciphertext LENGTH follows the marker length —
                # NOT the raw bytes: a fresh-key cipher answers every probe
                # with different bytes at the SAME length (the constant family
                # live-caught by the unit fixture — the ladder never moved
                # past 'declared' and the channels never ran)
                if ct8 is not None and ct16 is not None \
                        and len(ct8) != len(ct16):
                    live = (chan, ct8, ct16)
                    break
                # NOTE: a BETWEEN-channel length difference is NOT liveness —
                # live-caught by the unit fixture: the header channel on a
                # header-NAME servlet feeds it the test-id as its fixed
                # plaintext (a DIFFERENT constant, 24B) and would shadow the
                # real hdrname channel. Liveness is only the WITHIN-channel
                # marker-length follow.
                if const_ct is None and ct16 is not None:
                    const_ct, const_chan = ct16, chan
            if live is None:
                # CR-3: the CONSTANT-PLAINTEXT family — the input never arrives
                # through ANY channel but the servlet still writes; the echoed
                # constant (visible in the write response) plus the input-
                # independent ct length identify the 8-byte block family on a
                # FIXED plaintext. The full-pad zone (len%8==0) is POISONED —
                # live-measured TN landscape: GCM-tag8/CCM constants answer
                # (8->16) and (0->8), byte-identical to DES there; every
                # measured TN tag is a standard 8/16 (never 1-7), so the
                # non-full-pad pad8 shape is clean (theoretical window: a
                # non-standard short-tag AEAD with a matching constant length
                # — documented, absent from the benchmark and common stacks).
                if const_ct is None:
                    continue
                from .detect import entity_normalize as _en_cr3
                _m = re.search(r"Sensitive value: '([^']*)'",
                               _en_cr3(getattr(self, "_last_write_body", "") or ""))
                _C = _m.group(1) if _m else ""
                _L, _lc = len(const_ct), len(_C)
                if _C and _lc % 8 != 0 and _L == (_lc // 8 + 1) * 8:
                    chan = const_chan or "declared"
                    wloc = _WLOC.get(chan) or self._prim_loc(ep, self._write_param_of(ep))
                    weak_reason = (f"the ciphertext is input-independent across every "
                                   f"input channel (14 channel probes, all {_L}B) and the "
                                   f"response echoes its fixed plaintext '" 
                                   f"{_C}' ({_lc}B) — a {_L}-byte ciphertext is EXACTLY "
                                   f"the 8-byte-block PKCS5 shape of that constant "
                                   f"({_lc}B pads to {_L}B) — an 8-byte BLOCK CIPHER "
                                   "(DES/DESede family) on a hardcoded plaintext "
                                   "(CWE-327); the full-pad zone (len%8==0) is excluded "
                                   "where GCM/CCM tag lengths collide")
                    _wp = self._write_param_of(ep) if chan == "declared" \
                        else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                    _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                           "read_loc": read_loc,
                                           "read_method": read_ep.method or "GET",
                                           "artifact": artifact_name,
                                           "write_param": _wp,
                                           "write_loc": wloc,
                                           "write_method": ("POST" if chan != "declared"
                                                             else (ep.method or "POST")),
                                           "truncate_url": (write_ep.url if write_ep else None),
                                           "truncate_param": write_param,
                                           "truncate_loc": (self._prim_loc(write_ep, write_param)
                                                            if write_ep else "query"),
                                           "constant": _C,
                                           **({"write_channel": chan}
                                              if chan in _CR2_CHANNELS else {})})
                    out.append(Finding(type="weak_crypto", severity=Severity.HIGH,
                        endpoint_url=ep.url, parameter="", method=ep.method,
                        evidence=[
                            Evidence("constant_block_oracle", weak_reason, None),
                            Evidence("chain_legs",
                                     f"write leg: {ep.url} (constant plaintext, channel "
                                     f"{chan}); read leg: {read_ep.url}?"
                                     f"{read_param}={artifact_name} (verified path_traversal)"
                                     + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                        " (verified write sink)" if write_ep else ""),
                                     None, _recipe)],
                        status=FindingStatus.CANDIDATE))
                continue
            chan, ct8, ct16 = live
            wloc = _WLOC.get(chan) or self._prim_loc(ep, self._write_param_of(ep))
            weak_reason = None
            if len(ct16) == 24:
                # GTP-12g: confirm with the OFF-BOUNDARY probe (15B -> must
                # still be a multiple of 8 on a real block cipher, AND
                # strictly SHORTER than ct16 — a block cipher grows 16->24;
                # an equal length means a STALE line (the truncate failed and
                # the read returned the previous probe's ciphertext))
                ct15 = self._probe(ep, P15, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if _is_block_cipher([ct15]) and len(ct15) < len(ct16):
                    weak_reason = ("known 16-byte plaintext encrypts to a 24-byte ciphertext "
                                   f"({base64.b64encode(ct16).decode()[:44]}…) and a 15-byte "
                                   f"plaintext still answers {len(ct15 or b'')}B (a block "
                                   "multiple) — an 8-byte BLOCK CIPHER (DES/DESede family), "
                                   "broken since the 1990s (CWE-327); AES-class answers "
                                   "pt+tag and leaves the multiple-of-8 grid off-boundary")
                else:
                    # the length curve matched but the boundary probe says
                    # stream+tag (the AES/GCM-8B-tag collision) — NOT weak
                    pass
            if weak_reason is None:
                # T2: the block-step signature on any input shape —
                # 8/16/24-byte plaintexts, ciphertexts all ==0 mod 8, +8 steps
                # (CR-2: ct8/ct16 come from the winning channel's screen)
                if ct8 is not None and ct8 != ct16 and len(ct8) % 8 == 0 \
                        and len(ct16) % 8 == 0 and len(ct16) - len(ct8) == 8:
                    ct24 = self._probe(ep, P24, read_ep, read_param, artifact_name,
                                       write_ep, write_param, channel=chan)
                    if ct24 is not None and len(ct24) % 8 == 0 \
                            and len(ct24) - len(ct16) == 8:
                        ct15 = self._probe(ep, P15, read_ep, read_param, artifact_name,
                                           write_ep, write_param, channel=chan)
                        if _is_block_cipher([ct15]):
                            weak_reason = (f"block-step signature: 8/16/24-byte known plaintexts "
                                           f"encrypt to {len(ct8)}/{len(ct16)}/{len(ct24)}-byte "
                                           "ciphertexts — all multiples of 8 with exact +8 steps, "
                                           "and the 15-byte off-boundary probe answers "
                                           f"{len(ct15 or b'')}B (still a multiple of 8) — an "
                                           "8-byte BLOCK CIPHER, DES family (AES-GCM/CCM answer "
                                           "plaintext+tag and leave the grid off-boundary) "
                                           "(CWE-327)")
            if weak_reason is None:
                # T3: ECB repeat — 64 uniform plaintext bytes
                ct64 = self._probe(ep, P64, read_ep, read_param, artifact_name,
                                   write_ep, write_param, channel=chan)
                if ct64 is not None and len(ct64) >= 24:
                    blocks = {8: [ct64[i:i + 8] for i in range(0, len(ct64) - 7, 8)],
                              16: [ct64[i:i + 16] for i in range(0, len(ct64) - 15, 16)]}
                    for bs, bl in blocks.items():
                        if len(bl) != len(set(bl)) and len(ct64) % bs == 0:
                            weak_reason = (f"known 64-byte repeated plaintext encrypts "
                                           f"to a ciphertext with REPEATED {bs}-byte "
                                           f"blocks ({len(bl)} blocks, "
                                           f"{len(set(bl))} unique) — ECB mode, "
                                           "deterministic and pattern-preserving "
                                           "(CWE-327)")
                            break
            if weak_reason:
                _wp = self._write_param_of(ep) if chan == "declared" \
                    else (urllib.parse.urlsplit(ep.url).path or "").rstrip("/").split("/")[-1]
                _recipe = _json.dumps({"read_url": read_ep.url, "read_param": read_param,
                                       "read_loc": read_loc,
                                       "read_method": read_ep.method or "GET",
                                       "artifact": artifact_name,
                                       "write_param": _wp,
                                       "write_loc": wloc,
                                       "write_method": ("POST" if chan != "declared"
                                                         else (ep.method or "POST")),
                                       "truncate_url": (write_ep.url if write_ep else None),
                                       "truncate_param": write_param,
                                       "truncate_loc": (self._prim_loc(write_ep, write_param)
                                                        if write_ep else "query"),
                                       **({"write_channel": chan}
                                          if chan in _CR2_CHANNELS else {})})
                out.append(Finding(type="weak_crypto", severity=Severity.HIGH,
                    endpoint_url=ep.url, parameter="", method=ep.method,
                    evidence=[
                        Evidence("block_oracle", weak_reason, None),
                        Evidence("chain_legs",
                                 f"write leg: {ep.url} via the {chan} channel; read leg: "
                                 f"{read_ep.url}?{read_param}={artifact_name} "
                                 "(verified path_traversal)"
                                 + (f"; truncate leg: {write_ep.url}?{write_param}={artifact_name}"
                                    " (verified write sink)" if write_ep else ""),
                                 None, _recipe)],
                    status=FindingStatus.CANDIDATE))
        return out

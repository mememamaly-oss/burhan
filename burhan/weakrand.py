"""Burhan v4.3.0 — weak random chain phase (GTP-09).

Runs after the active battery loop. For every endpoint whose response SETS
an application cookie (non-container), the phase classifies the value shape
and attempts to BREAK the generator that produced it:

  decimal-fraction cookies  -> Math.random()/nextDouble shapes.
    Family A (chain prediction): Math.random() is ONE static JVM generator
    — two observed cookies determine the 48-bit LCG state; the phase
    PREDICTS the third cookie's digits BEFORE fetching it. A match is
    mathematical proof of a time-seeded LCG (SecureRandom fails prediction).
  long-integer cookies      -> nextLong shapes (full 48-bit state exposed).
  base64 ~16-char cookies   -> nextBytes shapes (80 bits exposed).
    Family B (seed-relation attack): new Random() per request seeds with
    seedUniquifier ^ nanoTime and the uniquifier advances by an exact
    multiplicative constant — two exact states + the shared CLOCK_MONOTONIC
    window (agent-mode, same host as the target) solve for (u, t1, t2);
    a third cookie confirms the solved relation forward. SecureRandom
    satisfies the relation with probability ~2^-38 per window.

Honest limits (documented, never silently glossed): nextInt (32/48 bits) and
nextFloat (24 bits) cookies are listed as NOT RECOVERABLE; Family B requires
the clock-shared deployment (remote targets: family stays silent).
"""
from __future__ import annotations

import base64
import re
import time

from .core import Endpoint, EventBus, Evidence, Finding, FindingStatus, Severity
from .http_engine import RequestMutation
from .detect import command_shaped_endpoint
from . import jrand


CONTAINER_COOKIES = ("jsessionid", "phpsessid", "asp.net_sessionid")

# GTP-12b (round 5, live-caught on the OWASP Benchmark's weakrand category:
# 188 FNs at 13.8% recall): 193/218 vulnerable servlets draw their security
# value from `new java.util.Random()` — the VALUE never leaves the server
# (nextFloat consumed, discarded), so no output analysis can ever see it.
# But the servlet's own response TEXT names the generator: 'Weak Randomness
# Test java.util.Random.nextFloat() executed' (measured across the whole
# corpus: 218/218 vulnerable servlets disclose a non-CSPRNG class name,
# 0/275 SecureRandom servlets do, no other category does). An in-band
# self-disclosure of a predictable PRNG behind a security value IS the
# finding — the evidence is the response text itself, and the verifier
# re-observes it on a fresh fetch.
WEAK_PRNG_DISCLOSURE = re.compile(
    r"java\.util\.Random(?:\.\w+\(\))?"      # Java LCG (never matches SecureRandom)
    r"|Math\.random\(\)"                      # static JVM/JS LCG
    r"|\bnew\s+Random\s*\(\s*\)"             # Java/JS/C# shape
    r"|\bmt_rand\s*\(|\brand\s*\(\s*\)",   # PHP mt_rand / bare rand()
    re.I)
SECURE_PRNG_MARK = re.compile(r"SecureRandom|crypto\s*-?\s?secure|/dev/urandom|CSPRNG",
                               re.I)


class WeakRandomPhase:
    name = "weakrand"

    def __init__(self, engine, bus: EventBus):
        self.engine = engine
        self.bus = bus

    # ---------------------------------------------------------------- utils
    def _set_cookies(self, resp) -> list[tuple[str, str]]:
        out = []
        raw = (resp.headers or {}).get("set-cookie") or ""
        for chunk in re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw):
            m = re.match(r"\s*([^=;,\s]+)\s*=\s*([^;]*)", chunk)
            if not m:
                continue
            name, val = m.group(1), m.group(2).strip()
            if not val or name.lower() in CONTAINER_COOKIES:
                continue
            # GTP-09b (wave 3, live-caught on the Benchmark weakrand pages): the
            # old guard skipped every cookie whose Set-Cookie line carries the
            # Secure ATTRIBUTE (the rememberMe cookies ARE Secure-marked in this
            # deployment while served over plain HTTP) — 'secure' in the whole
            # chunk also matches Path values. Observing the VALUE is the point;
            # the attribute is irrelevant here.
            out.append((name, val))
        return out

    def _base_fetch(self, ep):
        """GTP-12b: ONE stateless base response per endpoint — the disclosure
        oracle reads its body; the cookie families read its Set-Cookie."""
        _m = RequestMutation(endpoint=ep, note="weakrand-sample")
        _m.skip_jar = True   # runtime attribute, NOT a dataclass field (see GTP-09b note)
        return self.engine.send(_m)

    def _fetch_cookie(self, ep) -> tuple[str, str] | None:
        # GTP-09b: skip_jar — a STATELESS sample. With the jar replaying the
        # rememberMe cookie the servlet took the foundUser branch ("Welcome
        # back") and never set a fresh cookie: the phase saw one sample per
        # endpoint and the chain/relation families never had a pair to break.
        r = self._base_fetch(ep)
        if r is None or r.error or not r.status:
            return None
        cs = self._set_cookies(r)
        return cs[0] if cs else None

    def _family_disclosure(self, ep: Endpoint, body: str, req_id) -> Finding | None:
        """GTP-12b: the endpoint's own response discloses a predictable-PRNG
        class as the generator behind its security value. The secure twin
        (java.security.SecureRandom) never matches — measured 218/218 vuln,
        0/275 secure, zero cross-category hits on the full 2,740 corpus."""
        if not body:
            return None
        m = WEAK_PRNG_DISCLOSURE.search(body)
        if not m:
            return None
        # same-phrase secure mention (a body that names BOTH a CSPRNG and a
        # weak class in the SAME sentence is a comparison, not a disclosure —
        # require the weak class to stand alone in its sentence)
        sentence = re.split(r"[.!<\n]", body[max(0, m.start() - 120):m.end() + 120])
        seg = next((s for s in sentence if m.group(0) in s), "")
        if seg and SECURE_PRNG_MARK.search(seg):
            return None
        excerpt = body[max(0, m.start() - 60):m.end() + 60].strip()[:180]
        return Finding(type="weak_random", severity=Severity.HIGH,
                       endpoint_url=ep.url, parameter="", method=ep.method,
                       evidence=[Evidence("prng_disclosure",
                          f"the endpoint's own response discloses its security-value "
                          f"generator as {m.group(0)!r} — a predictable LCG-family "
                          f"PRNG, not a CSPRNG (CWE-330); any token, cookie or "
                          f"secret derived from it is guessable. Disclosed text: "
                          f"…{excerpt}…", req_id)],
                       status=FindingStatus.CANDIDATE)

    # ------------------------------------------------------------ families
    def _family_chain(self, ep: Endpoint, cname: str) -> Finding | None:
        """Math.random() static-chain prediction on decimal-fraction cookies."""
        c1 = self._fetch_cookie(ep)
        if not c1 or not c1[1].isdigit():
            return None
        d1 = jrand.double_from_cookie(c1[1])
        if d1 is None:
            return None
        c2 = self._fetch_cookie(ep)
        if not c2:
            return None
        d2 = jrand.double_from_cookie(c2[1])
        if d2 is None:
            return None
        # the two cookies each consumed ONE nextDouble (two next() calls).
        # Recover the state between them: candidates for the state after
        # cookie1's second next() must predict cookie2 exactly.
        cands = []
        for s1 in jrand.recover_state_nextdouble(d1):
            # s1 = state after cookie1's FIRST next(); the second next gives
            # the 27-bit part. State after both = next_state(s1).
            s_after = jrand.next_state(s1)
            if jrand.predict_double_int(s_after) == d2:
                cands.append(s_after)
        if not cands:
            return None           # fresh instances or CSPRNG — not a shared chain
        # FM-21 (first-match audit): cands can hold up to 4 recovered states
        # (recover_state_nextdouble). The old cands[0] single pick predicted
        # cookie3 from the FIRST state only — the matching state sitting
        # later in the list yielded a false negative. Every candidate gets
        # its prediction; the fetched cookie3 arbitrates (self-verifying).
        preds = []
        for s_after in cands:
            # cookie2 consumed two more next() calls; the PREDICTED cookie3
            # rides the state after cookie2's calls.
            s_before3 = jrand.next_state(jrand.next_state(s_after))
            preds.append(jrand.double_int_to_cookie(jrand.predict_double_int(s_before3)))
        predicted = preds[0]
        c3 = self._fetch_cookie(ep)
        if not c3:
            return None
        got = c3[1].strip()
        # FM-21: any candidate's prediction matching the fetched cookie3
        # proves the shared chain (the exact state is then the matching one).
        # Java emits the shortest repr; tolerate leading-zero shape diffs.
        def _shape_eq(a: str, b: str) -> bool:
            return a == b or (a.lstrip("0") == b.lstrip("0") and a and b)
        if any(_shape_eq(got, p) for p in preds):
            predicted = next(p for p in preds if _shape_eq(got, p))
            return Finding(type="weak_random", severity=Severity.HIGH,
                           endpoint_url=ep.url, parameter=cname, method=ep.method,
                           evidence=[Evidence("lcg_chain_prediction",
                              f"cookie '{cname}' values come from a SHARED time-seeded "
                              f"java.util.Random (Math.random class): the 48-bit LCG state "
                              f"recovered from cookies 1-2 PREDICTED cookie 3 before it was "
                              f"fetched (predicted {predicted!r}, observed {got!r}) — a "
                              "CSPRNG fails this prediction", None,
                              f"{c1[1][:24]} / {c2[1][:24]} / {got[:24]}")],
                           status=FindingStatus.CANDIDATE)
        return None

    def _family_relation(self, ep: Endpoint, cname: str, kind: str) -> Finding | None:
        """new Random() per request: exact state recovery + seedUniquifier
        relation solve anchored on the shared CLOCK_MONOTONIC domain.
        kind: 'long' (nextLong cookies), 'bytes' (base64 nextBytes),
        'double' (decimal-fraction nextDouble cookies — 53-bit recovery)."""
        samples = []
        for _ in range(3):
            t0 = time.monotonic_ns()
            c = self._fetch_cookie(ep)
            t1 = time.monotonic_ns()
            if not c:
                return None
            samples.append((c[1].strip(), (t0 + t1) // 2))
        # FM-21b (full-repo first-match sweep, 2026-11-03): the 'double'
        # branch used to keep ONE recovered state (cands[0]) — a wrong pick
        # fed a false seed into the relation solve and killed the whole
        # 3-sample confirmation (false negative, the FM-21 twin). Every
        # candidate is now carried per sample; the relation solve + the
        # forward confirmation on request 3 arbitrate (self-verifying,
        # pure arithmetic — no extra requests).
        cand_sets: list[list[tuple[int, int]]] = []
        for val, ts in samples:
            per_sample: list[tuple[int, int]] = []
            if kind == "long":
                try:
                    v = jrand.parse_java_long(val)
                except ValueError:
                    return None
                per_sample = [(jrand.seed_from_state(
                    jrand.recover_state_nextlong(v)), ts)]
            elif kind == "double":
                d = jrand.double_from_cookie(val)
                if d is None:
                    return None
                per_sample = [(jrand.seed_from_state(s), ts)
                              for s in jrand.recover_state_nextdouble(d)]
            else:                                  # base64 nextBytes
                try:
                    bs = base64.b64decode(val + "===")[:10]
                except Exception:
                    return None
                per_sample = [(jrand.seed_from_state(
                    jrand.recover_state_nextbytes(bs)), ts)]
            if not per_sample:
                return None
            cand_sets.append(per_sample)
        # relation solve on requests 1-2 (window covers HTTP RTT jitter),
        # confirm forward on request 3 — over the candidates cross-product
        # (bounded: recover_state_nextdouble caps at 4 per sample, the
        # solver caps at 8 solutions per pair — FM-21c).
        # FM-21d: the solve is numpy-only (no pure fallback) — absence is
        # recorded LOUDLY as UNTESTABLE, never a silent negative.
        if not jrand.numpy_available():
            self.bus.emit(
                "WeakRandRelationUnavailable", ep.url,
                note="the per-request seed-relation family needs numpy "
                     "(vectorized window scan, no pure fallback) and it is "
                     "not importable — family UNTESTABLE on this surface "
                     "(requirements.txt declares numpy)")
            return None
        for c1 in cand_sets[0]:
            for c2 in cand_sets[1]:
                sols = jrand.uniquifier_relation_solve(c1[0], c2[0],
                                                      c1[1], c2[1],
                                                      window=1 << 23)
                for u1, _t1, _t2 in sols:
                    # forward confirmation (48-bit domain): the third request's
                    # seed must xor-decode (two uniquifier advances from
                    # request 1) to a nanoTime low-48 inside ITS measured window.
                    u3 = ((u1 * jrand.UNIQ_MULT % jrand.MOD64)
                          * jrand.UNIQ_MULT % jrand.MOD64) & jrand.MASK48
                    for c3 in cand_sets[2]:
                        t3 = c3[0] ^ u3
                        d3 = (t3 - (c3[1] & jrand.MASK48)) & jrand.MASK48
                        if not (d3 > (1 << 23) and d3 < jrand.MASK48 - (1 << 23)):
                            return Finding(type="weak_random", severity=Severity.HIGH,
                                           endpoint_url=ep.url, parameter=cname,
                                           method=ep.method,
                                           evidence=[Evidence("lcg_seed_relation",
                                              f"cookie '{cname}' values come from per-request "
                                              f"new java.util.Random() instances: exact 48-bit states recovered "
                                              f"from the observed values, and the seedUniquifier multiplicative "
                                              f"relation (u2 = u1*1181783497276652981 mod 2^64) holds across all "
                                              f"three requests inside the measured CLOCK_MONOTONIC windows — "
                                              "seeds are time-derived LCG seeds, not CSPRNG output", None,
                                              " ".join(v[:20] for v, _ in samples))],
                                           status=FindingStatus.CANDIDATE)
        return None

    # ------------------------------------------------------------------ run
    def run(self, endpoints: list[Endpoint], findings: list):
        out = []
        budget = 700                      # bounded: cookie-setting endpoints only
        for ep in endpoints:
            if (ep.method or "GET").upper() not in ("GET", "POST"):
                continue
            if command_shaped_endpoint(ep):
                continue          # MAX-10a: never open logout/destructive surfaces
            # GTP-12b: the disclosure oracle rides the SAME base fetch the
            # cookie families use — one request, two oracles.
            r = self._base_fetch(ep)
            if r is None or r.error or not r.status:
                continue
            df = self._family_disclosure(ep, r.body or "", r.request_id)
            if df is not None:
                out.append(df)
                continue
            if budget <= 0:
                continue          # disclosure stays free; the multi-request
                                 # cookie families stop at the budget
            cs = self._set_cookies(r)
            if not cs:
                continue
            budget -= 1
            cname, val = cs[0]
            v = val.strip()
            f = None
            if v.isdigit() and 3 <= len(v) <= 17:
                # decimal-fraction shapes: the shared-instance chain family
                # (Math.random) first; fresh per-request doubles fall through
                # to the relation family with 53-bit state recovery
                f = self._family_chain(ep, cname)
                if f is None:
                    f = self._family_relation(ep, cname, "double")
            elif re.fullmatch(r"-?\d{1,19}", v):
                f = self._family_relation(ep, cname, "long")
            elif re.fullmatch(r"[A-Za-z0-9+/]{12,20}={0,3}", v):
                f = self._family_relation(ep, cname, "bytes")
            if f is not None:
                out.append(f)
        return out

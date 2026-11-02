"""Scan Orchestrator — ties Discovery -> Planner -> Detection -> Verification -> Finding Pipeline.
Plus: burhan doctor (Phase 45) and benchmark runner hooks (Phase 16/29).
"""
from __future__ import annotations
import json, os, time
import urllib.parse
from .core import (Endpoint, EventBus, Evidence, Finding, FindingStatus, ScopeRule, ParamKind,
                   Severity, Target, DiscoverySource, new_run_id, SCANNER_VERSION, Verification,
                   ParamLocation)
from .http_engine import RequestEngine, RequestMutation, Response
from .discovery import DiscoveryEngine
from .discovery import DESTRUCTIVE_GET_RE   # V411-DISC-SAFE vocabulary gate
from .discovery import (STATE_CHANGE_GET_RE, LOGOUT_PATH_RE,
                        gate_scope, endpoint_gate_scope)
from .detect import (ACTIVE_DETECTORS, SQLiDetector, XSSDetector, TraversalDetector,
                     RedirectDetector, CrlfDetector, XxeDetector, passive_audit, plan_for,
                     StoredXSSDetector, PathTraversalDetector,
                     RUN_STYLE_DETECTORS, command_shaped_endpoint, _pseudo_param)
from .intel import VerificationEngine, FindingPipeline, StrategyStore, FailureMemory, RepairClassifier
from .auth import AuthProfile, AuthEngine, AuthedEngineProxy, TokenAuthEngine, TokenWatchdogProxy
from .fingerprint import FingerprintCollector
from .coverage import CoverageTracker, _CoverageProxy
from .paramintel import ParamIntel
from .secrets import SecretsScanner
from .evidence import assess as assess_impact
from .compliance import compliance_for
from .evidence import build_proof as build_finding_proof
from .appmap import build_appmap
from .authz import AuthzConfig, AuthzEngine, _rank as _az_rank
from .boundary import BoundaryEngine
from .planner import SafeAttackPlanner



def select_primary_identity(authz_sessions: dict, auth_profile=None) -> dict | None:
    """V411: the primary identity for the GraphQL/WS engine wiring, derived
    DIRECTLY from the authz engine's logged-in sessions (token-mode or form).
    v4.1.0 defect (found during the DVGA gap validation): the orchestrator
    read authz_result["accounts"], a key injected only LATER at twin building
    — after the GraphQL/WS engines had already run — so primary_identity was
    always None inside the engine wiring and the cross-identity probes
    silently degraded to UNTESTABLE. Never exposed before: no v4.1.0 live
    target offered GraphQL."""
    if not authz_sessions:
        return None
    from .authz import _rank as _az_rank
    ordered = sorted(
        authz_sessions.values(),
        key=lambda s: (_az_rank(s["account"].role), s["account"].name))
    username = getattr(auth_profile, "username", "") if auth_profile else ""
    acct = next(
        (s["account"] for s in ordered if username and s["account"].username == username),
        ordered[0]["account"] if ordered else None)
    if acct is None:
        return None
    return {"name": acct.name, "role": acct.role, "username": acct.username,
            "object_id": acct.object_id, "marker": acct.marker}


class ScanConfig:
    def __init__(self, allow_private=False, max_pages=25, crawl=True, active=True,
                 passive=True, timeout=12.0, seed=None, strategy_path=None,
                 allowed_domains=None, oast=None, browser=True, auth=None,
                 openapi=True, openapi_spec=None, authz=None, secrets=True,
                 vault=None, vault_key_file=None, workflow=False, logic_active=False,
                 graphql=True, websocket=True, modern=True, modern_v2=False,
                 exclude_urls=None,
                 max_requests: int = 500,
                 race: bool = False, race_parallel: int = 10,
                 race_candidates: list | None = None,
                 race_variance: float = 0.005, symbolic=False):
        self.allow_private = allow_private
        self.max_pages = max_pages
        # RT-07 fix (audit-rb-1 AUD-GOV-01): hard request budget. The engine had
        # NO built-in limit — the live testasp campaign breached 1,261 requests
        # before the external watchdog killed it. Default 500; 0/negative = off
        # (explicit operator opt-out, never silent).
        self.max_requests = max_requests
        self.crawl, self.active, self.passive = crawl, active, passive
        self.timeout, self.seed = timeout, seed
        self.strategy_path = strategy_path
        self.allowed_domains = allowed_domains or []
        self.oast = oast          # OastServer | None — enables OOB (blind-XXE) confirmation
        self.browser = browser    # Phase 50: DOM engine (graceful skip when unavailable)
        self.auth = auth          # Phase 51: AuthProfile | None — authenticated scanning
        self.openapi = openapi    # DISC-13: auto-probe well-known OpenAPI/Swagger docs
        self.openapi_spec = openapi_spec   # explicit spec dict/url seed (None = auto only)
        self.authz = authz        # Phase 56: multi-user authorization config (dict | None)
        self.secrets = secrets    # Phase 56: credential-exposure scan of passive baselines
        self.vault = vault                     # Phase 57: vault file path | None
        self.vault_key_file = vault_key_file   # Phase 57: authorized key file path
        self.workflow = workflow or logic_active   # Phase 58: workflow learning (--workflow)
        self.logic_active = logic_active       # Phase 58: attack battery (--logic-active)
        self.graphql = graphql       # v4.1.0: GraphQL intelligence engine
        self.websocket = websocket   # v4.1.0: WebSocket intelligence engine
        self.modern = modern         # v4.4.0 (axis 13): modern vulnerability battery
        # (JWT algorithm confusion + none-acceptance, GraphQL batching,
        # request-smuggling timing, mass assignment, prototype pollution)
        self.modern_v2 = modern_v2   # owner order part 3 (2026-10-31): NEW
        # detection layers, OFF by default — jwt weak-secret (bounded offline
        # wordlist, RFC 8725), graphql aliasing cost-DoS, excessive data
        # exposure, rebind TOCTOU. Zero overlap with the v1 family set.
        self.exclude_urls = list(exclude_urls or [])
        # V411-EXC: operator-declared URL exclusions (substring match) — the
        # surface is neither page-fetched, kept in the endpoint map, nor
        # actively probed. For authorized scans of stateful targets whose
        # GET routes change server configuration (mode toggles) or data —
        # the operator pins the target's state instead of letting a crawler
        # flip it mid-scan (live-caught on DVGA: /difficulty/<level> switches
        # the whole application between easy and hardened GraphQL behavior).
        # ---- ORD-002-WIRE (axis-17): the race-condition battery wiring.
        # OFF by default — without --race the burhan/race/ package is never
        # imported, never registered, never invoked (constraint 4; pinned by
        # test_wire_disabled_by_default in a fresh subprocess).
        self.race = bool(race)                      # --race (explicit operator opt-in)
        self.race_parallel = int(race_parallel)     # --race-parallel N (concurrency cap)
        self.race_variance = float(race_variance)   # --race-variance F (decision threshold)
        # 3F (order 2026-11-01): the operator's EXPLICIT race-prober opt-in —
        # a list of candidate endpoints; the prober never selects targets on
        # its own (the never-blind constraint, documented in the family)
        self.race_candidates = list(race_candidates or [])
        # ---- AXIS-18 (ORD-003): symbolic execution analysis. OFF by default —
        # without --symbolic the burhan/symbolic/ package is never imported,
        # never invoked, sends nothing, and no section appears (the historical
        # bomb-test file tests/test_axis18_symbolic.py is not part of the
        # current tree; the signing path is covered by
        # tests/test_symbolic_rfc8032.py).
        self.symbolic = bool(symbolic)              # --symbolic (operator opt-in)


class _FingerprintingProxy:
    """Phase 54 transparent proxy: every response the scan receives passes
    through FingerprintCollector.observe() — WAF signatures, tech headers,
    cookie platforms, DOM markers accumulate from traffic the scan already
    produces. No extra requests, no behavior change (pure observer)."""
    def __init__(self, inner, collector: FingerprintCollector):
        self._inner, self._fp = inner, collector

    def send(self, m):
        r = self._inner.send(m)
        self._fp.observe(r)
        return r

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _BudgetProxy:
    """RT-07 fix (audit-rb-1 AUD-GOV-01): hard request budget as a transparent
    engine proxy — the same architectural pattern as _FingerprintingProxy /
    _CoverageProxy. Wrapped at construction time, OUTERMOST of every later
    proxy, so EVERY request the scan issues (auth, crawl, browser, active
    detectors, verification replays, authz identities, graphql, websocket)
    counts against the same limit. On reaching the limit it emits ONE
    BUDGET_REACHED event and short-circuits every further send() with a
    synthetic error response (the scope-block pattern: status=0 + error) —
    loops finish cleanly, no mid-flight exceptions, the report is honest
    about what was cut short."""
    def __init__(self, inner, bus: EventBus, max_requests: int):
        self._inner, self._bus, self._max = inner, bus, int(max_requests)
        self._announced = False
        self.stopped_at = None

    def send(self, m):
        sent = getattr(self._inner, "requests_sent", 0)
        if sent >= self._max:
            if not self._announced:
                self._announced = True
                self.stopped_at = sent
                self._bus.emit("BudgetReached",
                               msg=f"BUDGET_REACHED: stopped at {sent} requests "
                                   f"(limit={self._max})",
                               requests=sent, limit=self._max)
            url = getattr(getattr(m, "endpoint", None), "url", "")
            return Response(status=0, url=url,
                            error=f"budget:BUDGET_REACHED: stopped at {sent} "
                                  f"requests (limit={self._max})")
        return self._inner.send(m)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _RaceJournalProxy(dict):
    """ORD-002-WIRE: مساحة أسماء لطلبات السباق داخل سجل المحرك المشترك.
    كل فحص سباق يرقّم طلباته من race-0000 — الكتابة المباشرة بال rid نفسه
    كانت ستتصادم بين الفحوص المتعاقبة وتُسقط أدلة سابقة من السجل
    (عيب حقيقي اكتشفه الجناح قبل الالتزام). الوكيل يسبق المفاتيح
    بـ"race:" داخل سجل المحرك، يحتفظ بعدّه المحلي للسطر الصادق في
    سلسلة أدلة الحزمة، ويلتزم سقف سجل المحرك نفسه (JOURNAL_MAX —
    الانضباط المحكم للسجل المحدود). تنسيق القيم نفسه حرفياً من
    الحزمة: رؤوس RT-05 مقنعة وجسم بند-3 مقنع."""

    _MAX = 6000          # نفس سقف سجل المحرك (http_engine.JOURNAL_MAX)

    def __init__(self, inner):
        super().__init__()
        self._inner = inner
        self._dropped = 0

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if self._inner is None:
            return
        inner_n = len(self._inner) - sum(1 for k in self._inner
                                          if str(k).startswith("race:"))
        if inner_n >= self._MAX:
            self._dropped += 1
            return
        self._inner[f"race:{key}"] = value


class BurhanScanner:
    def __init__(self, target_url: str, cfg: ScanConfig | None = None):
        self.cfg = cfg or ScanConfig()
        self.run_id, self.seed = new_run_id(self.cfg.seed)
        self.bus = EventBus(self.run_id)
        self.target = Target(target_url)
        self.scope = ScopeRule(allowed_domains=[self.target.host] + self.cfg.allowed_domains,
                               allow_private=self.cfg.allow_private)
        self.engine = RequestEngine(self.scope, self.bus, timeout=self.cfg.timeout)
        # RT-07: budget wrap BEFORE anything else holds a reference — every
        # request of every phase flows through it (auth included).
        if self.cfg.max_requests and self.cfg.max_requests > 0:
            self.engine = _BudgetProxy(self.engine, self.bus, self.cfg.max_requests)
        self.verifier = VerificationEngine(self.engine, self.bus, oast=self.cfg.oast)
        self.browser = None       # Phase 50: BrowserEngine (set in run() when enabled+available)
        self.fp = FingerprintCollector()   # Phase 54: passive WAF + tech map
        self.pipeline = FindingPipeline(self.bus)
        self.strategies = StrategyStore(self.cfg.strategy_path)
        self.failures = FailureMemory()
        self.classifier = RepairClassifier()
        self.findings: list[Finding] = []
        self.vault = None         # Phase 57: opened Credential Vault (armed capture)
        self.stats = {"requests": 0, "endpoints": 0, "candidates": 0, "verified": 0, "rejected": 0,
                      "duration": 0.0}
        self._race_section = None    # AXIS-17 WIRE: set ONLY when cfg.race ran
        self._symbolic_sources: list[dict] = []  # AXIS-18: passive-baseline response
        #                                          sources, collected ONLY when
        #                                          cfg.symbolic (zero extra requests)
        self._symbolic_section = None  # AXIS-18: set ONLY when cfg.symbolic ran

    # ------------------------------------------------- AXIS-17 WIRE (ORD-002-WIRE)
    # Pure WIRING of the closed burhan/race/ package (STATE.md round-23)
    # through its four registration points — bus / journal / planner_gate /
    # signer. Zero package logic here, zero package edits (constraint 1);
    # everything is INJECTED, never imported by the package (its test 10).
    _RACE_SENSITIVE_WORDS = ("transfer", "convert", "pay", "payment", "checkout",
                             "delete", "remove", "modify", "edit", "update",
                             "withdraw", "withdrawal", "move", "relocate")

    def _race_sensitive(self, endpoints) -> list:
        """النقاط الحساسة بعد الاكتشاف (الأمر: تحويل/دفع/حذف/تعديل/سحب/
        نقل) — تحديد حتمي بمفردات حدود-كلمات على المسار والاستعلام.
        استبعادات المشغل (V411-EXC) محترمة؛ النقطة بلا معامل قابل للفحص
        تدخل بحد empty_parameter الصادق (لا إرسال — قرار الحزمة نفسها)."""
        out, seen = [], set()
        for ep in endpoints:
            if any(x and x in ep.url for x in (self.cfg.exclude_urls or [])):
                continue
            u = urllib.parse.urlsplit(ep.url)
            hay = (u.path or "").replace("/", " ").replace("-", " ").replace("_", " ").replace(".", " ")
            q = urllib.parse.unquote_plus(u.query or "")
            for sep in ("&", "=", "+", "%", "|", ";"):
                q = q.replace(sep, " ")
            hay += " " + q.replace("/", " ").replace("-", " ").replace("_", " ")
            if not set(hay.lower().split()) & set(self._RACE_SENSITIVE_WORDS):
                continue
            key = ((ep.method or "GET").upper(), u.path or "/",
                   tuple(sorted(p.name for p in ep.parameters)))
            if key in seen:
                continue
            seen.add(key)
            param = next((p.name for p in ep.parameters
                          if p.kind != ParamKind.TOKEN and not p.flow_control
                          and not p.is_file), "")
            out.append((ep, param))
        return sorted(out, key=lambda t: ((t[0].method or "GET").upper(), t[0].url, t[1]))

    def _run_race_battery(self, endpoints) -> dict:
        """تشغيل بطارية السباق — ربط صرف عبر نقاط التسجيل الأربع."""
        import hashlib as _hashlib
        from . import race as race_pkg                 # lazy (constraint 4)
        from . import proof
        from .audit import derive_keypair
        from .planner import classify_operation

        # (نقطة 3) بوابة المخطط — سطح المحرك الحقيقي نفسه؛ التدميري
        # يُرفض دائماً، وعلم --race هو الإذن الصريح للمعدِّلات (عقيدة
        # المخطط: لا يحجب ما فعّله المشغّل صراحة). كل قرار يُسجَّل في
        # سجل قرارات المخطط نفسه — مسار التدقيق "ماذا فعل هذا المسح
        # بتطبيقي؟" يبقى كاملاً.
        def planner_gate(plan):
            verdict = classify_operation(plan.get("url", ""),
                                         plan.get("method", "POST"))
            impact = verdict["impact"]
            allowed = impact != "DESTRUCTIVE"
            try:
                self.attack_planner.decisions.append({
                    "url": str(plan.get("url", "")).split("?")[0],
                    "method": str(plan.get("method", "POST")).upper(),
                    "impact": impact, "allowed": allowed,
                    "policy": "operator-enabled (--race); destructive blocked",
                    "rationale": verdict["rationale"]})
                if not allowed:
                    self.attack_planner.blocked += 1
            except Exception:
                pass
            return allowed, f"planner:{impact}"

        # (نقطة 4) التوقيع — آلية المحور-14 حرفياً: جذر ميركل فوق سلسلة
        # الأدلة (وصفة §8.2 من proof) + هضم مركب بفواصل 0x00 + ed25519
        # من primitives المحور-8؛ الزوج يُشتق من بذرة التشغيلة عبر
        # audit.derive_keypair (HKDF-SHA256 على كامل المادة، أرضية RT-03).
        priv, pub = derive_keypair(self.seed)

        def signer(payload: bytes) -> dict:
            doc = json.loads(payload.decode("utf-8"))
            chain = doc.get("evidence_chain", [])
            if chain:
                leaves = [json.dumps({"step": s}, sort_keys=True,
                                     separators=(",", ":"), ensure_ascii=False)
                          for s in chain]
                root_hex = proof.merkle_root(
                    [l.encode("utf-8") for l in leaves]).hex()
            else:
                root_hex = _hashlib.sha256(b"").hexdigest()
            digest = _hashlib.sha256("\x00".join([
                str(doc.get("endpoint", "")), str(doc.get("parameter", "")),
                str(int(doc.get("request_count", 0))), root_hex,
                _hashlib.sha256(payload).hexdigest()]).encode("utf-8")).hexdigest()
            sig = proof.ed25519_sign(priv, bytes.fromhex(digest))
            return {"signature": sig.hex(), "public_key": pub.hex(),
                    "merkle_root": root_hex, "algorithm": "ed25519"}

        # (النقطتان 1+2) التسجيل: bus + journal — الحقن لكل فحص عبر
        # وكيل مساحة الأسماء (يمنع تصادم rids بين الفحوص ويحفظ سقف
        # السجل)؛ الطلبات تدخل سجل المحرك المشترك بنفس تنسيقه
        # وتقنّع RT-05/item-3 داخل الحزمة نفسها — ثم البوابة والتوقيع.
        ctx = race_pkg.register(
            bus=self.bus, journal=None,   # the proxy below is the injection point
            planner_gate=planner_gate, signer=signer)

        section = {"title": "Race Condition Analysis", "enabled": True,
                   "trigger": "--race",
                   "parallel_cap": self.cfg.race_parallel,
                   "variance_threshold": self.cfg.race_variance,
                   "sensitive_words": sorted(self._RACE_SENSITIVE_WORDS),
                   "probed": [], "finding_gates": [],
                   "findings": 0, "requests": 0}
        total_requests, n_findings = 0, 0
        for ep, param in self._race_sensitive(endpoints):
            # هندسة الطلب (نفس منطق _render في المحرك): معاملات الاستعلام
            # تُعاد إلى عنوان الفحص — بوابة المخطط تفحص المسار والاستعلام
            # معاً (OWSP-21) فلا يجوز أن تضيع الاستعلامات هنا (عيب حقيقي
            # اكتشفه الجناح حيّاً: نقطة GET ?mode=reseed كانت تُفحص بلا
            # استعلامها فلا ترى البوابة الكلمة التدميرية).
            qparams = [(p.name, p.value or "") for p in ep.parameters
                       if getattr(p, "location", None) == ParamLocation.QUERY]
            probe_url = ep.url
            if qparams and "?" not in probe_url:
                probe_url = ep.url + "?" + urllib.parse.urlencode(qparams)
            body, headers = "", {}
            if (ep.method or "GET").upper() in ("POST", "PUT", "PATCH"):
                fields = [(p.name, p.value or "burhan-probe")
                          for p in ep.parameters
                          if p.kind != ParamKind.TOKEN and not p.flow_control
                          and not p.is_file
                          and getattr(p, "location", None) in
                          (ParamLocation.BODY, ParamLocation.JSON)]
                if not fields:
                    fields = [(p.name, p.value or "burhan-probe")
                              for p in ep.parameters
                              if p.kind != ParamKind.TOKEN and not p.flow_control
                              and not p.is_file]
                if fields:
                    body = urllib.parse.urlencode(fields)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
            res = race_pkg.wire_plan(
                ctx, probe_url, parameter=param, samples=10, body=body,
                headers=headers, method=(ep.method or "GET").upper(),
                journal=_RaceJournalProxy(
                    getattr(self.bus, "request_journal", None)),
                max_concurrent=self.cfg.race_parallel,
                timeout=self.cfg.timeout, threshold=self.cfg.race_variance,
                mutating=True, run_id=self.run_id)
            # القيد في القسم يبقى res.to_dict() نقية — الوحدة الموقعة
            # القابلة للتحقق الخارجي بتوقيع المحور-14 (أي مفتاح إضافي بعد
            # التوقيع يبطل التحقق — عيب اكتشفه الجناح حيّاً). قرارات الربط
            # تُسجّل في مفتاح قسم منفصل خارج الحمولة الموقعة.
            entry = res.to_dict()
            gate_note = {"endpoint": res.endpoint, "created": False,
                         "reason": ""}
            # بوابة النتيجة على مستوى الربط (قرار ربط معلن، لا منطق حزمة):
            # فحص فشلت طلباته كلها (404/5xx/أعطال) لا يولّد نتيجة — توقيتات
            # الفشل ليست دليل سباق؛ القيد يظهر في القسم بصراحة.
            if res.race_detected and int(res.stats.get("ok", 0)) > 0:
                gate_note["created"] = True
                f = Finding(
                    type="race_condition", severity=Severity.HIGH,
                    endpoint_url=res.endpoint, parameter=res.parameter,
                    method=res.method, confidence=0.9,
                    status=FindingStatus.VERIFIED, run_id=self.run_id,
                    verification=Verification(
                        method="race:concurrent-timing-variance", passed=True,
                        confidence=0.9, rounds=res.request_count,
                        notes=(f"unbiased sample variance {res.timing_variance:.8f}s "
                               f"< threshold {self.cfg.race_variance}s over "
                               f"{res.request_count} concurrent requests")),
                    evidence=[
                        Evidence(kind="race_timing_variance",
                                 detail=(f"variance={res.timing_variance:.8f}s over "
                                         f"{res.request_count} concurrent {res.method} "
                                         f"requests (threshold={self.cfg.race_variance}s)")),
                        Evidence(kind="race_evidence_chain",
                                 detail=" -> ".join(str(s) for s in
                                                    res.evidence_chain)[:280]),
                        Evidence(kind="race_signature",
                                 detail=("axis-14 merkle+ed25519; root="
                                         + (res.merkle_root or "")[:24] + ".. pub="
                                         + (res.public_key or "")[:24]
                                         + ".. (full signed result: report.race_analysis)"))])
                self.findings.append(f)
                self.stats["candidates"] += 1
                self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                              param=f.parameter)
                n_findings += 1
            elif res.race_detected:
                gate_note["reason"] = ("race_detected on an all-failed probe "
                                       "(0 successful responses) — no finding: "
                                       "failure timings are not race evidence")
            section["probed"].append(entry)
            section["finding_gates"].append(gate_note)
            total_requests += int(res.request_count)
        section["findings"] = n_findings
        section["requests"] = total_requests
        return section

    # ---------------------------------------------------------------- run
    def _path_traversal_bases(self, endpoints) -> list[str]:
        """DETECT-17 (v4.2.3): probe bases for the URL-path traversal battery.
        Deterministic, bounded: the target root first, then up to two most-populous
        crawled directory prefixes (the gruyere instance dir /<inst>/ is where the
        live traversal worked — root-only probing would have missed it)."""
        import collections as _collections
        root = urllib.parse.urlsplit(self.target.url)
        base_root = f"{root.scheme}://{root.netloc}/"
        dirs = _collections.Counter()
        for ep in endpoints:
            p = urllib.parse.urlsplit(ep.url)
            if (p.scheme, p.netloc) != (root.scheme, root.netloc):
                continue
            path = p.path or "/"
            if path.rstrip("/") and path.count("/") > 1:
                d = path.rstrip("/").rsplit("/", 1)[0] + "/"
                dirs[f"{p.scheme}://{p.netloc}{d}"] += 1
        bases = [base_root] + [b for b, _ in sorted(dirs.items(), key=lambda kv: (-kv[1], kv[0]))[:2]]
        seen, uniq = set(), []
        for b in bases:
            if b not in seen:
                seen.add(b)
                uniq.append(b)
        return uniq

    def run(self) -> dict:
        t0 = time.time()
        self.bus.emit("ScanStarted", target=self.target.url, run=self.run_id,
                      scanner=SCANNER_VERSION, seed=self.seed)

        # ---- Phase 57 (v2.9.0): Credential Vault — opened BEFORE any request
        # so a wrong/unauthorized key fails fast as a configuration error,
        # never mid-scan. Every credential the exposure engine proves is then
        # captured encrypted-at-rest; public artifacts keep masks only.
        if self.cfg.secrets and self.cfg.vault and self.cfg.vault_key_file:
            from .vault import Vault
            self.vault = Vault.open(self.cfg.vault, self.cfg.vault_key_file)
            self.bus.emit("VaultUnlocked", org=self.vault.org,
                          actor=self.vault.key_id)

        # ---- Phase 51: authenticate BEFORE discovery — the session cookie (ENG-05
        # jar) then rides every later request, and the authenticated landing page
        # becomes a second crawl seed (the post-login surface is linked ONLY from
        # post-login pages: /bank/* on Altoro is invisible from the anonymous home).
        # AUTH-05 (Phase 54): token mode — Bearer/JWT/custom-header auth. Validation
        # instead of credential exchange; the header rides engine.default_headers;
        # no self-healing (static tokens cannot be re-minted) — 401/403 mid-scan are
        # counted honestly by the TokenWatchdogProxy instead of silently degrading.
        auth_seeds: list[str] = []
        self.auth_engine = None
        self.token_engine = None
        auth_headers: dict = {}
        if self.cfg.auth is not None:
            if self.cfg.auth.mode == "token":
                self.token_engine = TokenAuthEngine(self.cfg.auth, self.engine, self.bus)
                ok = self.token_engine.login()
                self.stats["authenticated"] = ok
                if ok:
                    self.engine = TokenWatchdogProxy(self.engine, self.token_engine)
                    self.verifier.engine = self.engine
                    auth_headers = {self.cfg.auth.auth_header: self.cfg.auth.header_value()}
                    auth_seeds.append(self.cfg.auth.login_url)
                else:
                    self.bus.emit("ScanContinuesUnauthenticated",
                                  reason=self.token_engine.state.last_error)
            else:
                self.auth_engine = AuthEngine(self.cfg.auth, self.engine, self.bus)
                ok = self.auth_engine.login()
                self.stats["authenticated"] = ok
                if ok:
                    # AUTH-03 watchdog proxy: from here on, session loss anywhere in
                    # the scan (discovery, detectors, verifier, browser) self-heals.
                    self.engine = AuthedEngineProxy(self.engine, self.auth_engine)
                    self.verifier.engine = self.engine
                    auth_seeds.append(self.auth_engine.state.landing_url)
                    # the authenticated crawl genuinely has more surface — grow budget
                    # deterministically (fixed 1.5x, no heuristics)
                    self.cfg.max_pages = int(self.cfg.max_pages * 1.5)
                else:
                    self.bus.emit("ScanContinuesUnauthenticated",
                                  reason=self.auth_engine.state.last_error)

        # ---- Phase 54: fingerprint everything the scan already fetches. The
        # collector rides a transparent proxy placed OUTERMOST (auth watchdog
        # proxies stay inner), so crawl baselines, detector probes and verify
        # replays ALL pass through observe() — zero extra requests, passive only.
        self.engine = _FingerprintingProxy(self.engine, self.fp)
        self.verifier.engine = self.engine
        # ---- Phase 56: Coverage Engine — every request the scan sends is
        # attributed to its endpoint (passive baseline / secrets scan / active
        # probe / verification replay). Navigation (crawl) and auth-flow
        # requests are intentionally NOT endpoint testing and are excluded.
        self.coverage = CoverageTracker()
        self.engine = _CoverageProxy(self.engine, self.coverage)
        self.verifier.engine = self.engine
        # ---- v4.1.0: Boundary Intelligence Engine (Phase V41-05) — the single
        # registry of what this scan could NOT test and why. Every engine's
        # honest skip lands here; coverage/reports/CI consume it.
        self.boundary = BoundaryEngine()
        # ---- v4.1.0: the REAL-TIME Safe Attack Planner (Phase V41-10). The
        # v4.0.0 ledger was a post-hoc reconstruction; this instance gates
        # attack-site operations (workflow battery, GraphQL mutations, WS
        # writes) BEFORE they are sent, and its decision log IS the run's
        # audit ledger.
        self.attack_planner = SafeAttackPlanner(logic_active=self.cfg.logic_active)
        # V411-WS-DISC-2: the JS-harvested WS intel registries (message shapes
        # + observed channel URLs) are per-scan state — reset them so a second
        # scan in the same process never inherits the previous target's JS.
        from .websocket import reset_ws_intel
        reset_ws_intel()

        # ---- Phase 4: discovery (extra_seeds carry the authenticated landing;
        # the login page itself is excluded from page-fetches — re-fetching it
        # clobbers the authenticated session cookie with a fresh anonymous one)
        d = DiscoveryEngine(self.engine, self.cfg.max_pages)
        endpoints: list[Endpoint] = [Endpoint(url=self.target.url, source=DiscoverySource.SEED)]
        # ---- AUTH-06: a successful json_login contributes the CREDENTIALED
        # login endpoint to the map. The JWT families harvest their token by
        # replaying exactly this surface (form-encoded replay would 415 on a
        # JSON API); auth-flow requests stay excluded from endpoint TESTING —
        # this is the harvest source, contributed only under the explicit
        # json_login flag so every existing gate is untouched.
        if self.cfg.auth is not None and getattr(self.cfg.auth, "json_login", False) \
                and self.auth_engine is not None \
                and getattr(self.auth_engine.state, "login_endpoint", None) is not None:
            _lep = self.auth_engine.state.login_endpoint
            _lep.source = DiscoverySource.AUTH
            if all(e.id != _lep.id for e in endpoints):
                endpoints.append(_lep)
            # the verifier's fresh harvest (VR-29/30) replays THIS endpoint —
            # a bare GET on a JSON login can never re-obtain the token
            self.engine.auth_harvest_endpoint = _lep
            # audit trail: the api_inventory lists the endpoint with source
            # "auth:login"; the bus event carries the same fact for consumers
            self.bus.emit("AuthSurfaceContributed", url=_lep.url,
                          note="credentialed json_login endpoint in the map as "
                               "the JWT harvest source")
        _excl = [u for u in (self.cfg.exclude_urls or []) if u]
        if self.cfg.crawl:
            found, js, crawl_stats = d.crawl(self.target.url, extra_seeds=auth_seeds,
                                             exclude_urls=([self.cfg.auth.login_url]
                                                           if self.cfg.auth else []) + _excl)
            endpoints.extend(e for e in found if e.id != endpoints[0].id)
            # V411-DISC-SAFE: destructive-GET page-fetch skips are auditable
            # boundaries, never silent (live-caught on DVGA: /start_over
            # re-seeded the whole DB on a passive crawl fetch)
            for skip_path in getattr(d, "crawl_skips", []):
                self.boundary.record(
                    "crawl/destructive-get", self.target.url.rstrip("/") + skip_path,
                    "BLOCKED_BY_SAFETY",
                    "path names a destructive/global-reset operation — a plain "
                    "GET is state-changing on this surface (state-changing-GET "
                    "anti-pattern), so the crawler did not page-fetch it; the "
                    "endpoint stays discovered and any probe rides the planner "
                    "gate (DESTRUCTIVE class = never sent)",
                    remediation="verify the route's behavior manually on a "
                                "staging copy if its coverage matters",
                    provenance="discovery:crawl-vocabulary-gate")
            robots = d.robots(self.target.url)
            endpoints.extend(e for e in robots if all(e.id != x.id for x in endpoints))
            self.stats["crawl"] = crawl_stats
            self.bus.emit("DiscoveryCompleted", **crawl_stats, js_endpoints=len(js))
        # ---- DISC-13 (Phase 54): the target's OWN OpenAPI/Swagger document is a
        # machine-readable surface map — unlinked admin/legacy/API paths that no
        # crawler can reach are declared there with parameters. Auto-probe the
        # well-known locations (and honor an explicit spec); merged endpoints ride
        # the SAME dedup + scope gates as crawl results.
        if self.cfg.openapi or self.cfg.openapi_spec:
            spec_eps, spec_info = [], None
            if self.cfg.openapi_spec:
                from .discovery import parse_openapi, _spec_info
                if isinstance(self.cfg.openapi_spec, dict):
                    spec_eps = parse_openapi(self.cfg.openapi_spec, self.target.url)
                    spec_info = _spec_info(self.cfg.openapi_spec, "(inline-seed)", len(spec_eps))
            else:
                try:
                    spec_eps, spec_info = d.openapi(self.target.url)
                except Exception:
                    spec_eps, spec_info = [], None
            if spec_eps:
                new_eps = [e for e in spec_eps if all(e.id != x.id for x in endpoints)]
                endpoints.extend(new_eps)
                self.stats["openapi"] = dict(spec_info or {})
                self.stats["openapi"]["new_endpoints"] = len(new_eps)
                self.bus.emit("OpenApiSeeded", **(spec_info or {}), new_endpoints=len(new_eps))
            elif self.cfg.openapi_spec is None:
                self.stats["openapi"] = {"source": None, "paths": 0, "new_endpoints": 0}
        # ---- V411-EXC: operator-declared exclusions leave the endpoint map
        # entirely — not page-fetched, not probed, not counted as discovered
        # surface; each exclusion is an auditable BLOCKED_BY_PERMISSION
        # boundary (the operator pinned target state; nothing is silent)
        if _excl:
            def _excluded(url: str) -> bool:
                return any(x and x in url for x in _excl)
            dropped_urls = sorted({e.url for e in endpoints if _excluded(e.url)})
            endpoints = [e for e in endpoints if not _excluded(e.url)]
            for u in dropped_urls:
                self.boundary.record(
                    "crawl/operator-exclusion", u, "BLOCKED_BY_PERMISSION",
                    "surface excluded by the operator (--exclude-url): stateful "
                    "GET routes that change target configuration or data are "
                    "neither fetched nor probed; the target's state is pinned "
                    "for this scan",
                    provenance="orchestrator:operator-exclusion")
            if dropped_urls:
                self.bus.emit("OperatorExclusionsApplied", count=len(dropped_urls))
        self.stats["endpoints"] = len(endpoints)

        # ---- Phase 50: browser/DOM engine — render-merge BEFORE planning so active
        # detectors cover runtime-discovered surfaces (JS-built forms, rendered links).
        dom_sinks = list(getattr(d, "dom_sinks", [])) if self.cfg.crawl else []
        if self.cfg.browser:
            from .browser import BrowserEngine, browser_available
            if browser_available():
                self.browser = BrowserEngine(self.engine, timeout=self.cfg.timeout,
                                             extra_headers=auth_headers)
                self.verifier.browser = self.browser
                existing = {e.id: e for e in endpoints}
                # Render budget: script-bearing pages first (runtime forms / DOM logic
                # only exist where scripts run — live-caught: a naive first-N endpoint
                # selection missed the JS-built form page entirely), then dom-sink
                # pages, then remaining GET pages up to the cap.
                seen_t = set()
                render_targets = []
                for u in (list(getattr(d, "script_pages", [])) +
                          [s.url for s in dom_sinks] +
                          [e.url for e in endpoints if (e.method or "GET") == "GET"]):
                    if u and u not in seen_t:
                        seen_t.add(u)
                        render_targets.append(u)
                # V411-DISC-SAFE (browser pass, live-caught on DVGA): the
                # destructive-GET vocabulary gate applies to BROWSER page
                # loads too — a headless render of /start_over is still a
                # state-changing GET that re-seeded the whole database
                # mid-scan (the crawler was already gated; the browser pass
                # repeated the mistake). Operator exclusions apply equally.
                from .discovery import DESTRUCTIVE_GET_RE as _DGR
                from .discovery import (STATE_CHANGE_GET_RE as _SGR,
                                        LOGOUT_PATH_RE as _LOGOUT_QRE,
                                        gate_scope as _gscope)
                # OWSP-21: path + query — query-routed command links
                # (index.php?do=toggle-security) must be gated too
                render_targets = [u for u in render_targets
                                  if not (_DGR.search(_gscope(u)) or _SGR.search(_gscope(u)))
                                  and not _LOGOUT_QRE.search(_gscope(u))
                                  and not any(x and x in u for x in _excl)][:15]
                new_eps = self.browser.render_merge(render_targets, self.target.host, existing)
                endpoints.extend(e for e in new_eps if e.id not in {x.id for x in endpoints})
                self.stats["endpoints"] = len(endpoints)
                self.stats["browser_pages"] = self.browser.pages_rendered
                self.bus.emit("BrowserRenderCompleted", pages=self.browser.pages_rendered,
                              new_endpoints=len(new_eps), dom_sink_candidates=len(dom_sinks))
            else:
                self.bus.emit("BrowserUnavailable",
                              note="playwright/chromium not installed — static fallback active")

        # ---- Phase 56: Smart Testing Engine (value-shape parameter intelligence)
        # + the Coverage Engine's discovery ledger. enrich() only UPGRADES param
        # kinds when the observed value proves a more specific shape (JSON object);
        # every skip it causes is recorded as an auditable coverage reason.
        for ep in endpoints:
            self.coverage.discover(ep)
        self.param_profile = ParamIntel.enrich(endpoints)
        for ep in endpoints:
            for p in ep.parameters:
                reason = ParamIntel.skip_reason(p)
                if reason:
                    self.coverage.skipped(ep, reason)
        self.stats["param_intel"] = self.param_profile

        # ---- Phase 7: plan; Phase 8: detect
        detectors = {d.name: d(self.engine, self.bus, self.strategies) for d in ACTIVE_DETECTORS}
        self._det_probe_counts: dict[str, int] = {d: 0 for d in detectors}
        # Phase 53: OAST-channel detectors (SSRF / blind command injection) receive
        # the armed channel; without one they stay inert (response oracles for these
        # classes are noise — live-observed on the cycling stock endpoint).
        for _d in detectors.values():
            if getattr(_d, "needs_oast", False):
                _d.oast = self.cfg.oast
        vuln_to_detector = {"sql_injection": "sqli", "xss_reflected": "xss",
                            "path_traversal": "traversal", "open_redirect": "redirect", "ssrf": "ssrf",
                            "header_injection": "crlf", "xxe": "xxe",
                            "command_injection": "cmdi", "cors_misconfig": "cors",
                            "ssti": "ssti", "csrf": "csrf", "nosql_injection": "nosql",
                            "jwt_security": "jwt", "host_header_injection": "hostheader",
                            "xpath_injection": "xpath", "ldap_injection": "ldapi",
                            "secure_cookie": "securecookie", "trust_bound": "trustbound",
                            "weak_random": "weakrand", "weak_hash": "hashchain",
                            "weak_crypto": "cryptochain"}
        plan = []
        for ep in endpoints:
            # OWSP-21b: command-shaped endpoints (a param VALUE names a
            # command: do=logout / do=toggle-security — the canonical ep.url
            # is query-stripped, so the check MUST read the Parameters) get
            # NO battery plan: the BASE request of any battery executes the
            # command (live: 16 do=logout base requests through the
            # authenticated jar). Blocked loudly, never silently.
            if command_shaped_endpoint(ep):
                self.coverage.skipped(ep, "command_shaped_endpoint")
                self.boundary.record(
                    "active/command-endpoint", ep.url, "BLOCKED_BY_SAFETY",
                    "endpoint parameters carry a command-shaped value "
                    "(do=logout / do=toggle-... style) — the base request of "
                    "any battery against it executes the app command; no "
                    "active probe is sent",
                    remediation="verify the command surface manually if its "
                                "coverage matters",
                    provenance="orchestrator:owsp21b-command-gate")
                continue
            plan.extend(plan_for(ep))
        self.bus.emit("ScanPlanReady", planned=len(plan))

        # ---- DETECT-17 (v4.2.3): URL-path traversal battery — once per scan, from
        # the target root + the crawled directory prefixes (bounded, deterministic
        # order: root first, then the two most populous dirs). The param-bound
        # battery never touches the URL path; google-gruyere serves
        # /<inst>/..%2f..%2f..%2f..%2fetc%2fpasswd with real /etc/passwd content
        # (IV13 gap #8, 2026-10-03). Stops after the first VERIFIED hit — one
        # confirmed arbitrary-file read is the finding; more probes add nothing.
        if self.cfg.active and "trav_path" in detectors:
            for base in self._path_traversal_bases(endpoints):
                for cand in detectors["trav_path"].run_base(base):
                    cand.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=cand.type, url=cand.endpoint_url,
                                  param=cand.parameter)
                    out_f = self.verifier.verify(cand, None)
                    self.findings.append(out_f)
                    self._det_probe_counts["trav_path"] += 1
                    self.strategies.record("trav_path", "path_marker",
                                           out_f.status == FindingStatus.VERIFIED,
                                           context=self.target.host)
                if any(f.type == "path_traversal" and f.status == FindingStatus.VERIFIED
                       for f in self.findings):
                    break

        for ep in endpoints:
            if self.cfg.passive:
                # V411-DISC-SAFE (passive baseline, live-caught on DVGA): a
                # destructive/global-reset GET is state-changing EVEN AS A
                # PASSIVE BASELINE — /start_over re-seeded the whole database
                # from this very loop. No request is sent; the skip is
                # accounted, the boundary is recorded, nothing is silent.
                # OWSP-21: gate on path + QUERY — a query-routed command
                # (index.php?do=toggle-security) changes app config on a
                # plain GET; the passive baseline must not fire it either.
                # OWSP-21b: endpoint_gate_scope also reads the canonical
                # endpoint's Parameters (the query is stripped from ep.url).
                from .discovery import DESTRUCTIVE_GET_RE as _DGR2
                from .discovery import STATE_CHANGE_GET_RE as _SGR2
                if (_DGR2.search(endpoint_gate_scope(ep))
                        or _SGR2.search(endpoint_gate_scope(ep))):
                    self.coverage.skipped(ep, "destructive_get_vocabulary")
                    self.boundary.record(
                        "passive/destructive-get", ep.url, "BLOCKED_BY_SAFETY",
                        "path names a destructive/global-reset operation — even "
                        "a passive baseline GET is state-changing on this "
                        "surface (state-changing-GET anti-pattern); no request "
                        "was sent",
                        remediation="verify the route's behavior manually on a "
                                    "staging copy if its coverage matters",
                        provenance="orchestrator:passive-vocabulary-gate")
                    continue
                # MAX-10a (live-caught on WebGoat 8.2.2): a logout endpoint
                # destroys the scan's OWN session — never fetched, even as a
                # passive baseline. The endpoint stays discovered and accounted.
                from .discovery import LOGOUT_PATH_RE as _LOGOUT_RE
                if _LOGOUT_RE.search(endpoint_gate_scope(ep)):
                    self.coverage.skipped(ep, "logout_self_preservation")
                    self.boundary.record(
                        "passive/logout", ep.url, "BLOCKED_BY_SAFETY",
                        "logout path — fetching it (even as a passive baseline) "
                        "destroys the scan's own authenticated session; the "
                        "endpoint stays discovered, never requested",
                        remediation="verify logout behavior manually if its "
                                    "coverage matters",
                        provenance="orchestrator:passive-logout-gate")
                    continue
                r = self.engine.send(RequestMutation(endpoint=ep, note="passive-baseline"))
                if r.error:
                    self.coverage.skipped(ep, "transport_error")
                else:
                    # AXIS-18 (ORD-003): with --symbolic, stash the baseline
                    # response as a constraint-extraction source (body bounded;
                    # zero extra requests — the analysis reads what the scan
                    # already fetched).
                    if getattr(self.cfg, "symbolic", False):
                        self._symbolic_sources.append(
                            {"url": ep.url, "method": ep.method or "GET",
                             "text": (r.body or "")[:2000], "status": r.status,
                             "note": "passive-baseline"})
                    # Phase 56 honesty gate: an ANONYMOUS scan that cannot open an
                    # endpoint (401/403, or bounced to a login gate) is an
                    # explicitly-accounted untested surface. With credentials
                    # configured the endpoint WAS tested — a 401 there is the
                    # application's answer (e.g. a login form rejecting wrong
                    # creds), not missing coverage.
                    hop = r.hop_location()
                    if self.cfg.auth is None and (r.status in (401, 403)
                                                  or (hop and "login" in hop.lower())):
                        self.coverage.skipped(ep, "requires_authentication")
                if not r.error:
                    for f in passive_audit(ep, r):
                        self.findings.append(self.verifier.verify(f, ep))
                    # ---- Phase 56: Credential Exposure Engine — secrets scan of
                    # the response the scan ALREADY fetched (zero extra requests;
                    # VR-19 re-fetches only for candidates).
                    if self.cfg.secrets:
                        self.coverage.activity(ep, "secrets", "secrets-passive-scan")
                        capture = (self.vault.capture_callback(self.run_id, ep.url)
                                   if self.vault is not None else None)
                        for sf in SecretsScanner().scan(ep, r, capture=capture):
                            sf.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=sf.type, url=ep.url,
                                          param=sf.parameter)
                            self.findings.append(self.verifier.verify(sf, ep))
            if not self.cfg.active:
                continue
            # OWSP-02 (OWASP campaign, live-caught on WrongSecrets 1.8.1): the
            # pre-OWSP-01 scan sent its whole battery into a route/CSRF gate
            # (uniform 405 on every probe) and recorded NOTHING — candidates=0
            # with no accounting, an entire POST surface silently absorbed.
            # Every battery response status is now collected per endpoint so a
            # uniform-reject surface is EXPLICITLY accounted (boundary +
            # coverage skip) instead of disappearing.
            _ep_probe_statuses = []
            for dname, det in detectors.items():
                try:
                    if dname == "sqli":
                        cands = det.candidates(ep)
                        if not cands: continue
                        # PER-PARAM ANALYSIS (live-caught on doLogin: old flat resp_map kept
                        # only the LAST param's responses, silently discarding earlier params)
                        # GTP-01/GTP-02: name-channel + synthetic-segment probes carry an
                        # explicit ncgroup:<id> note — their param NAMES differ by design
                        # (the payload IS the name), so a param_name groupby would split
                        # every TRUE/FALSE pair and silently kill the oracle. The note is
                        # the group key; the analysis pseudo-param is rebuilt per group.
                        from itertools import groupby
                        def _sqli_grp_key(t):
                            n = getattr(t[1], "note", "") or ""
                            return n[8:] if n.startswith("ncgroup:") else t[1].param_name
                        for gkey, grp in groupby(cands, key=_sqli_grp_key):
                            grp = list(grp)
                            resp_map = {}
                            for strat, m in grp:
                                r = self.engine.send(m)
                                self._det_probe_counts["sqli"] += 1
                                if not r.error:
                                    _ep_probe_statuses.append(r.status)
                                if r.error:
                                    fid = self.failures.record("sqli", r.error, {"url": ep.url})
                                    self.bus.emit("ScannerFailed", scanner="sqli", failure=fid, error=r.error)
                                    continue
                                resp_map[strat] = r
                            param_obj = next((p for p in ep.parameters if p.name == gkey), None)
                            if param_obj is None and grp:
                                # GTP-01/GTP-02 group: rebuild the analysis param.
                                #  ncgroup:name|<param>  -> the REAL param (the
                                #    anchor the verifier renames — its value is
                                #    the resolver's burhan VALUE).
                                #  ncgroup:<seg>|v / <seg>|n -> a synthetic param
                                #    whose face is the path segment.
                                _m0 = next((mm for tt, mm in grp if tt.endswith("_base")), grp[0][1])
                                if gkey.startswith("name|"):
                                    param_obj = next((p for p in ep.parameters
                                                      if p.name == gkey.split("|", 1)[1]), None)
                                elif "|" in gkey:
                                    param_obj = _pseudo_param(gkey.split("|")[0],
                                                              _m0.param_value or "1",
                                                              ParamKind.GENERIC)
                                else:
                                    param_obj = _pseudo_param(gkey, _m0.param_value or "1",
                                                              ParamKind.GENERIC)
                            if param_obj is None or not resp_map:
                                continue
                            cand = det.analyze((ep, param_obj), resp_map)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                # Phase 19/25: record VERIFIED outcomes only into strategy store
                                for st in ("quote_error", "boolean_and", "or_redirect", "or_differential", "quote_status"):
                                    self.strategies.record("sqli", st, out_f.status == FindingStatus.VERIFIED,
                                                           context=self.target.host)
                    elif dname == "xxe":
                        # DETECT-08 two-phase flow: candidates() returns recon probes (XML
                        # with form fields, root learned from JS); the recon response names
                        # missing elements ("Store ID could not be parsed"), expand() builds
                        # the entity differential probes, analyze() compares them.
                        cands = det.candidates(ep)
                        for strat, m in cands:
                            r0 = self.engine.send(m)
                            self._det_probe_counts["xxe"] += 1
                            if r0.error or r0.status == 0:
                                continue
                            root = strat.split("|")[1]
                            probes = det.expand(ep, r0, root)
                            if not probes:
                                continue
                            resp_map = {}
                            for s2, m2 in probes:
                                r = self.engine.send(m2)
                                if r.error:
                                    fid = self.failures.record("xxe", r.error, {"url": ep.url})
                                    self.bus.emit("ScannerFailed", scanner="xxe", failure=fid, error=r.error)
                                    continue
                                resp_map[s2] = r
                            if not resp_map:
                                continue
                            cand = det.analyze((ep, None), resp_map)
                            # Phase 49 — OOB fallback: response oracle impossible (noise /
                            # non-deterministic answers) but an OAST listener is armed ->
                            # the target itself becomes the evidence channel (blind XXE).
                            if cand is None and self.cfg.oast is not None:
                                self.bus.emit("OobAttemptStarted", scanner="xxe", url=ep.url)
                                cand = det.oob_attempt(ep, root, r0, self.cfg.oast)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                strat_name = ("oob_callback" if any(e.kind == "oob_callback" for e in cand.evidence)
                                              else "entity_differential")
                                self.strategies.record("xxe", strat_name,
                                                       out_f.status == FindingStatus.VERIFIED,
                                                       context=self.target.host)
                    elif dname == "xss_stored":
                        # DETECT-16 (v4.2.3): two-step stored-XSS flow on
                        # content-submission forms (comment/profile/signup/...):
                        # fresh form fetch -> canary submit -> render-surface
                        # re-fetch with persistence control. Returns a LIST (one
                        # finding per mutable param, capped at 2 per form).
                        for cand in det.run(ep):
                            if cand is None:
                                continue
                            cand.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=cand.type, url=ep.url,
                                          param=cand.parameter)
                            out_f = self.verifier.verify(cand, ep)
                            self.findings.append(out_f)
                            self._det_probe_counts["xss_stored"] += 1
                            self.strategies.record("xss_stored", "canary_persist",
                                                   out_f.status == FindingStatus.VERIFIED,
                                                   context=self.target.host)
                    elif dname == "traversal":
                        # GTP-03: the marker battery (content-read oracle) rides the
                        # generic flow below via candidates(); the EXISTENCE-oracle pair
                        # is a self-driven two-request flow per param, only when the
                        # marker battery found nothing on this endpoint (a confirmed
                        # content leak is the stronger finding — the exists pair adds
                        # nothing). PT-1 (recall push): the budget moved from the
                        # first-2-params to the detector's shared eligible_params()
                        # (2 full + 2 reduced) — the Benchmark's own spec puts the
                        # sink param third (['password','username','BenchmarkTestNNNNN'];
                        # 30/82 pathtraver FNs live-caught round-6); trailing params
                        # probe one depth (7) to keep the cost bounded.
                        # [PT-1 fix-up: 791e037 shipped proof artifacts without this
                        # code — reset --hard reverted it between proof and staging;
                        # re-applied verbatim.]
                        _trav_hit = any(f.type == "path_traversal"
                                       and f.endpoint_url == ep.url
                                       and f.status == FindingStatus.VERIFIED
                                       for f in self.findings)
                        if not _trav_hit:
                            try:
                                _full, _reduced = det.eligible_params(ep)
                            except AttributeError:
                                _full = [p for p in ep.parameters
                                         if p.kind != ParamKind.TOKEN
                                         and not p.flow_control and p.name][:2]
                                _reduced = []
                            for _p in _full + _reduced:
                                cand = det.exists_pair(
                                    ep, _p,
                                    depths=(7, 8) if _p in _full else (7,))
                                if cand:
                                    cand.run_id = self.run_id
                                    self.stats["candidates"] += 1
                                    self.bus.emit("CandidateCreated", type=cand.type, url=ep.url,
                                                  param=cand.parameter)
                                    out_f = self.verifier.verify(cand, ep)
                                    self.findings.append(out_f)
                                    self._det_probe_counts["traversal"] += 1
                                    self.strategies.record("traversal", "exists_oracle",
                                                           out_f.status == FindingStatus.VERIFIED,
                                                           context=self.target.host)
                                    break
                        for m in det.candidates(ep):
                            if isinstance(m, tuple):
                                m = m[1]
                            r = self.engine.send(m)
                            self._det_probe_counts[det.name] += 1
                            if not r.error:
                                _ep_probe_statuses.append(r.status)
                            if r.error:
                                fid = self.failures.record(det.name, r.error, {"url": ep.url})
                                self.bus.emit("ScannerFailed", scanner=det.name, failure=fid, error=r.error)
                                continue
                            pair = (ep, next((p for p in ep.parameters if p.name == m.param_name),
                                             ep.parameters[0] if ep.parameters else None)
                                    or _pseudo_param(m.param_name, m.param_value or "1", ParamKind.GENERIC))
                            cand = det.analyze(pair, r)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                self.strategies.record(dname, "primary", out_f.status == FindingStatus.VERIFIED,
                                                       context=self.target.host)
                    elif dname in RUN_STYLE_DETECTORS:
                        # CORS (DETECT-13) + Phase 55: endpoint-driven flows that
                        # drive their own request sequences per endpoint (header
                        # probes, baseline+replay pairs, JSON operator batteries) —
                        # none of them is param-bound, so they cannot ride the
                        # generic loop.
                        cand = det.run(ep)
                        if cand:
                            self._det_probe_counts[dname] += 1
                            cand.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                            out_f = self.verifier.verify(cand, ep)
                            self.findings.append(out_f)
                            self.strategies.record(dname, "primary",
                                                   out_f.status == FindingStatus.VERIFIED,
                                                   context=self.target.host)
                    else:
                        for m in det.candidates(ep):
                            if isinstance(m, tuple):
                                m = m[1]
                            r = self.engine.send(m)
                            self._det_probe_counts[det.name] += 1
                            if not r.error:
                                _ep_probe_statuses.append(r.status)
                            if r.error:
                                fid = self.failures.record(det.name, r.error, {"url": ep.url})
                                self.bus.emit("ScannerFailed", scanner=det.name, failure=fid, error=r.error)
                                continue
                            # XS-1 (xss recall round, live-caught on the OWASP
                            # Benchmark master = v1.2): a probe whose param name
                            # matches NO endpoint param is a name-channel probe
                            # (a renamed-clone/synthetic-name battery — the
                            # payload IS the name). The old ep.parameters[0]
                            # default attributed those probes to an unrelated
                            # param (live: the xss resolver candidates carried
                            # parameter=answer, so the detector never attached
                            # the input_channel evidence and the VR replayed
                            # the answer VALUE channel -> 0/6 -> the whole
                            # 33-test family REJECTED). The pseudo-param keeps
                            # the probe's OWN name: analyze() then sees the
                            # canary in p.name, attaches the name-channel
                            # evidence, and the VR replays the channel the app
                            # actually reads — the exact ncgroup discipline the
                            # sqli round enforced for nminj.
                            pair = (ep, next((p for p in ep.parameters if p.name == m.param_name), None)
                                    or _pseudo_param(m.param_name, m.param_value or "1", ParamKind.GENERIC))
                            cand = det.analyze(pair, r)
                            if cand:
                                cand.run_id = self.run_id
                                self.stats["candidates"] += 1
                                self.bus.emit("CandidateCreated", type=cand.type, url=ep.url, param=cand.parameter)
                                out_f = self.verifier.verify(cand, ep)
                                self.findings.append(out_f)
                                self.strategies.record(dname, "primary", out_f.status == FindingStatus.VERIFIED,
                                                       context=self.target.host)
                except Exception as e:
                    fid = self.failures.record(dname, f"{type(e).__name__}: {e}", {"url": ep.url})
                    self.bus.emit("ScannerFailed", scanner=dname, failure=fid, error=str(e)[:200])
            # OWSP-02 accounting: every battery probe on this endpoint was
            # uniformly rejected by a gate (route params filter / CSRF) — the
            # surface exists but was NOT testable as probed. Recorded loudly,
            # never silently absorbed. Partial rejections (mixed statuses) are
            # normal battery behavior and stay unrecorded.
            if _ep_probe_statuses and all(s in (403, 405) for s in _ep_probe_statuses):
                self.coverage.skipped(ep, "probes_uniformly_rejected")
                self.boundary.record(
                    "active/uniform-reject", ep.url, "UNTESTABLE",
                    f"all {len(_ep_probe_statuses)} battery probes answered HTTP "
                    f"{sorted(set(_ep_probe_statuses))} (route/CSRF gate) — the "
                    "endpoint exists but no probe reached application logic",
                    provenance="orchestrator:owsp02-uniform-reject-accounting",
                    remediation="inspect the form/route contract (submit-button "
                                "pairs, CSRF token lifecycle) and re-probe with "
                                "the corrected flow control")

        # ---- GTP-08: trust-boundary suppression filter ----------------------
        # The trust-bound oracle (input-controlled reflection) is the WEAKEST
        # claim the engine makes — every reflective class (xss, sqli errors,
        # open-redirect echoes) also reflects markers. Where a STRONGER class
        # already VERIFIED on the same endpoint, the reflection belongs to that
        # class: the trust_bound candidate is dropped (recorded, never silent).
        # This keeps the class honest on cross-category targets.
        if self.cfg.active:
            # GTP-08: only ACTIVE ATTACK classes suppress — passive hygiene
            # findings (missing headers, banners) sit on EVERY endpoint and
            # would strangle the whole trust_bound class.
            _PASSIVE_TYPES = {"missing_security_headers", "server_banner_disclosure",
                              "tech_banner", "vulnerable_js_dependency", "secure_cookie"}
            _verified_other = {}
            for f in self.findings:
                if (f.status == FindingStatus.VERIFIED and f.type != "trust_bound"
                        and f.type not in _PASSIVE_TYPES):
                    _verified_other.setdefault(f.endpoint_url, set()).add(f.type)
            _kept = []
            for f in self.findings:
                if (f.type == "trust_bound" and f.status == FindingStatus.VERIFIED
                        and _verified_other.get(f.endpoint_url)):
                    self.boundary.record(
                        "active/trustbound-suppressed", f.endpoint_url, "SUPERSEDED",
                        f"trust_bound reflection superseded by a stronger verified class "
                        f"({', '.join(sorted(_verified_other[f.endpoint_url]))}) on the same "
                        "endpoint — the reflection belongs to that class",
                        provenance="orchestrator:gtp08-suppression")
                    continue
                _kept.append(f)
            self.findings = _kept

        # ---- GTP-09/GTP-10: post-scan CHAIN PHASES ---------------------------
        # weakrand (GTP-09): the java.util.Random LCG cryptanalysis — state
        # recovery from observed cookie values, same-instance chain prediction
        # and the seedUniquifier relation attack across requests.
        # hash/crypto (GTP-10): artifact-hunt — value endpoints that WRITE the
        # digest/ciphertext to a server-side artifact are proven weak when a
        # verified file-read primitive on the same app exposes the artifact:
        # an exact MD5/SHA-1 match (hash) or a block-size/ciphertext-shape
        # analysis (crypto). Both phases are bounded and honest-silent without
        # their prerequisites.
        if self.cfg.active:
            try:
                from .weakrand import WeakRandomPhase
                for cand in WeakRandomPhase(self.engine, self.bus).run(endpoints, self.findings):
                    cand.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=cand.type, url=cand.endpoint_url,
                                  param=cand.parameter)
                    self.findings.append(self.verifier.verify(cand, None))
            except Exception as e:
                fid = self.failures.record("weakrand", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="weakrand", failure=fid, error=str(e)[:200])
            try:
                from .chainphase import HashCryptoChainPhase
                for cand in HashCryptoChainPhase(self.engine, self.bus).run(endpoints, self.findings):
                    cand.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=cand.type, url=cand.endpoint_url,
                                  param=cand.parameter)
                    self.findings.append(self.verifier.verify(cand, None))
            except Exception as e:
                fid = self.failures.record("hashchain", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="hashchain", failure=fid, error=str(e)[:200])

        # ---- Phase 50: DOM XSS execution probes (browser; static sink candidates).
        # search sources probe the extracted param names; hash sources take the
        # payload directly in the fragment; referrer/name sources are a documented
        # limit (cannot be set by plain navigation).
        if self.browser is not None and self.cfg.active and dom_sinks:
            try:
                import hashlib as _hb
                seen_probe = set()
                for sink in dom_sinks:
                    if sink.source == "search":
                        probe_params = [p for p in sink.params[:3] if p]
                    elif sink.source == "hash":
                        probe_params = [""]
                    else:
                        continue
                    for pname in probe_params:
                        pkey = f"{sink.url}|{pname}|{sink.source}"
                        if pkey in seen_probe:
                            continue
                        seen_probe.add(pkey)
                        canary = "z" + _hb.sha1(pkey.encode()).hexdigest()[:9]
                        # canonical page URL (crawl params stripped) — the finding and
                        # its re-probe must be reproducible from a clean URL
                        page_url = sink.url.split("?")[0].split("#")[0]
                        r = self.browser.probe_dom_xss(page_url, pname, canary, source=sink.source)
                        if r and r.get("fired"):
                            cand = Finding(type="xss_dom", severity=Severity.HIGH,
                                           endpoint_url=page_url, parameter=pname, method="GET",
                                           evidence=[Evidence("dom_execution",
                                                      f"source={sink.source} sink={sink.sink} — {r['detail']}; "
                                                      f"static flow: {sink.snippet}")],
                                           status=FindingStatus.CANDIDATE)
                            cand.run_id = self.run_id
                            self.stats["candidates"] += 1
                            self.bus.emit("CandidateCreated", type=cand.type, url=sink.url, param=pname)
                            out_f = self.verifier.verify(cand, None)
                            self.findings.append(out_f)
                            self.strategies.record("dom_xss", sink.sink,
                                                   out_f.status == FindingStatus.VERIFIED,
                                                   context=self.target.host)
                self.stats["browser_probes"] = self.browser.probes_sent
            except Exception as e:
                fid = self.failures.record("dom_xss", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="dom_xss", failure=fid, error=str(e)[:200])
        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:
                pass

        # ---- Phase 56: Multi-User Authorization Engine. Runs AFTER the active
        # phases with its OWN per-account engines (isolated cookie jars — no
        # session cross-contamination with the main scan session): logins every
        # configured account, builds the role x endpoint access matrix, and
        # tests the two authorization failure classes (IDOR/BOLA via victim-
        # marker oracle + vertical escalation via differential-landing
        # candidates). GET-only replays; every finding carries its own VR
        # (VR-17 fresh-victim / VR-18 fresh-privileged-replay).
        authz_result = None
        authz_sessions = {}
        if self.cfg.authz:
            try:
                acfg = AuthzConfig.from_dict(self.cfg.authz, self.target.url)
                aeng = AuthzEngine(acfg, self.scope, self.bus, timeout=self.cfg.timeout)
                authz_result = aeng.run(endpoints)
                authz_sessions = aeng.sessions
                for f in authz_result["findings"]:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                  param=f.parameter)
                self.findings.extend(authz_result["findings"])
                # authz probes touched these endpoints — record it in the ledger
                by_url = {e.url.split("?")[0]: e for e in endpoints}
                for url in authz_result.get("matrix", {}):
                    ep = by_url.get(url.split("?")[0])
                    if ep is not None:
                        self.coverage.activity(ep, "authz", "authz-matrix")
            except Exception as e:
                fid = self.failures.record("authz", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="authz", failure=fid,
                              error=str(e)[:200])
                authz_result = authz_result or {"stats": {"ran": False,
                                                          "error": str(e)[:160]}}
            if authz_result:
                self.stats["authz"] = dict(authz_result.get("stats", {}))

        # ---- Phase 58 (v3.0.0): Workflow / Business-Logic Intelligence. Runs
        # AFTER authz (it reuses the per-role sessions for the privilege
        # manipulation). LEARN: guided walks of multi-step flow clusters on the
        # main authenticated session (chain, resource linkage, state oracle,
        # execution-marker vocabulary). ATTACK (--logic-active only): the five
        # business-logic manipulations on FRESH isolated sessions, every one
        # verified by a state-oracle delta — a server that merely fails to
        # reject is never a finding.
        wf_extra_requests = 0
        if self.cfg.workflow:
            from .workflow import WorkflowEngine
            if self.auth_engine is not None:
                try:
                    wf = WorkflowEngine(planner=self.attack_planner)
                    wres = wf.run(endpoints, self.engine, self.scope, self.bus,
                                  self.cfg.auth, authz_sessions=authz_sessions,
                                  timeout=self.cfg.timeout,
                                  logic_active=self.cfg.logic_active)
                    for f in wres["findings"]:
                        f.run_id = self.run_id
                        self.stats["candidates"] += 1
                        self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                      param=f.parameter)
                    self.findings.extend(wres["findings"])
                    wstats = dict(wres["stats"])
                    wstats["flows"] = [WorkflowEngine.flow_summary(k)
                                       for k in wres["flows"]]
                    self.stats["workflow"] = wstats
                    wf_extra_requests = wres["stats"].get("requests", 0)
                except Exception as e:
                    fid = self.failures.record("workflow", f"{type(e).__name__}: {e}", {})
                    self.bus.emit("ScannerFailed", scanner="workflow", failure=fid,
                                  error=str(e)[:200])
                    self.stats["workflow"] = {"enabled": True, "error": str(e)[:160]}
            else:
                self.stats["workflow"] = {"enabled": False,
                                          "skipped": ["no_form_session"]}

        # ---- v4.1.0 (Phase V41-03/04): GraphQL + WebSocket intelligence.
        # Both engines run on the discovered surface with the identities the
        # scan already holds; the WS client enforces scope on its own (raw
        # sockets bypass the HTTP gate); every skip lands in the boundary.
        gql_stats_default = {"enabled": False, "skipped": ["disabled"]}
        ws_stats_default = {"enabled": False, "skipped": ["disabled"]}
        primary_ident, low_ident_ws = None, None
        lows_v41 = sorted((s for s in (authz_sessions or {}).values()
                           if s.get("rank", 3) > 0),
                          key=lambda s: s["account"].name)
        # V411 FIX (orchestrator identity wiring): see select_primary_identity.
        # V411-GL-14 (live-caught on DVGA): the LOW identity must be a
        # DISTINCT account — with two same-role accounts the name-sorted
        # first pick WAS the primary's own session, so the "cross-identity"
        # BOLA probe read the identity's OWN object (self-read is not BOLA;
        # the finding was mis-attributed and the real anonymous probe's
        # duplicate was deduped away under it).
        primary_ident = select_primary_identity(authz_sessions, self.cfg.auth)
        _pname = (primary_ident or {}).get("name", "")
        lows_v41 = sorted((s for s in (authz_sessions or {}).values()
                           if s.get("rank", 3) > 0
                           and s["account"].name != _pname),
                          key=lambda s: s["account"].name)
        low_session = lows_v41[0] if lows_v41 else None
        low_ident_ws = ({"name": low_session["account"].name,
                         "role": low_session["account"].role,
                         "engine": low_session["engine"]}
                        if low_session else None)
        if self.cfg.graphql:
            try:
                from .graphql import GraphqlEngine
                anon_engine = RequestEngine(self.scope, self.bus,
                                            timeout=self.cfg.timeout)
                gql_engine = GraphqlEngine(
                    self.engine, self.scope, self.bus, timeout=self.cfg.timeout,
                    planner=self.attack_planner, boundary=self.boundary,
                    coverage=self.coverage, logic_active=self.cfg.logic_active)
                gql_res = gql_engine.run(
                    endpoints, self.target.url, anonymous_engine=anon_engine,
                    low_identity=(low_ident_ws | {
                        "object_id": low_session["account"].object_id,
                        "marker": low_session["account"].marker}
                        if low_session else None),
                    primary_identity=primary_ident)
                for f in gql_res["findings"]:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                  param=f.parameter)
                self.findings.extend(gql_res["findings"])
                self.stats["graphql"] = gql_res["stats"]
                if gql_res["stats"].get("requests"):
                    self.stats["requests"] = self.stats["requests"] \
                        + gql_res["stats"]["requests"]
            except Exception as e:
                fid = self.failures.record("graphql", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="graphql", failure=fid,
                              error=str(e)[:200])
                self.stats["graphql"] = {"enabled": True, "error": str(e)[:160]}
                self.boundary.tool_failure("graphql", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:graphql")
        else:
            self.stats["graphql"] = gql_stats_default
        if self.cfg.websocket:
            try:
                from .websocket import WebSocketEngine
                ws_engine = WebSocketEngine(
                    self.scope, self.bus, timeout=self.cfg.timeout,
                    planner=self.attack_planner, boundary=self.boundary,
                    coverage=self.coverage, logic_active=self.cfg.logic_active)
                ws_res = ws_engine.run(endpoints, self.target.url,
                                       low_identity=low_ident_ws,
                                       primary_identity=primary_ident,
                                       observed_urls=getattr(d, "ws_observed", []))
                for f in ws_res["findings"]:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                  param=f.parameter)
                self.findings.extend(ws_res["findings"])
                self.stats["websocket"] = ws_res["stats"]
            except Exception as e:
                fid = self.failures.record("websocket", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="websocket", failure=fid,
                              error=str(e)[:200])
                self.stats["websocket"] = {"enabled": True, "error": str(e)[:160]}
                self.boundary.tool_failure("websocket", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:websocket")
        else:
            self.stats["websocket"] = ws_stats_default

        # ---- Axis 13 (v4.4.0): the modern vulnerability battery — LAZY import
        # (the graphql/wsattack pattern; the hot path never imports it at module
        # level). Fires only on its narrow trigger shapes; every candidate goes
        # through the SAME fail-closed verifier as everything else (VR-29..34).
        if self.cfg.modern and self.cfg.active:
            try:
                from .modernsec import run_modern_battery
                mres = run_modern_battery(self.engine, endpoints, seed=self.seed)
                for f in mres.findings:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type, url=f.endpoint_url,
                                  param=f.parameter)
                    _mep = next((e for e in endpoints if e.url == f.endpoint_url), None)
                    self.findings.append(self.verifier.verify(f, _mep))
                self.stats["modern"] = {"findings": len(mres.findings),
                                        "boundaries": mres.boundaries,
                                        "probe_counts": mres.probe_counts}
                if mres.requests:
                    self.stats["requests"] = self.stats["requests"] + mres.requests
            except Exception as e:
                fid = self.failures.record("modernsec", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="modernsec", failure=fid,
                              error=str(e)[:200])
                self.stats["modern"] = {"enabled": True, "error": str(e)[:160]}
                self.boundary.tool_failure("modernsec", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:modernsec")

        # ---- Owner order part 3 (2026-10-31): the modern-v2 battery —
        # NEW detection layers, LAZY import, ONLY on the explicit opt-in flag
        # (--modern-v2). The v1 battery above is untouched; this block shares
        # no code path with it.
        if self.cfg.modern_v2 and self.cfg.active:
            try:
                from .modernsec2 import run_modern_battery_v2
                rebind_cfg = None
                _rdns = os.environ.get("BURHAN_REBIND_DNS", "")
                _rfetch = os.environ.get("BURHAN_REBIND_FETCH_URL", "")
                if _rdns and _rfetch:
                    rebind_cfg = {"dns_port": int(_rdns),
                                  "fetch_url": _rfetch}
                m2 = run_modern_battery_v2(self.engine, endpoints,
                                           seed=self.seed,
                                           rebind_cfg=rebind_cfg,
                                           authz_sessions=authz_sessions,
                                           race_candidates=self.cfg.race_candidates,
                                           spec=self.cfg.openapi_spec,
                                           target_url=self.target.url)
                for f in m2.findings:
                    f.run_id = self.run_id
                    self.stats["candidates"] += 1
                    self.bus.emit("CandidateCreated", type=f.type,
                                  url=f.endpoint_url, param=f.parameter)
                    _m2ep = next((e for e in endpoints
                                  if e.url == f.endpoint_url), None)
                    self.findings.append(self.verifier.verify(f, _m2ep))
                self.stats["modern_v2"] = {"findings": len(m2.findings),
                                           "boundaries": m2.boundaries,
                                           "probe_counts": m2.probe_counts}
                if m2.requests:
                    self.stats["requests"] = self.stats["requests"] + m2.requests
            except Exception as e:
                fid = self.failures.record("modernsec2",
                                           f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="modernsec2",
                              failure=fid, error=str(e)[:200])
                self.stats["modern_v2"] = {"enabled": True,
                                           "error": str(e)[:160]}
                self.boundary.tool_failure("modernsec2", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:modernsec2")

        # ---- AXIS-17 WIRE (ORD-002-WIRE): the race-condition battery —
        # pure WIRING of the closed burhan/race/ package through its four
        # registration points; runs ONLY when the operator passed --race.
        # A default scan never reaches this block at all (constraint 4).
        if self.cfg.race:
            try:
                self._race_section = self._run_race_battery(endpoints)
            except Exception as e:
                fid = self.failures.record("race", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="race", failure=fid,
                              error=str(e)[:200])
                self._race_section = {
                    "title": "Race Condition Analysis", "enabled": True,
                    "error": str(e)[:160], "boundary": "engine_error",
                    "probed": [], "findings": 0, "requests": 0}
                self.boundary.tool_failure("race", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:race")

        # ---- AXIS-18 (ORD-003): Symbolic Execution Engine (--symbolic).
        # Purely additive: with the flag OFF this block is dead code — the
        # package is never imported (lazy import below), never invoked, and
        # no section appears (bomb-tested; bench x3 zero-drift at the gate).
        # With the flag ON the four-phase chain runs over the passive-baseline
        # sources collected above: extract constraints from validation prose,
        # solve exactly (stdlib only), gate destructive values BEFORE any
        # request, verify path activation through the FULL engine stack
        # (scope gate + journal + budget) and the planner URL gate.
        if getattr(self.cfg, "symbolic", False) and self._symbolic_sources:
            from .symbolic import run_symbolic_analysis, summarize
            from .core import ParamLocation as _SymPL

            def _sym_send(m: dict) -> dict:
                """The injected sender (registration point RP-4): rides the
                full engine stack — scope-gated, journaled, budget-counted,
                exactly like every other engine request."""
                params = dict(m.get("params") or {})
                var = next(iter(params), "")
                ep = Endpoint(url=m.get("url", ""), method=m.get("method") or "GET")
                mut = RequestMutation(endpoint=ep, param_name=var,
                                      param_location=_SymPL.QUERY,
                                      param_value=str(params.get(var, "")),
                                      note=m.get("note", "symbolic-verify"))
                r = self.engine.send(mut)
                return {"status": r.status, "body": r.body or "", "error": r.error}

            def _sym_url_gate(url: str, method: str) -> dict:
                """Defense in depth: the Safe Attack Planner classifies the
                verification URL; DESTRUCTIVE class = never sent (the
                package-side value gate already blocked destructive values)."""
                g = self.attack_planner.gate(url, method=method, note="symbolic-verify")
                return {"allowed": bool(g.get("allowed")), "impact": g.get("impact"),
                        "reason": g.get("rationale", "")}

            try:
                _sym_results = run_symbolic_analysis(
                    self._symbolic_sources, sender=_sym_send,
                    url_gate=_sym_url_gate, seed=self.seed or self.run_id)
                self._symbolic_section = summarize(_sym_results,
                                                   sources=len(self._symbolic_sources))
                self.stats["symbolic"] = {k: v for k, v in self._symbolic_section.items()
                                          if k != "results"}
                self.stats["symbolic"]["results"] = self._symbolic_section["results"]
                self.bus.emit("SymbolicAnalysisCompleted",
                              **{k: v for k, v in self._symbolic_section.items()
                                 if k != "results"})
            except Exception as e:
                # AXIS-18 failures are analysis-level, never scan-level: the
                # scan continues; the failure is an honest boundary.
                fid = self.failures.record("symbolic", f"{type(e).__name__}: {e}", {})
                self.bus.emit("ScannerFailed", scanner="symbolic", failure=fid,
                              error=str(e)[:200])
                self._symbolic_section = {
                    "title": "Symbolic Execution Analysis", "enabled": True,
                    "error": str(e)[:160], "boundary": "engine_error"}
                self.boundary.tool_failure("symbolic", self.target.url,
                                           f"{type(e).__name__}: {e}",
                                           evidence=f"failure {fid}",
                                           provenance="orchestrator:axis18")

        # ---- Phase 12: dedup + correlation + risk
        verified = [f for f in self.findings if f.status == FindingStatus.VERIFIED]
        rejected = [f for f in self.findings if f.status == FindingStatus.REJECTED]
        # OWSP-20 (OWASP campaign, live-caught on DVWA 3.x /vulnerabilities/csrf/):
        # post-verification CANDIDATE findings were silently DROPPED at the
        # findings-list rebuild below (final + rejected left no seat for them),
        # betraying VF-01's documented contract that unverified candidates are
        # visible under their honest name. VR-13's no-input-discrimination
        # branch (a blanket-2xx endpoint: CSRF plausible, unproven) is the
        # producer — the DVWA csrf candidate vanished between detector and
        # report. They now survive into unverified_candidates.
        unverified = [f for f in self.findings if f.status == FindingStatus.CANDIDATE]
        self.stats.update({"requests": self.engine.requests_sent,
                           "verified": len(verified), "rejected": len(rejected),
                           "duration": round(time.time() - t0, 2)})
        # v4.2.1: passive raw-capture journal (supervisor directive 2026-10-03)
        # — snapshot for the independent verification packages. Aggregates every
        # engine that rode this scan's bus (main + authz identities + workflow
        # fresh sessions + graphql anon). Never read by any verdict code path.
        _jr = getattr(self.bus, "request_journal", None)
        if _jr is not None:
            self.stats["request_journal"] = dict(_jr)
            self.stats["request_journal_dropped"] = getattr(self.bus, "request_journal_dropped", 0)
        if self.auth_engine is not None:
            self.stats["auth"] = {
                "authenticated": self.auth_engine.state.authenticated,
                "landing": self.auth_engine.state.landing_url,
                "logins": self.auth_engine.state.logins,
                "reauths": self.auth_engine.state.reauths,
                "failed_reauths": self.auth_engine.state.failed_reauths,
            }
        elif self.token_engine is not None:
            # AUTH-05: token mode — no re-auth is possible; rejections (401/403
            # while armed) are the honest degradation signal instead.
            self.stats["auth"] = {"mode": "token",
                                  "authenticated": self.token_engine.state.authenticated,
                                  "header": self.cfg.auth.auth_header,
                                  "rejections": self.token_engine.rejections}
        # Phase 54: WAF + technology map (passive, evidence-backed) and rate-limit
        # resilience counters — scan context in the report, auditable without rerun.
        self.stats["fingerprint"] = self.fp.summary()
        base = self._base_engine()
        self.stats["rate_limit"] = {"limited": base.rate_limited,
                                    "retries": base.rate_limit_retries,
                                    "recovered": base.rate_limit_recovered}
        # Phase 52: OAST channel transparency — which channel served OOB evidence
        # (local loopback listener vs public webhook provider) and how many
        # interactions it recorded. Blind-vuln confirmations are auditable from
        # the report alone, without re-running the scan.
        if self.cfg.oast is not None:
            try:
                self.stats["oast"] = {"channel": getattr(self.cfg.oast, "channel", "local"),
                                      "interactions": len(self.cfg.oast.hits())}
            except Exception:
                self.stats["oast"] = {"channel": getattr(self.cfg.oast, "channel", "local"),
                                      "interactions": -1}
        # Phase 56: authz-engine requests ride their OWN engines — add them to
        # the total so the report's request count is the whole truth.
        if authz_result and authz_result.get("stats", {}).get("requests"):
            self.stats["requests"] += authz_result["stats"]["requests"]
        # Phase 58: workflow fresh-session requests likewise (the LEARN walks
        # ride the main engine and are already counted there).
        if wf_extra_requests:
            self.stats["requests"] += wf_extra_requests
        # AXIS-17 WIRE: the race battery rides its own transport (http.client
        # concurrency inside burhan/race/) — its requests are counted on top
        # of the engine total so the report's request count stays the whole
        # truth (zero when --race absent — the section is never even built).
        if getattr(self, "_race_section", None) and self._race_section.get("requests"):
            self.stats["requests"] += self._race_section["requests"]
        ded = self.pipeline.dedup(verified)
        final = self.pipeline.correlate(ded)
        for f in final:
            f.confidence = max(f.confidence, 0.5)
        self.findings = final + unverified + rejected
        for f in final:
            self.bus.emit("FindingCreated", id=f.id, type=f.type, url=f.endpoint_url,
                          param=f.parameter, risk=self.pipeline.risk(f))
        # ---- Phase 56: Coverage account + Application Map + secrets summary +
        # impact proof on every verified finding. All deterministic, all derived
        # from artifacts the scan already produced.
        self.stats["coverage"] = self.coverage.summarize()
        auth_mode = ("multi-user(" + ",".join(self.stats.get("authz", {}).get("roles", [])) + ")"
                     if self.stats.get("authz", {}).get("ran") else
                     "form-session" if self.auth_engine is not None else
                     "token" if self.token_engine is not None else "anonymous")
        self.stats["appmap"] = build_appmap(endpoints, param_profile=self.param_profile,
                                            authz_result=authz_result,
                                            coverage_summary=self.stats["coverage"],
                                            auth_mode=auth_mode,
                                            workflow_summary=self.stats.get("workflow", {}).get("flows"))
        # ---- Phase 60-63 (v4.0.0): the Security Digital Twin + Autonomous
        # Reasoning + Safe Attack Planner + Evidence OS. All built from
        # artifacts the scan ALREADY produced — zero extra requests, fully
        # deterministic, additive to the report.
        from .twin import build_twin, twin_summary, authorization_matrix, entity_inventory
        from . import reasoning

        wf_stats = self.stats.get("workflow", {})
        cred_surfaces: dict[str, list[str]] = {}
        for f in final:
            if f.type == "credential_exposure":
                cred_surfaces.setdefault(f.parameter, []).append(f.endpoint_url)
        secrets_summary = {"classes": cred_surfaces} if cred_surfaces else None
        # the twin's identity nodes come from the authz engine's ACTUALLY
        # logged-in sessions (every account that was really exercised)
        if authz_result is not None and authz_sessions:
            authz_result = dict(authz_result)
            authz_result["accounts"] = [
                {"name": s["account"].name, "role": s["account"].role,
                 "username": s["account"].username, "marker": s["account"].marker,
                 "object_id": s["account"].object_id}
                for _, s in sorted(authz_sessions.items())]
        self.twin = build_twin(self.target.url, endpoints,
                               param_profile=self.param_profile,
                               authz_result=authz_result, auth_mode=auth_mode,
                               workflow_stats=wf_stats,
                               findings=[f.to_dict() for f in final
                                         if f.status == FindingStatus.VERIFIED],
                               coverage_summary=self.stats["coverage"],
                               secrets_summary=secrets_summary)
        # hypotheses: generated from twin patterns, resolved against what the
        # scan actually did (findings + the workflow attack log)
        hyps = reasoning.generate_hypotheses(self.twin,
                                             logic_active=self.cfg.logic_active)
        hyps = reasoning.resolve_hypotheses(hyps,
                                             [f.to_dict() for f in final
                                              if f.status == FindingStatus.VERIFIED],
                                             workflow_attack_log=wf_stats.get("attack_log"),
                                             authz_stats=self.stats.get("authz"))
        self.stats["reasoning"] = reasoning.hypothesis_summary(hyps)
        self.stats["reasoning"]["hypotheses"] = hyps[:80]
        # attach the resolved hypotheses to the twin graph (audit trail)
        self.twin_hypotheses = hyps
        for h in hyps:
            self.twin.add_node("hypothesis", h["id"], label=h["pattern"],
                               pattern=h["pattern"], status=h["status"],
                               premise=h.get("premise", "")[:160], test=h.get("test", ""))
            surf = self.twin.find("surface", h.get("surface", ""))
            if surf is not None:
                self.twin.add_edge(surf, self.twin.find("hypothesis", h["id"]),
                                   "generated_hypothesis")
        # ---- v4.1.0 Twin 2.0 (Phase V41-07): GraphQL endpoints, WebSocket
        # channels and the boundary registry become first-class twin nodes,
        # linked to their surfaces — the twin answers protocol questions the
        # same way it answers endpoint ones (with provenance).
        for cand in (self.stats.get("graphql", {}).get("endpoints") or []):
            gn = self.twin.add_node("graphql_endpoint", cand["url"],
                                    label=cand["url"], source=cand["source"])
            surf = self.twin.find("surface", cand["url"])
            if surf is not None:
                self.twin.add_edge(surf, gn, "speaks_protocol")
        for ch in (self.stats.get("websocket", {}).get("channels") or []):
            proto = ((self.stats.get("websocket", {}).get("protocols") or {})
                     .get(ch["url"], ""))
            wn = self.twin.add_node("ws_channel", ch["url"], label=ch["url"],
                                    source=ch["source"], protocol=proto)
            surf = self.twin.find("surface", ch["url"])
            if surf is not None:
                self.twin.add_edge(surf, wn, "speaks_protocol")
        for r in self.boundary.unresolved()[:40]:
            self.twin.add_node("boundary", f"{r.category}|{r.target}",
                               label=f"{r.category} {r.state}", state=r.state,
                               reason=r.reason[:140],
                               remediation=r.remediation[:140])
        self.stats["digital_twin"] = twin_summary(self.twin)
        self.stats["digital_twin"]["authorization_matrix"] = authorization_matrix(self.twin)
        self.stats["digital_twin"]["entity_inventory"] = entity_inventory(self.twin)

        # ---- v4.1.0 (Phase V41-05/06): the multi-dimensional coverage account
        # + the workflow boundary translation. Every dimension is derived from
        # artifacts the scan ALREADY produced; every workflow skip becomes a
        # boundary record; nothing is claimed tested that was not.
        wf_flows = self.stats.get("workflow", {}).get("flows") or []
        wf_log = self.stats.get("workflow", {}).get("attack_log") or []
        for fl in wf_flows:
            self.coverage.dim_discover("workflow", fl["cluster"], {"entry": fl["entry"]})
            if any(a.get("flow") == fl["cluster"]
                   and a.get("verdict") in ("verified", "no_proof") for a in wf_log):
                self.coverage.dim_tested("workflow", fl["cluster"])
            elif self.stats.get("workflow", {}).get("logic_active"):
                self.coverage.dim_untested("workflow", fl["cluster"],
                                           "attacks never ran on this flow")
            for br in (fl.get("branches") or []):
                bkey = f"{fl['cluster']}#{br['field']}={br['value']}"
                self.coverage.dim_discover("workflow_branch", bkey,
                                           {"label": br["label"], "class": br["class"]})
                if br.get("functional") or any(
                        a.get("flow") == fl["cluster"] and a.get("verdict") == "verified"
                        and a.get("attack") in ("branch_bypass", "unauthorized_branch")
                        for a in wf_log):
                    self.coverage.dim_tested("workflow_branch", bkey)
                else:
                    self.coverage.dim_untested(
                        "workflow_branch", bkey,
                        "declared branch never exercised (no functional baseline "
                        "and no branch attack reached it)")
                    self.boundary.record(
                        "workflow/branch", bkey, "NOT_DISCOVERED" if not br.get("functional")
                        else "UNTESTABLE",
                        "branch condition never observed satisfied — the branch "
                        "path exists only as a declared option",
                        provenance="workflow:graph",
                        remediation="provide credentials/preconditions that "
                                    "legitimately reach this branch")
            for tr in (fl.get("state_transitions") or []):
                if "->" in tr and not tr.startswith("-") and not tr.endswith("-"):
                    self.coverage.dim_discover("state", f"{fl['cluster']}@{tr}", {})
            if any(a.get("flow") == fl["cluster"] and a.get("attack") == "cross_state"
                   for a in wf_log):
                for key in list(self.coverage.dim_items("state")):
                    if key.startswith(fl["cluster"] + "@"):
                        self.coverage.dim_tested("state", key)
        # workflow attack log -> boundary records (the honest ledger)
        for a in wf_log:
            if a.get("planner_blocked"):
                self.boundary.blocked("workflow/" + a.get("attack", "?"),
                                      a.get("flow", ""), "safety",
                                      "the Safe Attack Planner refused this "
                                      "manipulation",
                                      provenance="planner:gate")
            elif a.get("verdict") == "skipped" and a.get("precondition"):
                self.boundary.untestable(
                    "workflow/" + a.get("attack", "?"),
                    a.get("flow", ""), a.get("note", "precondition absent")[:120],
                    provenance="workflow:battery")
            elif a.get("verdict") in ("no_proof",):
                self.boundary.tested(
                    "workflow/" + a.get("attack", "?"), a.get("flow", ""),
                    "attack ran; the target held (no state-oracle proof of impact)",
                    evidence=a.get("note", "")[:100], provenance="workflow:battery")
        for s in (self.stats.get("workflow", {}).get("skipped") or []):
            if ":" in s and s.split(":", 1)[1] in ("no_anchor", "chain_too_short",
                                                   "no_resource_linkage",
                                                   "no_state_oracle",
                                                   "no_execution_marker",
                                                   "marker_walk_failed"):
                self.boundary.untestable("workflow/flow", s.split(":", 1)[0],
                                         "flow dropped during learning: " +
                                         s.split(":", 1)[1],
                                         provenance="workflow:learn")
        # authentication dimension
        if self.auth_engine is not None:
            self.coverage.dim_discover("authentication", "form-login", {})
            self.coverage.dim_tested("authentication", "form-login")
            if self.stats.get("auth", {}).get("reauths", 0):
                self.coverage.dim_discover("authentication", "reauthentication", {})
                self.coverage.dim_tested("authentication", "reauthentication")
        elif self.token_engine is not None:
            self.coverage.dim_discover("authentication", "token", {})
            self.coverage.dim_tested("authentication", "token")
        self.coverage.dim_discover("authentication", "anonymous-probe", {})
        self.coverage.dim_tested("authentication", "anonymous-probe")
        # identity dimension
        for a in (authz_result or {}).get("accounts") or []:
            self.coverage.dim_discover("identity", a["name"],
                                       {"role": a["role"]})
            if a["name"] in (authz_sessions or {}):
                self.coverage.dim_tested("identity", a["name"])
        if self.stats.get("authenticated"):
            self.coverage.dim_discover("identity", "primary-session", {})
            self.coverage.dim_tested("identity", "primary-session")
        # authorization dimension (matrix cells actually probed)
        mx = ((self.stats.get("authz") or {}).get("matrix") or {})
        for url in mx:
            self.coverage.dim_discover("authorization", url, {})
            self.coverage.dim_tested("authorization", url)
        if not mx and self.cfg.authz is None:
            self.coverage.dim_untested("authorization", "none",
                                       "no_multi_user_config")
        # entity + object dimensions from the twin
        tested_urls = {f.endpoint_url.split("?")[0] for f in final}
        for ent in (self.stats["digital_twin"].get("entity_inventory") or []):
            self.coverage.dim_discover("entity", ent.get("entity", "?"),
                                       {"surfaces": len(ent.get("surfaces", []))})
            if any(u in tested_urls for u in ent.get("surfaces", [])):
                self.coverage.dim_tested("entity", ent.get("entity", "?"))
        for n in self.twin.by_kind("object"):
            self.coverage.dim_discover("object", n.key, {})
            if any(f.endpoint_url and n.key in f.endpoint_url for f in final) or \
                    any(n.key in str(a.get("resource", "")) or
                        n.key in str(a.get("object", "")) for a in wf_log):
                self.coverage.dim_tested("object", n.key)
        # api_protocol dimension
        self.coverage.dim_discover("api_protocol", "http", {})
        self.coverage.dim_tested("api_protocol", "http")
        if (self.stats.get("openapi") or {}).get("paths"):
            self.coverage.dim_discover("api_protocol", "openapi", {})
            self.coverage.dim_tested("api_protocol", "openapi")
        if (self.stats.get("graphql") or {}).get("candidates"):
            self.coverage.dim_discover("api_protocol", "graphql", {})
            self.coverage.dim_tested("api_protocol", "graphql")
        if (self.stats.get("websocket") or {}).get("candidates"):
            self.coverage.dim_discover("api_protocol", "websocket", {})
            self.coverage.dim_tested("api_protocol", "websocket")
        # detector dimension: every active detector that actually sent probes
        for dname, cnt in getattr(self, "_det_probe_counts", {}).items():
            if cnt > 0:
                self.coverage.dim_discover("detector", dname, {"probes": cnt})
                self.coverage.dim_tested("detector", dname)
        for d in ACTIVE_DETECTORS:
            if d.name not in getattr(self, "_det_probe_counts", {}):
                self.coverage.dim_untested("detector", d.name,
                                           "no candidate surface for this detector")
        # evidence dimension: verified findings vs proof packages
        if verified:
            self.coverage.dim_discover("evidence", "verified-findings", {})
            if self.stats.get("proofs"):
                self.coverage.dim_tested("evidence", "verified-findings")
        # oast dimension
        if self.cfg.oast is not None:
            self.coverage.dim_discover("oast", "local-channel", {})
            if (self.stats.get("oast") or {}).get("interactions", 0) > 0:
                self.coverage.dim_tested("oast", "local-channel")
            else:
                self.coverage.dim_untested("oast", "local-channel",
                                           "armed but no interactions recorded")
        else:
            self.coverage.dim_untested("oast", "none",
                                       "no OAST channel armed (blind classes inert)")
        # browser dimension
        if self.stats.get("browser_pages"):
            self.coverage.dim_discover("browser", "render-merge", {})
            self.coverage.dim_tested("browser", "render-merge")
        elif self.cfg.browser:
            self.coverage.dim_untested("browser", "render-merge",
                                       "playwright/chromium unavailable — static fallback")
        # endpoint dimension mirrors the classic account
        for r in self.coverage.records.values():
            self.coverage.dim_discover("endpoint", r["id"],
                                       {"url": r["url"], "method": r["method"]})
            if any(k in r["activity"] for k in
                   ("passive", "secrets", "active", "authz")):
                self.coverage.dim_tested("endpoint", r["id"])
            elif r["skips"]:
                # V411-COV: an endpoint that was never exercised carries its
                # skip reason INTO the dimension account (live-caught on DVWS:
                # /setup.php showed untested_reason='' in the endpoint
                # dimension while the boundary held the real reason — the
                # reason must be visible where the reader looks)
                self.coverage.dim_untested("endpoint", r["id"], r["skips"][0])
        self.stats["coverage"] = self.coverage.summarize()
        self.stats["coverage"]["dimensions"] = self.coverage.dimensions(
            boundary=self.boundary)
        self.stats["boundary"] = self.boundary.summary()
        # ---- v4.1.0 (Phase V41-11/12): the unified API inventory + the
        # identity x action boundary matrix (both pure projections; wired into
        # the twin as api nodes and into every report format)
        from .apintel import build_api_inventory, build_action_matrix
        self.stats["api_inventory"] = build_api_inventory(
            endpoints, openapi_info=self.stats.get("openapi"),
            graphql_stats=self.stats.get("graphql"),
            websocket_stats=self.stats.get("websocket"),
            coverage_summary=self.stats["coverage"],
            findings=[f.to_dict() for f in final
                      if f.status == FindingStatus.VERIFIED],
            boundary=self.boundary)
        self.stats["action_matrix"] = build_action_matrix(
            self.twin, authz_result=authz_result,
            coverage_summary=self.stats["coverage"])
        for api in self.stats["api_inventory"]["apis"][:80]:
            self.twin.add_node("api", f"{api['protocol']}:{api['path']}",
                               label=api["path"], protocol=api["protocol"],
                               method=api["method"], sources=api["sources"],
                               findings=api["findings"])
        # Twin 2.0 invariants: EVERY node added after build_twin (hypotheses,
        # graphql/ws/boundary/api) gets its belief + provenance NOW, and the
        # audit + why() demonstration are computed from the COMPLETE graph
        self.twin.annotate_provenance()
        self.stats["digital_twin"]["belief_audit"] = self.twin.belief_audit()
        self.stats["digital_twin"]["why_examples"] = [
            self.twin.why(n.id) for n in
            (self.twin.by_kind("identity")[:1] + self.twin.by_kind("workflow")[:1]
             + self.twin.by_kind("graphql_endpoint")[:1]
             + self.twin.by_kind("ws_channel")[:1])]

        # Safe Attack Planner ledger (v4.1.0 Phase V41-10): the REAL-TIME
        # audit ledger — every attack-site operation that was gated BEFORE it
        # ran (workflow battery, GraphQL mutations, WebSocket writes) plus the
        # scan's baseline posture. The v4.0.0 post-hoc reconstruction is gone:
        # what you see is what the planner actually decided, when it decided.
        planner = self.attack_planner
        planner.gate(self.target.url, "GET", note="passive-baseline")
        if self.cfg.crawl:
            planner.gate(self.target.url + "/*", "GET", note="discovery")
        self.stats["planner"] = planner.summary()
        self.stats["planner"]["decisions"] = planner.decisions[:200]
        # Evidence OS: every verified finding becomes a self-contained proof
        # file (hypothesis, preconditions, chain of custody, reproduction).
        # Priority-ordered (business-logic and authorization proofs first —
        # they are the ones an auditor reproduces by hand), then capped.
        def _proof_priority(f) -> tuple:
            if f.type.startswith("business_logic_"):
                return (0, f.type)
            if f.type in ("idor_bola", "vertical_privilege_escalation",
                          "credential_exposure"):
                return (1, f.type)
            return (2, f.type)
        # RP-1/RP-3 (replay fidelity, 2026-10-31): proofs must carry the
        # endpoint's request SHAPE (param locations — query vs form vs JSON
        # body) and the producing detector's name, or a clean replay rebuilds
        # every request as GET-style query params and mis-routes
        # one-type-many-detectors classes (live-caught: csrf/jwt/cmdi fixture
        # replays + 5 remote path_traversal replays all died as
        # REPRODUCTION_FAILED for exactly these two reasons).
        _ep_shape = {}
        for _e in endpoints:
            _ep_shape.setdefault((_e.url.split("?")[0], (_e.method or "GET").upper()), _e)

        def _proof_ep(f):
            return _ep_shape.get((f.endpoint_url.split("?")[0],
                                  (f.method or "GET").upper()))
        self.stats["proofs"] = [build_finding_proof(
                                       f, getattr(f, "state_before", ""),
                                       getattr(f, "state_after", ""),
                                       endpoint=_proof_ep(f)) for f in
                                sorted((f for f in final
                                        if f.status == FindingStatus.VERIFIED),
                                       key=_proof_priority)][:40]
        # VF-01 (v4.2.0): honest accounting of unverified candidates in stats.
        self.stats["unverified_candidates"] = sum(
            1 for f in final if f.status == FindingStatus.CANDIDATE)
        cred_classes = sorted({f.parameter for f in final if f.type == "credential_exposure"})
        if cred_classes or self.cfg.secrets:
            self.stats["secrets"] = {"classes_found": cred_classes,
                                     "findings": sum(1 for f in final
                                                     if f.type == "credential_exposure"),
                                     "masking": ("raw values encrypted into the "
                                                 "credential vault; public reports "
                                                 "show masks only"
                                                 if self.vault is not None else
                                                 "raw values never stored (prefix+length only)")}
        # Phase 57: vault account — masked counts only, plus the audit-visible
        # org/revision (never key material, never record values).
        if self.vault is not None:
            masked_list = self.vault.list()
            self.stats["vault"] = {"org": self.vault.org,
                                   "revision": self.vault.revision,
                                   "records": len(masked_list),
                                   "classes": sorted({r["cls"] for r in masked_list}),
                                   "policy": ("raw values encrypted at rest; "
                                              "reveal requires an authorized key "
                                              "and is audit-logged")}
        self.bus.emit("ScanCompleted", **self.stats)
        return self.report()

    def _base_engine(self) -> RequestEngine:
        """Peel auth/fingerprint proxies to the real RequestEngine (counter owner)."""
        e = self.engine
        for _ in range(4):
            inner = getattr(e, "_inner", None)
            if inner is None:
                break
            e = inner
        return e

    def report(self) -> dict:
        rep = {
            "run_id": self.run_id, "seed": self.seed, "scanner": SCANNER_VERSION,
            "target": self.target.url, "stats": self.stats,
            "findings": [f.to_dict() | {"risk": self.pipeline.risk(f),
                                        "impact": assess_impact(f),
                                        "compliance": compliance_for(f.type)}
                         for f in self.findings
                         if f.status == FindingStatus.VERIFIED],
            "rejected_candidates": [f.to_dict() for f in self.findings
                                    if f.status == FindingStatus.REJECTED],
            # VF-01 (v4.2.0): unverified candidates are no longer silently stamped
            # VERIFIED into findings — and they are no longer silently DROPPED
            # either. They are visible under their honest name.
            "unverified_candidates": [f.to_dict() | {"risk": self.pipeline.risk(f)}
                                      for f in self.findings
                                      if f.status == FindingStatus.CANDIDATE],
        }
        # v4.3.0 (L2 — Attack Path Intelligence): pure post-processing over the
        # serialized report above (findings + journal + twin stats). Zero extra
        # requests, fully deterministic, never mutates verdicts — the additive
        # key rides the report so every scan (bench included) carries its paths.
        from .apath import build_attack_paths
        rep["attack_paths"] = build_attack_paths(rep)
        # Phase 57: defense in depth — when a vault is armed, scrub the WHOLE
        # report of every known raw value. Findings carry masks by
        # construction; this catches any future accidental leakage path.
        if self.vault is not None:
            rep = self.vault.scrub(rep)
        # Axis 14 (v4.4.1): the independently-auditable layer — LAZY import
        # (the apath pattern; the hot path never imports it at module level).
        # ADDITIVE ONLY: one "audit" section — no finding changed, no request
        # added, no stats touched (pinned by the axis-14 wing).
        try:
            from .audit import enrich_report
            rep = enrich_report(rep, seed=self.seed, run_id=self.run_id)
        except Exception as e:
            fid = self.failures.record("audit", f"{type(e).__name__}: {e}", {})
            self.bus.emit("ScannerFailed", scanner="audit", failure=fid,
                          error=str(e)[:200])
            self.boundary.tool_failure("audit", self.target.url,
                                       f"{type(e).__name__}: {e}",
                                       evidence=f"failure {fid}",
                                       provenance="orchestrator:audit")
        # AXIS-17 WIRE (ORD-002-WIRE): the race section rides the report ONLY
        # when the operator passed --race (the order: without the flag the
        # section never appears — a default scan never sets _race_section).
        # Added AFTER the audit enrich so the axis-14 report signature (over
        # the findings) is untouched by the section's presence.
        _race_sec = getattr(self, "_race_section", None)
        if _race_sec is not None:
            rep["race_analysis"] = _race_sec
        # AXIS-18 (ORD-003): the symbolic section rides the report doc the
        # same way — present ONLY when --symbolic ran; the stats copy feeds
        # the store/HTML path. Added after the audit enrich so the axis-14
        # report signature (over the findings) is untouched by its presence.
        _sym_sec = getattr(self, "_symbolic_section", None)
        if _sym_sec is not None:
            rep["symbolic_analysis"] = _sym_sec
        return rep


# ============================================================ DOCTOR (Phase 44/45)
def doctor(allow_private=False) -> dict:
    import socket, ssl, subprocess, sys, platform
    checks = []

    def add(name, ok, detail, fix=""):
        checks.append({"check": name, "status": "PASS" if ok else ("WARN" if detail.startswith("warn") else "FAIL"),
                       "detail": detail, "auto_fix": fix if not ok else ""})

    add("runtime", True, f"Python {sys.version.split()[0]} on {platform.system()}")
    # DNS
    try:
        socket.gethostbyname("scanme.nmap.org")
        add("dns_resolution", True, "resolved scanme.nmap.org")
    except Exception as e:
        add("dns_resolution", False, str(e)[:80], "check /etc/resolv.conf")
    # outbound TCP
    try:
        s = socket.create_connection(("scanme.nmap.org", 80), timeout=8); s.close()
        add("network_egress", True, "TCP connect scanme.nmap.org:80 OK")
    except Exception as e:
        add("network_egress", False, str(e)[:80])
    # TLS
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        add("tls_stack", True, OpenSSL_ver := ssl.OPENSSL_VERSION)
    except Exception as e:
        add("tls_stack", False, str(e)[:80])
    # scope policy sanity
    from .core import is_private_ip
    add("scope_policy", is_private_ip("127.0.0.1") and is_private_ip("10.0.0.5") and not is_private_ip("45.33.32.156"),
        "private ranges blocked, public allowed" + (" (+private override)" if allow_private else ""))
    # detector registry
    add("detector_registry", len(ACTIVE_DETECTORS) >= 4, f"{len(ACTIVE_DETECTORS)} active detectors registered")
    # strategy store
    add("strategy_store", True, "verified-outcome Wilson ordering enabled")
    # persistence layer (Phase 46): sqlite3 available + schema initializes + round-trip
    try:
        import tempfile, os as _os, sqlite3
        from .store import Store
        p = _os.path.join(tempfile.mkdtemp(), "doctor.db")
        st = Store(p)
        st.save_run({"run_id": "run-doctor", "seed": "s", "scanner": "doctor",
                     "target": "http://doctor.local", "stats": {"requests": 1},
                     "findings": [{"id": "F-d", "type": "missing_security_headers",
                                   "severity": "low", "status": "verified",
                                   "url": "http://doctor.local/", "parameter": "", "method": "GET",
                                   "confidence": 0.98, "risk": 20, "evidence": [], "verification": {}}],
                     "rejected_candidates": []})
        ok = len(st.list_findings()) == 1 and st.stats_summary()["runs"] == 1
        add("persistence_layer", ok,
            f"SQLite store OK (schema + write + query round-trip) at {sqlite3.sqlite_version}")
    except Exception as e:
        add("persistence_layer", False, str(e)[:80])
    # repair registry
    add("repair_registry", len(RepairClassifier.RULES) >= 3, f"{len(RepairClassifier.RULES)} repair rules loaded")
    # v4.3.0 (L2 — Attack Path Intelligence): the layer must build paths from a
    # synthetic report AND classify honestly (one proven seed -> VERIFIED path,
    # one indicated seed -> INFERRED path with the weak link named).
    try:
        from .apath import build_attack_paths, _doctor_fixture
        ap = build_attack_paths(_doctor_fixture())
        s = ap["summary"]
        ok = (s["paths_total"] == 2 and s["paths_verified"] == 1
              and s["paths_inferred"] == 1
              and any(p["weak_links"] == ["impact"] for p in ap["paths"]))
        add("attack_path_layer", ok,
            f"L2 active: {s['paths_total']} fixture paths "
            f"({s['paths_verified']} verified / {s['paths_inferred']} inferred) — "
            "weakest-link classification live")
    except Exception as e:
        add("attack_path_layer", False, str(e)[:120])
    # v4.4.0 (L3 — Proven Real Impact): the layer must plan safely from the
    # fail-closed registries, refuse honestly, and NEVER verify an impact
    # without a confirming fresh probe record (empty journal -> 0 verified).
    try:
        from .impact import doctor_check
        ok, detail = doctor_check()
        add("impact_layer", ok, detail)
    except Exception as e:
        add("impact_layer", False, str(e)[:120])
    # browser engine (Phase 50): DOM XSS phase needs Playwright + Chromium.
    # Absent browser = WARN (degraded, not broken): static DOM sink analysis still
    # runs and every other phase is unaffected; browser-only checks are skipped.
    try:
        from .browser import browser_available
        if browser_available():
            add("browser_engine", True, "Playwright Chromium launch OK — DOM engine active")
        else:
            add("browser_engine", False,
                "warn: playwright/chromium unavailable — DOM XSS execution phase disabled "
                "(static sink analysis remains active; install playwright + chromium to enable)")
    except Exception as e:
        add("browser_engine", False, "warn: " + str(e)[:120])
    # auth engine (Phase 51): AuthProfile/AuthEngine/AuthedEngineProxy importable
    # and the ENG-06 body serialization they depend on behaves (no-param POST
    # requests with BODY fields must carry a non-empty form body).
    try:
        from .auth import AuthProfile, AuthEngine, AuthedEngineProxy
        from .core import ParamLocation, Parameter as _P
        eng = RequestEngine(ScopeRule(allowed_domains=["auth.doctor.local"]),
                            EventBus("doctor-auth"), timeout=2)
        m = RequestMutation(endpoint=Endpoint(
            url="http://auth.doctor.local/doLogin", method="POST",
            parameters=[_P("uid", ParamLocation.BODY, "u"), _P("passw", ParamLocation.BODY, "p")]))
        _, _, hdrs, body = eng._render(m)
        add("auth_engine", bool(body) and "uid=u" in body and "passw=p" in body,
            f"login flow engine OK (form body serialized: {bool(body)}; "
            f"watchdog proxy + budget-capped re-auth available)")
    except Exception as e:
        add("auth_engine", False, str(e)[:120])
    # OAST providers (Phase 52): local loopback listener must bind + record, and
    # the public webhook channel must create a token + read an empty request log.
    # The public check is network-dependent -> WARN (degraded, not broken) when
    # the service is unreachable: local OOB confirmation still works.
    try:
        from .oast import OastServer, PublicWebhookProvider
        with OastServer() as _o:
            assert _o.poll("doctor-none", timeout=0.2) is None
        local_ok = True
        try:
            with PublicWebhookProvider() as _p:
                assert _p.public_base.startswith("https://")
                assert _p.poll("doctor-none", timeout=1.0) is None
            public_detail = "local listener + public webhook channel both OK"
            public_ok = True
        except Exception as _pe:
            public_detail = f"warn: public channel unreachable ({str(_pe)[:60]}) — local OOB only"
            public_ok = None                                   # WARN path
        add("oast_providers", public_ok if public_ok is not None else False, public_detail)
    except Exception as e:
        add("oast_providers", False, str(e)[:80])
    # Intelligence Layer (Phase 56): coverage / param-intel / secrets / evidence
    # / appmap / authz modules importable AND their core invariants hold.
    try:
        from .coverage import CoverageTracker
        from .paramintel import ParamIntel
        from .secrets import SecretsScanner, mask
        from .evidence import assess
        from .appmap import build_appmap
        from .authz import AuthzConfig, ROLE_RANK
        from .core import ParamKind          # NOTE: Endpoint stays module-level — a
                                             # local import would shadow it for the
                                             # WHOLE function and break the auth_engine
                                             # check above (live-caught: UnboundLocalError)
        # param-intel: JSON-object value shape is recognized and auditable
        assert ParamIntel.infer("filter", '{"a": 1}') == ParamKind.JSON_OBJECT
        assert ParamIntel.infer("q", "plain") is None
        # coverage: discovered/tested/skip math is exact
        cov = CoverageTracker()
        ep = Endpoint(url="http://x.local/a")
        cov.discover(ep); cov.activity(ep, "passive"); cov.skipped(ep, "demo_reason")
        s = cov.summarize()
        assert s["discovered"] == 1 and s["tested"] == 1 and s["skip_reasons"]["demo_reason"] == 1
        # secrets: signature fires, value is masked, placeholders rejected
        sc = SecretsScanner()
        hits = sc.scan(Endpoint(url="http://x.local/cfg"),
                       type("R", (), {"error": "", "status": 200, "body":
                            '{"aws_access_key_id": "AKIA' + "B" * 16 + '"}',
                            "headers": {}, "request_id": "r1"})())
        assert len(hits) == 1 and "…" in hits[0].evidence[0].detail and "BBBB" not in hits[0].evidence[0].detail
        # evidence: impact assessment maps every registered finding type
        assert assess(type("F", (), {"type": "sql_injection", "evidence": [],
                                     "verification": None, "parameter": "x",
                                     "method": "GET", "endpoint_url": "http://x"})())["grade"] == "proven"
        # authz: role ranking + config parsing
        assert ROLE_RANK["admin"] < ROLE_RANK["user"]
        acfg = AuthzConfig.from_dict({"login_url": "/login", "accounts": [
            {"name": "a", "role": "admin", "username": "u", "password": "p",
             "marker": "m", "object_id": "1"}]}, "http://t.local")
        assert acfg.login_url == "http://t.local/login" and len(acfg.accounts) == 1
        add("intelligence_engines", True,
            "coverage / param-intel / secrets (masked) / evidence-impact / appmap / authz OK")
    except Exception as e:
        add("intelligence_engines", False, str(e)[:120])
    # Credential Vault (Phase 57): crypto self-test — RFC 8439 §2.8.2 AEAD
    # known-answer vector through the library primitive, vault roundtrip,
    # purge leaves no plaintext.
    try:
        import tempfile as _tf, os as _os2
        from .vault import Vault, VaultError, keygen, crypto_selftest
        crypto_selftest()   # RFC 8439 §2.8.2 KAT via the storage AEAD
        with _tf.TemporaryDirectory() as td:
            kf, vp = _os2.path.join(td, "k.json"), _os2.path.join(td, "v.vault")
            keygen(kf, "doctor")
            v = Vault.init(vp, kf, "doctor-selftest")
            probe = "AK" + "IA" + "D" * 16      # aws-shaped probe value
            rid = v.store("aws_access_key", probe,
                          {"url": "http://x/cfg"}, "critical")
            assert v.export(rid)["raw"] == probe
            v.purge(all_records=True)
            data = open(vp, "rb").read()
            assert data.count(probe.encode()) == 0, "plaintext survived purge"
        add("credential_vault", True,
            "ChaCha20-Poly1305 AEAD (cryptography) OK; audit + purge leave no plaintext")
    except Exception as e:
        add("credential_vault", False, str(e)[:120])
    # Workflow Engine (Phase 58): parser + clustering + synthesis invariants.
    try:
        from .workflow import (WorkflowEngine, parse_forms, _privilege_options,
                               _synth_fresh_resource, CANARY_CREATE)
        html = ('<form action="/wf/x/confirm" method="POST">'
                '<input type="hidden" name="csrfToken" value="t1">'
                '<input type="hidden" name="tid" value="TRF-0007">'
                '<input type="hidden" name="amount" value="1111">'
                '<select name="mode"><option value="ach">ACH</option>'
                '<option value="wire">Wire transfer (admin only)</option></select></form>')
        forms = parse_forms(html)
        assert [f["name"] for f in forms[0]["fields"]] == ["csrfToken", "tid", "amount", "mode"]
        assert _privilege_options(forms) == [("mode", "wire", "Wire transfer (admin only)")]
        we = WorkflowEngine()
        assert dict(we._synth_fields(forms[0]))["mode"] == "ach"          # first option
        assert dict(we._synth_fields(forms[0], overrides={"mode": "wire"}))["mode"] == "wire"
        assert _synth_fresh_resource("TRF-0007") == "TRF-99001"
        # cluster eligibility: root excluded, flat /vuln-style dirs excluded,
        # mixed multi-step clusters qualify (>=2 POST + >=1 GET + >=3 members)
        # NOTE: Endpoint is NOT re-imported here — a local import shadows the
        # module-level name for the WHOLE function and breaks the auth_engine
        # check above (live-caught in v2.8.0, same defect class).
        from .core import ParamLocation, Parameter as _P
        eps = [Endpoint(url="http://t.local/wf/transfer/start"),
               Endpoint(url="http://t.local/wf/transfer/ledger"),
               Endpoint(url="http://t.local/wf/transfer/select", method="POST",
                        parameters=[_P("acct", ParamLocation.BODY, "800001")]),
               Endpoint(url="http://t.local/wf/transfer/create", method="POST",
                        parameters=[_P("amount", ParamLocation.BODY, "")]),
               Endpoint(url="http://t.local/wf/transfer/confirm", method="POST"),
               Endpoint(url="http://t.local/vuln/a.php"), Endpoint(url="http://t.local/vuln/b.php")]
        cl = we._cluster_members(eps, {"http://t.local/doLogin"})
        assert "/wf/transfer" in cl and "/vuln" in cl
        assert we._eligible(cl["/wf/transfer"]) and not we._eligible(cl["/vuln"])
        assert "/" not in cl and all("/wf" != d for d in cl)
        add("workflow_engine", True,
            "flow parser (select/options + privilege labels) + cluster rules + "
            "guided-walk synthesis OK")
    except Exception as e:
        add("workflow_engine", False, str(e)[:120])
    # AXIS-18 (ORD-003): Symbolic Execution Engine — the four registration
    # points importable + a REAL extraction->solve->payload round trip.
    try:
        from .symbolic import (parse_constraints, parse_expression, solve_constraints,
                               generate_payload, REGISTRATION_POINTS)
        assert len(REGISTRATION_POINTS) == 4
        cons = parse_constraints(text="password must be at least 8 characters")
        assert cons and cons[0].expr == "len(password) >= 8", [c.expr for c in cons]
        sol = solve_constraints(cons)
        assert sol["status"] == "solved" and \
            len(sol["solutions"]["password"].value) >= 8, sol
        payload, blocked = generate_payload(sol["solutions"])
        assert payload.get("password") and not blocked, (payload, blocked)
        destructive = solve_constraints(parse_expression('mode == "delete_all"'))
        _, dblocked = generate_payload(destructive["solutions"])
        assert "mode" in dblocked, dblocked
        add("symbolic_engine", True,
            "AXIS-18 registration points OK — extract 'len(password) >= 8' -> "
            "solve -> gated payload; destructive solution blocked pre-send")
    except Exception as e:
        add("symbolic_engine", False, str(e)[:120])
    # AXIS-18 evidence signing: Merkle root + Ed25519 sign/verify round trip
    # (RFC 8032 via the audited cryptography library; externally verifiable).
    try:
        from .symbolic.models import SymbolicResult, Constraint, Solution, \
            sign_result, verify_result_signature
        r = SymbolicResult(constraints=[Constraint("password", ">=", 8, "length",
                                                   "len(password) >= 8")],
                           solution=Solution("password", "password123", "doctor"),
                           payload={"password": "password123"})
        sign_result(r, b"doctor-selftest")
        d = r.to_dict()
        assert verify_result_signature(d), "signature failed verification"
        d["payload"]["password"] = "tampered"
        assert not verify_result_signature(d), "tampering not caught"
        add("symbolic_signature", True,
            "AXIS-18 Merkle root + Ed25519 sign/verify round-trip OK — tamper "
            "rejected, externally verifiable (embedded public key)")
    except Exception as e:
        add("symbolic_signature", False, str(e)[:120])
    passed = sum(1 for c in checks if c["status"] == "PASS")
    return {"overall": "PASS" if passed == len(checks) else "DEGRADED",
            "passed": passed, "total": len(checks), "checks": checks}

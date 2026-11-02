"""PART 3 patcher — 3G: Shadow / Zombie API detection.

Diffs the engine's own crawl-discovered endpoint set against an
operator-supplied OpenAPI/Swagger spec, BOTH directions:

  SHADOW  live, reachable, responds with a JSON body, absent from the
          spec (undocumented attack surface).
  ZOMBIE  declared in the spec but (a) the live endpoint 404s (spec
          drift — a dead declaration), or (b) the operation carries
          deprecated:true and the endpoint STILL responds (a
          declared-deprecated version kept alive — OWASP API8:2023
          lists exactly this: "outdated API versions").

Spec ingestion REUSE CASE (order 3.1, stated explicitly): this project
ALREADY ingests specs — discovery.parse_openapi (DISC-13, Phase 54)
builds standard Endpoints from a spec and the orchestrator merges them
into the endpoint map. 3G reuses it for the spec-side endpoint set and
additionally reads the raw paths dict for the deprecated flag, which
parse_openapi does not carry. Nothing new was built for parsing.

Diff scope rule (documented): the spec's namespaces (the first path
segment of every declared path) bound the diff — HTML pages and other
namespaces the spec never claimed are not "undocumented API".

Patches:
  burhan/modernsec2.py   — the 3G family + caps + battery signature
  burhan/orchestrator.py — pass cfg.openapi_spec + target url
  burhan/intel.py        — VR-38 (the reachability must reproduce)
  burhan/compliance.py   — CWE-668 / CWE-1104 + API8:2023
  burhan/report.py       — Burhan-API-001 / Burhan-API-002
  fixtures/vulnapp.py    — SHADOW=1: /api/v2/internal/telemetry (live,
                           undocumented) + /api/v1/users (the deprecated
                           version kept alive) + a lab link
"""
import re

# ---------------------------------------------------------------- modernsec2
p = "burhan/modernsec2.py"
s = open(p).read()

s = s.replace(
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou", "bfla",\n'
    '                 "race_condition")',
    'MODERN2_TYPES = ("jwt_weak_secret", "graphql_aliasing",\n'
    '                 "excessive_data_exposure", "rebind_toctou", "bfla",\n'
    '                 "race_condition", "shadow_api")')
s = s.replace(
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4,\n'
    '                "bfla": 18, "race_condition": 48}',
    'FAMILY2_CAPS = {"jwt_weak_secret": 2, "graphql_aliasing": 2,\n'
    '                "excessive_data_exposure": 8, "rebind_toctou": 4,\n'
    '                "bfla": 18, "race_condition": 48, "shadow_api": 14}')

s = s.replace(
    'RACE_CAND_CAP = 4       # operator-named candidates per scan (3F)',
    'SHADOW_PROBE_CAP = 6    # live-confirmation fetches for SHADOW candidates (3G)\n'
    'ZOMBIE_PROBE_CAP = 8    # live checks of spec-declared paths (3G); the two\n'
    '                         # caps together are the family cap 14 above\n'
    'RACE_CAND_CAP = 4       # operator-named candidates per scan (3F)')

anchor = "def run_modern_battery_v2("
family = '''# ------------------------------------------------------------------ 3G
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


def run_modern_battery_v2('''
assert anchor in s, "battery anchor"
s = s.replace(anchor, family, 1)

s = s.replace(
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None,
                          race_candidates: list | None = None) -> Modern2Result:''',
    '''def run_modern_battery_v2(engine: RequestEngine, endpoints, seed=None,
                          rebind_cfg: dict | None = None,
                          authz_sessions: dict | None = None,
                          race_candidates: list | None = None,
                          spec: dict | None = None,
                          target_url: str = "") -> Modern2Result:''')
s = s.replace(
    '''    _race_prober(st, eps, race_candidates or [])
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''',
    '''    _race_prober(st, eps, race_candidates or [])
    _shadow_api(st, eps, spec, target_url)
    return Modern2Result(st.findings, st.boundaries, probe_counts_of(st),
                         st.requests)''')
open(p, "w").write(s)
print("modernsec2 patched")

# ------------------------------------------------------------- orchestrator
p = "burhan/orchestrator.py"
s = open(p).read()
old = '''                m2 = run_modern_battery_v2(self.engine, endpoints,
                                           seed=self.seed,
                                           rebind_cfg=rebind_cfg,
                                           authz_sessions=authz_sessions,
                                           race_candidates=self.cfg.race_candidates)'''
new = '''                m2 = run_modern_battery_v2(self.engine, endpoints,
                                           seed=self.seed,
                                           rebind_cfg=rebind_cfg,
                                           authz_sessions=authz_sessions,
                                           race_candidates=self.cfg.race_candidates,
                                           spec=self.cfg.openapi_spec,
                                           target_url=self.target.url)'''
assert old in s, "orch anchor"
s = s.replace(old, new)
open(p, "w").write(s)
print("orchestrator patched")

# --------------------------------------------------------------------- intel
p = "burhan/intel.py"
s = open(p).read()
anchor = '''        elif f.type == "race_condition":'''
new = '''        elif f.type in ("shadow_api_endpoint", "zombie_api_endpoint"):
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

        elif f.type == "race_condition":'''
assert anchor in s, "intel anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("intel patched")

# --------------------------------------------------------------- compliance
p = "burhan/compliance.py"
s = open(p).read()
anchor = '''    "race_condition": {'''
new = '''    "shadow_api_endpoint": {
        "cwe": "CWE-668",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "zombie_api_endpoint": {
        "cwe": "CWE-1104",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "race_condition": {'''
assert anchor in s, "compliance anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("compliance patched")

# -------------------------------------------------------------------- report
p = "burhan/report.py"
s = open(p).read()
anchor = '''    "race_condition":                      "Burhan-RACE-001",'''
new = '''    "race_condition":                      "Burhan-RACE-001",
    "shadow_api_endpoint":                 "Burhan-API-001",
    "zombie_api_endpoint":                 "Burhan-API-002",'''
assert anchor in s, "report anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("report patched")

# ------------------------------------------------------------------- vulnapp
p = "fixtures/vulnapp.py"
s = open(p).read()
# routes (do_GET): the live undocumented telemetry + the deprecated version
anchor = '''        if path == "/api/admin/stats":'''
new = '''        if path == "/api/v2/internal/telemetry":
            # 3G SHADOW surface (SHADOW=1): live, JSON, deliberately absent
            # from the RED spec — the undocumented attack surface.
            return self._send(200, '{"requests": 42, "errors": 0}',
                              {"Content-Type": "application/json"})
        if path == "/api/v1/users":
            # 3G ZOMBIE surface (SHADOW=1): the deprecated version kept
            # alive — the RED spec declares it deprecated:true and it still
            # answers.
            return self._send(200,
                              json.dumps({"users": [{"uid": 1001}, {"uid": 2002}]}),
                              {"Content-Type": "application/json"})
        if path == "/api/admin/stats":'''
assert anchor in s, "vulnapp routes anchor"
s = s.replace(anchor, new, 1)
# crawl link for the shadow endpoint (SHADOW=1 only)
anchor = '''if os.environ.get("BFLA") == "1":
    LAB_PAGE = LAB_PAGE.replace("<div>End of lab.</div>", _BFLA_DIVS)'''
new = anchor + '''
# 3G: the shadow endpoint must be CRAWL-discovered (a live link); the
# deprecated /api/v1/users needs no link — the zombie check probes every
# spec-declared path directly.
if os.environ.get("SHADOW") == "1":
    LAB_PAGE = LAB_PAGE.replace(
        "<div>End of lab.</div>",
        '<a href="/api/v2/internal/telemetry">telemetry</a>'
        ' - <a href="/api/v1/users">users v1</a>\\n<div>End of lab.</div>')'''
assert anchor in s, "vulnapp link anchor"
s = s.replace(anchor, new, 1)
open(p, "w").write(s)
print("vulnapp patched")
print("ALL 3G PATCHES APPLIED")

"""Round 10, PART 2 — attack-path chaining over VERIFIED findings.

The design rule (owner order 2.1): a chain rule must cite the SPECIFIC
finding types it connects and the CONCRETE precondition that makes one
finding's output actually feed the other — never "any high + any high".
Every rule below names its pair, states the precondition, and (when the
precondition is a live property of the target rather than a data join)
carries a COMBINED PROOF: a single script whose requests demonstrate
finding A's output genuinely feeding finding B's exploitation, with the
elevation oracle observed over HTTP — re-executed and verified exactly
like every other finding in this project.

OFF BY DEFAULT (2.2): detect_chains() is inert unless a rule's specific
pair both fire in the same scan. On an ordinary scan (no defined pair)
it sends ZERO requests and returns no chains — the layer cannot perturb
any existing run, benchmark, or reproducibility gate.

THE RULES:

CR-01 credential-feeding  (the order's archetype (a))
    pair:  bfla  +  jwt_signature_not_enforced
    precondition: the BFLA finding's admin function, executed with the
    low-privilege session, returns CREDENTIAL MATERIAL (a token) whose
    claims the CWE-347 endpoint accepts — i.e. finding A's own response
    body is the credential that unlocks finding B's protected surface.
    combined proof (live, 3 bounded requests): fresh login harvest ->
    execute the admin function as the low-privilege user -> corrupt the
    returned credential's signature (finding B's own CWE-347 mechanism,
    one mid-signature character flipped) -> present it to finding B's
    protected endpoint -> the elevation oracle must answer role=admin.
    The chain is reported ONLY on that oracle; anything less is not a
    chain, it is two findings.

CR-02 shared-surface entry  (the order's archetype (c))
    pair:  shadow_api_endpoint | zombie_api_endpoint  +  any VERIFIED
    exploitable finding on the SAME normalized endpoint
    precondition: a pure data join — the undocumented/undeclared surface
    (finding A) IS the endpoint the second family proved exploitable.
    The chain narrative: the undocumented surface is an unreviewed entry
    to a proven-exploitable vulnerability; no spec governance, no
    security review trail, no deprecation path. Zero extra requests.

CONSIDERED AND DEFERRED — the order's archetype (b): "an XSS finding on
a page reachable only through an authenticated flow unlocked by a
separate authz bypass". Deferred with the concrete reason: in THIS
engine, for the xss_reflected finding to fire at all, the scanner's own
session must already have reached the authenticated surface — the
detector's reachability IS the unlock, so the pair adds nothing that is
separately provable, and inventing a chain the scanner cannot
demonstrate end-to-end would violate the no-speculation rule. This rule
stays out until a fixture exists where the XSS surface is reachable
ONLY with a credential the scan itself does not hold.
"""
from __future__ import annotations

import json
import urllib.parse

from .prioritize import normalize_endpoint

SCANNER_LAYER = "burhan-chainrules/1.0"

# the exploitable classes CR-02 may join to a shadow/zombie finding on
# the same endpoint (SEED_CLASSES from apath.py discipline: passive
# context classes — banners, header absence — never chain)
EXPLOITABLE_CLASSES = frozenset({
    "sql_injection", "nosql_injection", "xss_reflected", "xss_dom",
    "xss_stored", "path_traversal", "xxe", "ssrf", "command_injection",
    "ssti", "csrf", "jwt_security", "host_header_injection",
    "http_response_header_injection", "open_redirect", "idor_bola",
    "vertical_privilege_escalation", "bfla", "workflow_state_bypass",
    "authorization_bypass", "jwt_signature_not_enforced",
    "jwt_algorithm_confusion", "jwt_none_acceptance", "mass_assignment",
    "prototype_pollution",
})

RULES = [
    {
        "id": "CR-01-credential-feeding",
        "pair": ("bfla", "jwt_signature_not_enforced"),
        "precondition": ("the BFLA function's response, executed with the "
                         "low-privilege session, returns credential "
                         "material whose claims the CWE-347 endpoint "
                         "accepts"),
    },
    {
        "id": "CR-02-shared-surface-entry",
        "pair": ("shadow_api_endpoint|zombie_api_endpoint",
                 "<any exploitable class>"),
        "precondition": ("the undocumented surface IS the same normalized "
                         "endpoint another family proved exploitable "
                         "(pure data join)"),
    },
]


def _corrupt_signature(token: str) -> str:
    """Finding B's own CWE-347 mechanism: flip ONE mid-signature
    character. A signature-ENFORCING endpoint rejects this; the
    signature-not-enforced surface accepts it."""
    parts = token.split(".")
    if len(parts) != 3 or len(parts[2]) < 8:
        return token
    mid = len(parts[2]) // 2
    flipped = "A" if parts[2][mid] != "A" else "B"
    return f"{parts[0]}.{parts[1]}.{parts[2][:mid]}{flipped}{parts[2][mid + 1:]}"


def _bearer_of(response) -> str:
    """The Bearer token a response hands out (the Authorization header
    the engine armed, or token material mined from the body)."""
    hdrs = getattr(response, "headers", None) or {}
    for k, v in hdrs.items():
        if k.lower() == "authorization":
            return v[7:] if v[:7].lower() == "bearer " else v
    body = getattr(response, "body", "") or ""
    try:
        obj = json.loads(body)
        if isinstance(obj, dict) and obj.get("token"):
            return str(obj["token"])
    except ValueError:   # non-JSON body — not a broad except; carries no token
        return ""
    m = None
    if isinstance(body, str):
        import re
        m = re.search(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}", body)
    return m.group(0) if m else ""


# ------------------------------------------------------------- CR-01 proof
def _fresh_login_token(engine):
    """A fresh login harvest through the engine's own credentialed
    endpoint (the AUTH-06 replay pattern — a bare GET can never
    re-obtain a JSON-API token)."""
    ep = getattr(engine, "auth_harvest_endpoint", None)
    if ep is None:
        return None, "no credentialed harvest endpoint on this engine"
    from .http_engine import RequestMutation
    r = engine.send(RequestMutation(endpoint=ep, note="chain-cr01-harvest"))
    tok = _bearer_of(r)
    if not tok:
        return None, f"no token on the fresh harvest (HTTP {getattr(r, 'status', 0)})"
    return tok, None


def _b64u_decode(seg: str) -> dict:
    import base64
    pad = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + pad))


def prove_credential_feeding(engine, bfla_finding: dict,
                             jwt_finding: dict) -> tuple[dict | None, str]:
    """The CR-01 combined proof — ONE script, live requests, the
    elevation oracle. Returns (proof, "") on success, (None, reason) on
    any broken link: a broken link means NO chain, never a reported one."""
    from .http_engine import RequestMutation
    from .core import Endpoint

    # step 1: fresh low-privilege identity (the scan's own login surface)
    low_tok, why_not = _fresh_login_token(engine)
    if not low_tok:
        return None, f"step1 login: {why_not}"

    # step 2: execute the admin-only FUNCTION as the low-privilege user
    # (finding A's own surface, its own method)
    fn_url = bfla_finding.get("url", "")
    r_exec = engine.send(RequestMutation(
        endpoint=Endpoint(url=fn_url, method="POST"),
        extra_headers={"Authorization": f"Bearer {low_tok}"},
        note="chain-cr01-execute-admin-function"))
    if getattr(r_exec, "status", 0) != 200:
        return None, (f"step2 admin function: HTTP "
                      f"{getattr(r_exec, 'status', 0)} — not executed")
    try:
        exec_obj = json.loads(getattr(r_exec, "body", "") or "{}")
    except ValueError:
        return None, "step2 admin function: non-JSON response"
    admin_tok = exec_obj.get("admin_token") or exec_obj.get("token") or ""
    if not admin_tok:
        return None, ("step2 admin function executed but returned NO "
                       "credential material — the escalation link is "
                       "BROKEN (finding A's output cannot feed finding B)")
    try:
        _b64u_decode(admin_tok.split(".")[1])
    except (ValueError, IndexError):
        return None, "step2 returned material is not a claims-bearing token"

    # step 3: corrupt the credential's signature (finding B's OWN
    # mechanism — the CWE-347 differential) and present it to finding B's
    # protected surface; the elevation oracle must answer as admin
    bad_tok = _corrupt_signature(admin_tok)
    prot_url = jwt_finding.get("url", "")
    r_accept = engine.send(RequestMutation(
        endpoint=Endpoint(url=prot_url, method="GET"),
        extra_headers={"Authorization": f"Bearer {bad_tok}"},
        note="chain-cr01-elevation-oracle"))
    if getattr(r_accept, "status", 0) != 200:
        return None, (f"step3 corrupted credential: HTTP "
                      f"{getattr(r_accept, 'status', 0)} on the protected "
                      f"surface — the chain's end link failed")
    try:
        acc_obj = json.loads(getattr(r_accept, "body", "") or "{}")
    except ValueError:
        return None, "step3 protected surface: non-JSON response"
    if str(acc_obj.get("role", "")) != "admin":
        return None, (f"step3 elevation oracle answered role="
                      f"{acc_obj.get('role')!r} — the credential does not "
                      f"carry admin authority; no elevation, no chain")

    proof = {
        "steps": [
            {"step": 1,
             "action": "fresh login harvest through the scan's own "
                       "credentialed endpoint (low-privilege identity)",
             "request_id": getattr(low_tok, "request_id", "harvest"),
             "note": "the low-privilege session the scan itself used"},
            {"step": 2,
             "action": f"executed the admin-only function {fn_url} with "
                       f"the low-privilege session (finding A's surface)",
             "request_id": getattr(r_exec, "request_id", ""),
             "response_sha256_note": "the function's own response is the "
                                     "escalation: it returned the rotated "
                                     "admin credential"},
            {"step": 3,
             "action": f"corrupted that credential's signature (finding "
                       f"B's own CWE-347 mechanism: one mid-signature "
                       f"character flipped) and presented it to "
                       f"{prot_url}",
             "request_id": getattr(r_accept, "request_id", ""),
             "oracle": f"accepted with role=admin — "
                       f"{json.dumps(acc_obj, sort_keys=True)[:200]}"},
        ],
        "elevation_oracle": acc_obj,
        "verdict": "CHAIN PROVEN end-to-end: finding A's own output is "
                   "the credential that unlocks finding B's protected "
                   "surface, accepted AS ADMIN with a corrupted signature",
    }
    return proof, ""


# ------------------------------------------- Finding/dict accessors
def _t(f):
    return getattr(f, "type", None) or f.get("type", "")
def _url(f):
    return getattr(f, "endpoint_url", None) or f.get("url", "")
def _id(f):
    return getattr(f, "id", None) or f.get("id", "")
def _ev0(f):
    ev = getattr(f, "evidence", None) or f.get("evidence") or []
    return (ev[0].detail if ev and hasattr(ev[0], "detail")
            else (ev[0].get("detail", "") if ev else ""))
def _ctx(f):
    return getattr(f, "authz_context", None) or f.get("authz_context", "")


# ------------------------------------------------------------- detection
def _cr01_chains(verified: list, engine) -> list[dict]:
    """The CR-01 pass, isolated so the 'one proven chain suffices' rule is
    a single early return rather than loop breaks."""
    if engine is None:
        return []   # inert: no engine -> no live proof -> no chain claim
    bfla_fs = [f for f in verified if _t(f) == "bfla"]
    jwt_fs = [f for f in verified if _t(f) == "jwt_signature_not_enforced"]
    for b in bfla_fs:
        for j in jwt_fs:
            proof, why_not = prove_credential_feeding(
                engine, {"url": _url(b)}, {"url": _url(j)})
            if proof is None:
                continue    # broken link — the honest non-chain
            return [{
                "rule": "CR-01-credential-feeding",
                "layer": SCANNER_LAYER,
                "title": "admin function hands out the credential "
                         "that unlocks the signature-not-enforced surface",
                "findings": {"finding_a": _id(b), "finding_b": _id(j)},
                "pair": ("bfla", "jwt_signature_not_enforced"),
                "precondition": RULES[0]["precondition"],
                "narrative": [
                    {"step": 1,
                     "text": f"Broken function-level authorization "
                             f"({_ctx(b) or 'lower-privilege session'}): "
                             f"the admin-only function "
                             f"{_url(b).split('?')[0]} executed for a "
                             f"low-privilege session (finding {_id(b)}).",
                     "finding_id": _id(b),
                     "evidence_excerpt": _ev0(b)[:240]},
                    {"step": 2,
                     "text": f"That function's own response returned the "
                             f"rotated ADMIN credential — finding "
                             f"{_id(b)}'s output IS the material that "
                             f"feeds finding {_id(j)}.",
                     "finding_id": _id(b)},
                    {"step": 3,
                     "text": f"Signature not enforced "
                             f"({_url(j).split('?')[0]}): the admin "
                             f"credential with a CORRUPTED signature was "
                             f"accepted as admin (finding {_id(j)}'s own "
                             f"CWE-347 mechanism).",
                     "finding_id": _id(j),
                     "evidence_excerpt": _ev0(j)[:240]},
                ],
                "impact": proof,
                "combined_proof": proof,
                "verified": True,
            }]
    return []


def detect_chains(findings: list, engine=None) -> list[dict]:
    """The chain layer. INERT unless a rule's specific pair fires in
    this scan's VERIFIED findings; the CR-01 proof is live (bounded,
    3 requests) and runs only when its pair is present; CR-02 is a pure
    data join. Returns [] on ordinary scans — no chains, no requests."""
    def _status(f):
        st = getattr(f, "status", None)
        if st is None:
            st = f.get("status", "")
        # FindingStatus.VERIFIED (str-Enum) -> "verified" via .value; a
        # plain dict string passes through. str() on a 3.12 str-Enum does
        # NOT give the value — live-caught here by the e2e test.
        return getattr(st, "value", str(st)).lower()
    verified = [f for f in findings if _status(f) == "verified"]
    # accessors are module-level (_t/_url/_id/_ev0/_ctx) so both the
    # CR-01 helper and this function share one normalization set

    chains: list[dict] = []

    # ---- CR-01: bfla + jwt_signature_not_enforced (needs the engine for
    # the live combined proof; without an engine the rule is skipped and
    # SAID so — never reported on inference alone). One PROVEN chain
    # suffices — the first pair whose combined proof observes the
    # elevation oracle; broken-link pairs return (None, reason) and the
    # scan honestly reports nothing.
    chains.extend(_cr01_chains(verified, engine))

    # ---- CR-02: shadow/zombie + an exploitable finding on the SAME
    # normalized endpoint (pure join — zero requests)
    shadow_fs = [f for f in verified
                 if _t(f) in ("shadow_api_endpoint", "zombie_api_endpoint")]
    if shadow_fs:
        by_endpoint: dict[str, list] = {}
        for f in verified:
            if _t(f) in EXPLOITABLE_CLASSES:
                by_endpoint.setdefault(normalize_endpoint(_url(f)),
                                       []).append(f)
        for sh in shadow_fs:
            ep = normalize_endpoint(_url(sh))
            for other in by_endpoint.get(ep, []):
                if _id(other) == _id(sh):
                    continue
                chains.append({
                    "rule": "CR-02-shared-surface-entry",
                    "layer": SCANNER_LAYER,
                    "title": "undocumented surface is the entry to a "
                             "proven-exploitable vulnerability",
                    "findings": {"finding_a": _id(sh),
                                 "finding_b": _id(other)},
                    "pair": (_t(sh), _t(other)),
                    "precondition": RULES[1]["precondition"],
                    "narrative": [
                        {"step": 1,
                         "text": f"Undocumented surface: {_url(sh).split('?')[0]} "
                                 f"is LIVE but declared by no supplied spec "
                                 f"(finding {_id(sh)}) — unreviewed attack "
                                 f"surface.",
                         "finding_id": _id(sh),
                         "evidence_excerpt": _ev0(sh)[:240]},
                        {"step": 2,
                         "text": f"The SAME endpoint was independently proven "
                                 f"{_t(other)}-vulnerable "
                                 f"(finding {_id(other)}) — the undocumented "
                                 f"surface is this vulnerability's entry.",
                         "finding_id": _id(other),
                         "evidence_excerpt": _ev0(other)[:240]},
                    ],
                    "impact": {"narrative": "an unreviewed, unlisted entry "
                                  "point leads directly to a proven "
                                  "exploitable vulnerability: no spec "
                                  "governance, no security review trail, "
                                  "no deprecation path",
                               "join": "same normalized endpoint (pure "
                                       "data join — verified by identity of "
                                       "URL)"},
                    "combined_proof": None,   # a data-join rule: the two
                              # findings' own evidence IS the proof
                    "verified": True,
                })

    return chains


def chains_summary(chains: list[dict]) -> dict:
    return {"chains_total": len(chains),
            "chains_by_rule": {r: sum(1 for c in chains if c["rule"] == r)
                               for r in sorted({c["rule"] for c in chains})}}

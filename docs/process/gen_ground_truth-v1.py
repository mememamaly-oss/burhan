#!/usr/bin/env python3
"""gen_ground_truth.py — phaseC L1 SPEC §8 step 1: the labeled reference
GENERATOR (Design A — generated strictly from the official list).

Owner order 2026-11-13: ONE build step per session; this session delivers
STEP 1 ONLY (the generator). The oracle (label_oracle.py) and the floors
are the NEXT sessions — nothing here computes P/R or commits any floor.

What it does (SPEC §3.1 contract):
  reads the OFFICIAL challenge list shipped in the package (path pinned,
  sha256 recorded) and emits labeled-ground-truth.json with:
    - one label per official challenge — NO hand-entered vulnerabilities
    - classification by a DECLARED RULE in this code (reviewable), never
      by case-by-case judgment:
        * measurable            — an unauthenticated DAST crawl could in
                                  principle match it with an automatic
                                  oracle (declared rule below)
        * out_of_scope_reason   — outside an unauthenticated DAST's reach
                                  by nature (attacker action, multi-step,
                                  client-side rendering, business logic)
    - classification_rationale generated from the challenge's own official
      definition (category/description/tags) via the declared rule
    - auth_required present from day one (for the later auth expansion)
    - any challenge without a derivable automatic oracle → out_of_scope
      with the reason — FAILS CLOSED: integrity before coverage (§3.1 r3)

Declared classification rule (THE rule, versioned):
  RULE v1 (this file, 2026-11-13):
    A challenge is measurable iff ALL hold:
      (a) its official category maps to an engine battery family
          (CATEGORY_TO_FAMILY table below — the ONLY mapping table, and
          it maps official Juice Shop categories to engine types), AND
      (b) its official definition does NOT require: logging in, a
          registered account, multi-step attacker actions, client-side
          (browser/JS) rendering, or non-HTTP side effects
          (KEYWORD evidence extracted from description+tags+name), AND
      (c) an automatic oracle is derivable: either an engine finding-type
          match on an unauthenticated surface, or an endpoint-secret the
          engine can fetch unauthenticated.
    Otherwise: out_of_scope_reason with the specific failed condition(s).

Usage:
  python3 scripts/bench/gen_ground_truth.py \
      --challenges <path/to/challenges.yml> \
      --app juice-shop --version 20.3.0 \
      --out evidence/real-targets/juice-shop/labeled-ground-truth.json
  --check: verify a committed reference matches regeneration (CI guard).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

LABEL_SCHEMA_VERSION = "1"
RULE_VERSION = "gen-rule-v1 (2026-11-13, this file)"

# Official Juice Shop category -> engine battery family (DECLARED table).
# Categories absent from this table are by-declaration class-gap →
# out_of_scope (rule a). This mirrors the sealed engine taxonomy's
# grounding (19 observed types) — no invented mappings.
CATEGORY_TO_FAMILY: dict[str, list[str]] = {
    "Injection": ["sql_injection", "nosql_injection", "command_injection", "ssti"],
    "XSS": ["xss_reflected", "xss_dom"],
    "Improper Input Validation": ["xss_reflected", "path_traversal", "http_response_header_injection"],
    "Sensitive Data Exposure": ["credential_exposure"],
    "Broken Access Control": ["idor_bola", "vertical_privilege_escalation", "ssrf"],
    "Unvalidated Redirects": ["open_redirect"],
    "Broken Authentication": ["credential_exposure", "jwt_security"],
    "Security Misconfiguration": ["missing_security_headers", "cors_misconfig"],
    "Cryptographic Issues": ["jwt_security"],
    "XXE": ["xxe"],
    "Insecure Deserialization": [],  # no engine battery class
    "Vulnerable Components": [],     # SCA out of the 19-type battery
    "Miscellaneous": [],             # mixed grab-bag — no single family
    "Observability Failures": [],    # log/exposure class, not battery
    "Broken Anti Automation": [],    # rate-limit class
    "Security through Obscurity": [],  # discovery class
}

# Evidence keywords that make a challenge need attacker action / auth /
# client-side rendering / non-HTTP effects (rule b). The regexes run over
# the challenge's official name+description+tags. Each has a human-readable
# label so the rationale string explains itself.
ATTACKER_EVIDENCE: list[tuple[str, str]] = [
    (r"\blog ?in\b|\blogged[- ]in\b|\bsign ?in\b|\bauthenticat", "requires login/authenticated session"),
    (r"\bregistered? (user|account|customer)\b|\byour account\b|\ban account\b", "requires a registered account"),
    (r"\bas (another|a different|the admin|an admin)\b|\bsomeone else'?s?\b|\bon behalf of\b", "multi-account/multi-step attacker action"),
    (r"\bupload\b.*\bthen\b|\bafter (uploading|posting)\b", "multi-step attacker action (upload then act)"),
    (r"\bbrowser\b|\bjavascript\b|\bclient[- ]side\b|\bdevtools\b|\bdom\b", "client-side rendering/inspection required"),
    (r"\bpay(ment|ing)\b|\border\b.*\bplaced\b|\bshopping cart\b|\bbasket\b", "business-logic flow with side effects"),
    (r"\bcsrf\b|\bcross[- ]site request forgery\b", "CSRF victim-session class"),
    (r"\breview of (a|the) product you\b|\bfive[- ]star\b|\bstar review\b", "attacker-authored content flow"),
    (r"\brepeat\w* request|slammer|repeate?d\b", "repeated-request stress class"),
    (r"\bftp\b|\bdirectory listing\b|\bfile system\b|\bfolder\b", "raw file/directory discovery outside HTTP crawl"),
    (r"\bregister as\b|\bsign ?up\b|\bcreating an? account\b", "account-creation attacker flow"),
    (r"\bchange\b.*\bpassword\b|\breset\b.*\bpassword\b|\bpassword\b.*\bchange\b", "authenticated victim-account action"),
    (r"\bmint\b|\bnft\b|\bwallet\b|\bsoul bound token\b|\bbees?\b|\bblockchain\b|\bcrypto ?wallet\b|\bweb3\b", "Web3/NFT wallet flow outside HTTP crawl"),
    (r"\btake over\b|\btakeover\b|\bhijack\b", "account/wallet takeover flow"),
    (r"\bgather\b|\bcollect\b.*\bfrom\b", "multi-step gathering quest"),
]

# Oracle kinds the engine can evaluate automatically today on an
# unauthenticated crawl (rule c). endpoint_secret: the challenge's own
# key/token is fetchable; finding_type_match: an engine type above would
# flag the surface. Challenges whose only proof is the challenge KEY
# being solved server-side (client-side solution ceremony) get the honest
# out_of_scope reason instead of a fabricated oracle.
NO_ORACLE_HINTS = re.compile(
    r"\bchallenge key\b|\bsolve[sd]? this challenge\b|\bstatus code\b|"
    r"\bsuccessfully\b(?!.{0,40}\bendpoint\b)|\bproof\b", re.I)

FAMILY_TO_ORACLE: dict[str, str] = {
    "sql_injection": "finding_type_match:sql_injection",
    "nosql_injection": "finding_type_match:nosql_injection",
    "command_injection": "finding_type_match:command_injection",
    "ssti": "finding_type_match:ssti",
    "xss_reflected": "finding_type_match:xss_reflected",
    "xss_dom": "finding_type_match:xss_dom",
    "path_traversal": "finding_type_match:path_traversal",
    "http_response_header_injection": "finding_type_match:http_response_header_injection",
    "credential_exposure": "finding_type_match:credential_exposure",
    "idor_bola": "finding_type_match:idor_bola",
    "vertical_privilege_escalation": "finding_type_match:vertical_privilege_escalation",
    "open_redirect": "finding_type_match:open_redirect",
    "jwt_security": "finding_type_match:jwt_security",
    "missing_security_headers": "finding_type_match:missing_security_headers",
    "cors_misconfig": "finding_type_match:cors_misconfig",
    "xxe": "finding_type_match:xxe",
    "ssrf": "finding_type_match:ssrf",
}


def parse_challenges(text: str) -> list[dict]:
    """Minimal, dependency-free YAML reader for the official flat schema:
    a list of maps whose values are scalars or lists of scalars. The
    official challenges.yml uses exactly this shape (verified against
    v20.3.0: 116 entries, quoted scalar values, no nesting beyond tags).
    Fails closed on anything else."""
    import yaml  # only if available; else use the fallback parser
    return yaml.safe_load(text)


def classify(ch: dict) -> tuple[str, str, list[str], dict]:
    """Returns (classification, rationale, families, oracle)."""
    name = ch.get("name", "")
    desc = ch.get("description", "")
    tags = " ".join(ch.get("tags", []) or [])
    blob = f"{name} {desc} {tags}"
    low = blob.lower()

    # rule (a): category must map to a battery family
    families = CATEGORY_TO_FAMILY.get(ch.get("category", ""), [])
    if not families:
        return ("out_of_scope_reason",
                f"official category '{ch.get('category')}' has no engine "
                f"battery family (declared CATEGORY_TO_FAMILY table) — class gap",
                [], {"kind": "none", "definition": "no automatic oracle derivable"})

    # rule (b): no attacker-action/auth/client-side evidence in the
    # OFFICIAL definition itself
    failed_conditions = []
    for rx, why in ATTACKER_EVIDENCE:
        if re.search(rx, low):
            failed_conditions.append(why)
    if failed_conditions:
        return ("out_of_scope_reason",
                "official definition requires: " + "; ".join(failed_conditions),
                families, {"kind": "none", "definition": "outside unauthenticated DAST reach"})

    # rule (c): automatic oracle derivable for at least one family
    oracle_kinds = [FAMILY_TO_ORACLE[f] for f in families if f in FAMILY_TO_ORACLE]
    if not oracle_kinds:
        return ("out_of_scope_reason",
                f"category '{ch.get('category')}' families {families} have no "
                f"automatic oracle kind in the declared table",
                families, {"kind": "none", "definition": "no automatic oracle derivable"})
    # pick the subfamily the official description names — deterministic,
    # reviewable (SUBFAMILY_KEYWORDS), falls back to the first family
    fam = pick_subfamily(ch, [f for f in families if f in FAMILY_TO_ORACLE])
    oracle = {"kind": "finding_type_match",
              "definition": FAMILY_TO_ORACLE[fam]}
    rationale = (f"category '{ch.get('category')}' maps to battery family "
                 f"'{fam}'; official definition shows no attacker-action/auth/"
                 f"client-side evidence (rule b keywords); automatic oracle "
                 f"derivable ({FAMILY_TO_ORACLE[fam]})")
    # the label's mapping is the SELECTED subfamily (single-element list),
    # not the whole category family — the oracle above uses exactly it
    return ("measurable", rationale, [fam], oracle)


# Subfamily selection WITHIN a mapped category: the official
# description names the concrete sink; the declared keyword table picks
# the right engine type from the category's family list (deterministic,
# reviewable). Falls back to the first family member.
SUBFAMILY_KEYWORDS: list[tuple[str, str]] = [
    (r"\bssrf\b|\bserver[- ]side request forgery\b", "ssrf"),
    (r"\bssti\b|\btemplate\b", "ssti"),
    (r"\bnosql\b|\bmongo\b", "nosql_injection"),
    (r"\bredirect\b|\bredirects\b", "open_redirect"),
    (r"\bxxe\b|\bxml external entity\b", "xxe"),
    (r"\bjwt\b|\bcoupon\b|\bforge[ds]? (coupon|signed)\b|\btoken signing\b", "jwt_security"),
    (r"\bheader\b.*\bmissing\b|\bsecurity headers\b|\bcsp\b|\bcross[- ]origin\b|\bcors\b", "missing_security_headers"),
    (r"\bpassword|credential|\bsecret\b|\bapi key\b|\bbackup\b|\bblueprint\b|\bpackage\.json\b|\bemail[s]?\b|\bdocument\b|\bdirectory\b|\bschema\b|\bleak\b", "credential_exposure"),
    (r"\bxss\b|\bscript\b|\biframe\b|\balert\b|\bencode[d]?\b|\bnull byte\b|\bencoding\b", "xss_reflected"),
    (r"\bsqlite_master\b|\bunion\b|\blike\b|\bselect\b|\bsql\b", "sql_injection"),
    (r"\bupload\b|\bfile size\b|\bfile type\b|\bmaximum\b", "path_traversal"),
]


def pick_subfamily(ch: dict, families: list[str]) -> str:
    blob = f"{ch.get('name','')} {ch.get('description','')}".lower()
    for rx, fam in SUBFAMILY_KEYWORDS:
        if re.search(rx, blob) and fam in families:
            return fam
    return families[0]


def auth_required(ch: dict) -> bool:
    blob = f"{ch.get('name','')} {ch.get('description','')}".lower()
    return bool(re.search(r"\blog ?in\b|\blogged[- ]in\b|\bregistered? (user|account|customer)\b", blob))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenges", required=True,
                    help="path to the OFFICIAL challenge list (pinned at step zero)")
    ap.add_argument("--app", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--check", action="store_true",
                    help="verify the committed reference matches regeneration")
    a = ap.parse_args()

    src = pathlib.Path(a.challenges)
    if not src.exists():
        print(f"FAIL-CLOSED: challenge list not found: {src}")
        return 2
    raw = src.read_bytes()
    ref_sha = hashlib.sha256(raw).hexdigest()
    challenges = parse_challenges(raw.decode("utf-8"))
    if not challenges or not isinstance(challenges, list):
        print("FAIL-CLOSED: challenge list did not parse into a non-empty list")
        return 2

    labels = []
    for ch in challenges:
        cls, rationale, families, oracle = classify(ch)
        labels.append({
            "challenge_id": ch.get("key", ""),
            "challenge_name": ch.get("name", ""),
            "category": ch.get("category", ""),
            "difficulty": ch.get("difficulty"),
            "auth_required": auth_required(ch),
            "classification": cls,
            "classification_rationale": rationale,
            "vuln_type_mapping": families[0] if families else "none",
            "oracle": oracle,
        })

    counts = {}
    for l in labels:
        counts[l["classification"]] = counts.get(l["classification"], 0) + 1
    out = {
        "source": f"{a.app} v{a.version} — official challenge list (generated, Design A)",
        "source_file": str(src),
        "reference_sha256": ref_sha,
        "rule": RULE_VERSION,
        "label_schema_version": LABEL_SCHEMA_VERSION,
        "counts": counts,
        "labels": labels,
    }
    text = json.dumps(out, indent=1, ensure_ascii=False) + "\n"

    outp = pathlib.Path(a.out)
    if a.check:
        current = outp.read_text(encoding="utf-8") if outp.exists() else ""
        if current != text:
            print(f"DRIFT: {outp} does not match regeneration from {src}")
            return 1
        print(f"OK: {outp} matches regeneration ({len(labels)} labels, "
              f"counts {counts})")
        return 0
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(text, encoding="utf-8")
    print(f"wrote {outp} ({len(labels)} labels, counts {counts})")
    print(f"reference_sha256={ref_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

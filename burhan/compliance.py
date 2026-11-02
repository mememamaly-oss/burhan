"""P2-C (2026-10-31): Compliance mapping registry — OWASP / CWE / PCI DSS.

Every detector class the engine can emit (the stable set behind
report.SARIF_RULES) carries a compliance mapping so every finding, every
report format and every platform view can answer the buyer's first question:
"which OWASP / CWE / PCI DSS requirement does this hit?"

Honesty contract (same as every other registry in this engine):

- A category assignment is tagged "official" ONLY when the chosen CWE number
  appears in that category's official "List of Mapped CWEs" on the OWASP Top 10
  page for that year. Those official lists were fetched from top10.owasp.org
  on 2026-10-31 and are embedded verbatim below in OFFICIAL_LISTS — the tag is
  machine-checkable (tests/test_compliance_mappings.py cross-checks it).
- Anything not provable that way is tagged "scope": an editorial assignment by
  category scope, clearly marked as such in every surface that renders it.
- Unknown/legacy finding types get an explicit unmapped result — never a guess.

OWASP Top 10 editions used:
- OWASP Top 10:2021 (A01:2021 .. A10:2021) — https://top10.owasp.org/2021/en
- OWASP Top 10:2025 (final release; A01:2025 .. A10:2025) —
  https://top10.owasp.org/2025/en — note the final 2025 list differs from the
  April-2025 release candidate (A03 became Software Supply Chain Failures,
  A04 Cryptographic Failures, A05 Injection, A06 Insecure Design); the mappings
  below follow the FINAL list.

PCI DSS: every mapped type carries "6.4.2" — PCI DSS v4.0 Requirement 6.4.2
("public-facing web applications are protected against ongoing attacks"; this
is the requirement numbered 6.6 in PCI DSS v3.2.1). A DAST finding stream is
the assessment evidence for that requirement; the mapping is uniform by
design, not per-type.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Edition category registries (code -> human title)
# ---------------------------------------------------------------------------
OWASP_2021_CATEGORIES: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software or Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server Side Request Forgery (SSRF)",
}

OWASP_2025_CATEGORIES: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# ---------------------------------------------------------------------------
# OFFICIAL_LISTS — the "List of Mapped CWEs" per category page, fetched from
# top10.owasp.org on 2026-10-31. A mapping row may only claim "official" when
# its CWE number is present in the corresponding set below. This is the
# auditable source for the tags; tests re-verify every "official" claim.
# ---------------------------------------------------------------------------
OFFICIAL_LISTS: dict[tuple[str, str], frozenset[str]] = {
    ("2025", "A01:2025"): frozenset({
        "CWE-22", "CWE-23", "CWE-36", "CWE-59", "CWE-61", "CWE-65", "CWE-200",
        "CWE-201", "CWE-219", "CWE-276", "CWE-281", "CWE-282", "CWE-283",
        "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-379",
        "CWE-402", "CWE-424", "CWE-425", "CWE-441", "CWE-497", "CWE-538",
        "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-615",
        "CWE-639", "CWE-668", "CWE-732", "CWE-749", "CWE-862", "CWE-863",
        "CWE-918", "CWE-922", "CWE-1275",
    }),
    ("2025", "A02:2025"): frozenset({
        "CWE-5", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315",
        "CWE-489", "CWE-526", "CWE-547", "CWE-611", "CWE-614", "CWE-776",
        "CWE-942", "CWE-1004", "CWE-1174",
    }),
    ("2025", "A03:2025"): frozenset({
        "CWE-447", "CWE-1035", "CWE-1104", "CWE-1329", "CWE-1357", "CWE-1395",
    }),
    ("2025", "A05:2025"): frozenset({
        "CWE-20", "CWE-74", "CWE-76", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
        "CWE-83", "CWE-86", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93",
        "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-103",
        "CWE-104", "CWE-112", "CWE-113", "CWE-114", "CWE-115", "CWE-116",
        "CWE-129", "CWE-159", "CWE-470", "CWE-493", "CWE-500", "CWE-564",
        "CWE-610", "CWE-643", "CWE-644", "CWE-917",
    }),
    ("2025", "A06:2025"): frozenset({
        "CWE-73", "CWE-183", "CWE-256", "CWE-266", "CWE-269", "CWE-286",
        "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-362", "CWE-382",
        "CWE-419", "CWE-434", "CWE-436", "CWE-444", "CWE-451", "CWE-454",
        "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-598",
        "CWE-602", "CWE-628", "CWE-642", "CWE-646", "CWE-653", "CWE-656",
        "CWE-657", "CWE-676", "CWE-693", "CWE-799", "CWE-807", "CWE-841",
        "CWE-1021", "CWE-1022", "CWE-1125",
    }),
    ("2025", "A07:2025"): frozenset({
        "CWE-258", "CWE-259", "CWE-287", "CWE-288", "CWE-289", "CWE-290",
        "CWE-291", "CWE-293", "CWE-294", "CWE-295", "CWE-297", "CWE-298",
        "CWE-299", "CWE-300", "CWE-302", "CWE-303", "CWE-304", "CWE-305",
        "CWE-306", "CWE-307", "CWE-308", "CWE-309", "CWE-346", "CWE-350",
        "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798",
        "CWE-940", "CWE-941", "CWE-1390", "CWE-1391", "CWE-1392", "CWE-1393",
    }),
    ("2025", "A08:2025"): frozenset({
        "CWE-345", "CWE-353", "CWE-426", "CWE-427", "CWE-494", "CWE-502",
        "CWE-506", "CWE-509", "CWE-565", "CWE-784", "CWE-829", "CWE-830",
        "CWE-915", "CWE-926",
    }),
    ("2021", "A03:2021"): frozenset({
        "CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80",
        "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93",
        "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100",
        "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471",
        "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917",
    }),
    ("2021", "A07:2021"): frozenset({
        "CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
        "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306",
        "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
        "CWE-640", "CWE-798", "CWE-940", "CWE-1216",
    }),
}

CWE_LABELS: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-23": "Relative Path Traversal",
    "CWE-601": "URL Redirect to Untrusted Site (Open Redirect)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-78": "OS Command Injection",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-942": "Permissive Cross-Domain Policy",
    "CWE-113": "HTTP Response Splitting (CRLF)",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-1104": "Use of Unmaintained Third-Party Components",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-269": "Improper Privilege Management",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-1336": "Template Injection (SSTI)",
    "CWE-943": "Improper Neutralization in Data Query Logic (NoSQL)",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-644": "HTTP Request Spoofing (Host Header)",
    "CWE-614": "Sensitive Cookie in 'Secure' Session Without the 'Secure' Attribute",
    "CWE-840": "Business Logic Errors",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-94": "Code Injection",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests (Smuggling)",
    "CWE-915": "Mass Assignment",
    "CWE-1321": "Prototype Pollution",
}

# ---------------------------------------------------------------------------
# COMPLIANCE — one row per detector class (the SARIF_RULES key set).
# Fields: cwe | owasp_2021 + owasp_2021_src | owasp_2025 + owasp_2025_src
# src ∈ {"official", "scope"} (see module docstring).
# ---------------------------------------------------------------------------
COMPLIANCE: dict[str, dict[str, str]] = {
    # ---- core injection family
    "sql_injection": {
        "cwe": "CWE-89",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "xss_reflected": {
        "cwe": "CWE-79",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "xss_dom": {
        "cwe": "CWE-79",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "command_injection": {
        "cwe": "CWE-78",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "ssti": {
        "cwe": "CWE-1336",
        "owasp_2021": "A03:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "nosql_injection": {
        "cwe": "CWE-943",
        "owasp_2021": "A03:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "http_response_header_injection": {
        "cwe": "CWE-113",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "header_injection": {
        "cwe": "CWE-113",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "host_header_injection": {
        "cwe": "CWE-644",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "graphql_sql_injection": {
        "cwe": "CWE-89",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    "graphql_command_execution": {
        "cwe": "CWE-94",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
    # ---- access control family
    "path_traversal": {
        "cwe": "CWE-23",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "open_redirect": {
        "cwe": "CWE-601",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "csrf": {
        "cwe": "CWE-352",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "ssrf": {
        "cwe": "CWE-918",
        "owasp_2021": "A10:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "idor": {
        "cwe": "CWE-639",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "idor_bola": {
        "cwe": "CWE-639",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "vertical_privilege_escalation": {
        "cwe": "CWE-269",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "official",
    },
    "credential_exposure": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "server_banner_disclosure": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "tech_banner_disclosure": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "graphql_introspection_enabled": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "graphql_bola": {
        "cwe": "CWE-639",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "graphql_field_authorization": {
        "cwe": "CWE-862",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "graphql_mutation_authorization": {
        "cwe": "CWE-862",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "websocket_sensitive_data_exposure": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    "websocket_cross_user_access": {
        "cwe": "CWE-862",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "official",
    },
    # ---- configuration family
    "secure_cookie": {
        "cwe": "CWE-614",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A02:2025", "owasp_2025_src": "official",
    },
    "xxe": {
        "cwe": "CWE-611",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A02:2025", "owasp_2025_src": "official",
    },
    "cors_misconfig": {
        "cwe": "CWE-942",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A02:2025", "owasp_2025_src": "official",
    },
    "missing_security_headers": {
        "cwe": "CWE-693",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "official",
    },
    "http_request_smuggling": {
        "cwe": "CWE-444",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "official",
    },
    # ---- components / supply chain
    "vulnerable_js_dependency": {
        "cwe": "CWE-1104",
        "owasp_2021": "A06:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A03:2025", "owasp_2025_src": "official",
    },
    # ---- authentication family
    "jwt_security": {
        "cwe": "CWE-347",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "shadow_api_endpoint": {
        "cwe": "CWE-668",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "zombie_api_endpoint": {
        "cwe": "CWE-1104",
        "owasp_2021": "A05:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A05:2025", "owasp_2025_src": "scope",
    },
    "race_condition": {
        "cwe": "CWE-362",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A04:2025", "owasp_2025_src": "scope",
    },
    "bfla": {
        "cwe": "CWE-285",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "scope",
    },
    "jwt_algorithm_confusion": {
        "cwe": "CWE-347",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "jwt_signature_not_enforced": {
        "cwe": "CWE-347",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "jwt_none_acceptance": {
        "cwe": "CWE-347",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "graphql_anonymous_access": {
        "cwe": "CWE-306",
        "owasp_2021": "A07:2021", "owasp_2021_src": "official",
        "owasp_2025": "A07:2025", "owasp_2025_src": "official",
    },
    "websocket_origin_not_enforced": {
        "cwe": "CWE-346",
        "owasp_2021": "A07:2021", "owasp_2021_src": "official",
        "owasp_2025": "A07:2025", "owasp_2025_src": "official",
    },
    # ---- integrity family
    "mass_assignment": {
        "cwe": "CWE-915",
        "owasp_2021": "A08:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A08:2025", "owasp_2025_src": "official",
    },

    # ---- owner order part 3 (2026-10-31): modern battery v2 families ----
    "jwt_weak_secret": {
        "cwe": "CWE-798",
        "owasp_2021": "A07:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A07:2025", "owasp_2025_src": "scope",
    },
    "graphql_aliasing": {
        "cwe": "CWE-400",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "excessive_data_exposure": {
        "cwe": "CWE-200",
        "owasp_2021": "A01:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A01:2025", "owasp_2025_src": "scope",
    },
    "rebind_toctou": {
        "cwe": "CWE-367",
        "owasp_2021": "A10:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A10:2025", "owasp_2025_src": "scope",
    },
    "prototype_pollution": {
        "cwe": "CWE-1321",
        "owasp_2021": "A08:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A08:2025", "owasp_2025_src": "scope",
    },
    # ---- business logic / workflow (insecure design)
    "business_logic_step_bypass": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_out_of_order": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_value_tamper": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_duplicate_execution": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_privilege_escalation": {
        "cwe": "CWE-269",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "official",
    },
    "business_logic_cross_user_execution": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_cross_object_execution": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_cross_state_execution": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_branch_bypass": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_unauthorized_branch": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_approval_bypass": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "business_logic_rollback_abuse": {
        "cwe": "CWE-840",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    "graphql_batching_enabled": {
        "cwe": "CWE-400",
        "owasp_2021": "A04:2021", "owasp_2021_src": "scope",
        "owasp_2025": "A06:2025", "owasp_2025_src": "scope",
    },
    # ---- WebSocket message reflection (XSS-class via cross-client echo)
    "websocket_message_reflection": {
        "cwe": "CWE-79",
        "owasp_2021": "A03:2021", "owasp_2021_src": "official",
        "owasp_2025": "A05:2025", "owasp_2025_src": "official",
    },
}

# NOTE: registry keys are exactly the engine's SARIF_RULES keys — the
# parity test (tests/test_compliance_mappings.py) fails CI if they drift.

PCI_DSS_REQUIREMENT = "6.4.2"
PCI_DSS_NOTE = ("PCI DSS v4.0 Req 6.4.2 — protection of public-facing web "
                "applications (numbered 6.6 in PCI DSS v3.2.1).")


def compliance_for(ftype: str) -> dict:
    """Compliance view of one finding type. Never guesses: unknown types get
    mapped=False and empty fields, which every renderer shows as an honest
    'unmapped' instead of a fabricated category."""
    row = COMPLIANCE.get(ftype)
    if not row:
        return {
            "type": ftype, "mapped": False,
            "cwe": None, "cwe_label": None,
            "owasp_2021": None, "owasp_2021_title": None, "owasp_2021_src": None,
            "owasp_2025": None, "owasp_2025_title": None, "owasp_2025_src": None,
            "pci_dss": None,
        }
    return {
        "type": ftype, "mapped": True,
        "cwe": row["cwe"], "cwe_label": CWE_LABELS.get(row["cwe"], ""),
        "owasp_2021": row["owasp_2021"],
        "owasp_2021_title": OWASP_2021_CATEGORIES.get(row["owasp_2021"], ""),
        "owasp_2021_src": row["owasp_2021_src"],
        "owasp_2025": row["owasp_2025"],
        "owasp_2025_title": OWASP_2025_CATEGORIES.get(row["owasp_2025"], ""),
        "owasp_2025_src": row["owasp_2025_src"],
        "pci_dss": PCI_DSS_REQUIREMENT,
    }


def compliance_summary(findings: list) -> dict:
    """Category-level counts over a finding list (dicts with a 'type' key).
    Used by the executive/SARIF/HTML/GLASS views and the platform demo page."""
    by_2021: dict[str, int] = {}
    by_2025: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    unmapped = 0
    for f in findings or []:
        c = compliance_for(str(f.get("type", "")))
        if not c["mapped"]:
            unmapped += 1
            continue
        by_2021[c["owasp_2021"]] = by_2021.get(c["owasp_2021"], 0) + 1
        by_2025[c["owasp_2025"]] = by_2025.get(c["owasp_2025"], 0) + 1
        by_cwe[c["cwe"]] = by_cwe.get(c["cwe"], 0) + 1
    return {
        "owasp_2021": dict(sorted(by_2021.items())),
        "owasp_2025": dict(sorted(by_2025.items())),
        "cwe": dict(sorted(by_cwe.items())),
        "pci_dss": {PCI_DSS_REQUIREMENT: sum(by_cwe.values())},
        "unmapped_types": unmapped,
        "note": ("official = the CWE appears in the category's official "
                 "mapped-CWE list (top10.owasp.org, fetched 2026-10-31); "
                 "scope = editorial assignment by category scope"),
    }


def compliance_json() -> dict:
    """Machine-readable export for the CLI (`burhan compliance --json`),
    the platform registry generator (scripts/gen_compliance_registry.py) and
    the parity tests. Everything downstream renders from this one source."""
    return {
        "generated_by": "burhan.compliance",
        "pci_dss": {"requirement": PCI_DSS_REQUIREMENT, "note": PCI_DSS_NOTE},
        "categories": {
            "owasp_2021": OWASP_2021_CATEGORIES,
            "owasp_2025": OWASP_2025_CATEGORIES,
        },
        "official_lists": {
            f"{year} {cat}": sorted(cwes)
            for (year, cat), cwes in sorted(OFFICIAL_LISTS.items())
        },
        "cwe_labels": CWE_LABELS,
        "types": {ftype: compliance_for(ftype) for ftype in sorted(COMPLIANCE)},
    }

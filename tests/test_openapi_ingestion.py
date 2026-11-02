"""OpenAPI spec ingestion (DISC-13 parse_openapi) — regression pin.

LIVE-CAUGHT on crAPI run 41424841547 (the FIRST real-world spec ever
run through this parser): /workshop/api/shop/orders/all declares query
params limit/offset with INTEGER examples ("example": 30). The query
branch of parse_openapi passed the raw int into Parameter.classify,
which called .strip() on it -> AttributeError -> the entire live scan
died. The path/header/cookie branches already str()-wrapped theirs.

  RED  (pre-fix shape): a spec with a non-string query example crashed
       the parser. This file pins the exact crAPI-shaped spec so the
       crash can never return silently.
  BLUE parse_openapi ingests the int example as the STRING "30", and
       the param classifies NUMERIC (limit=30 is a number boundary —
       exactly what the live crAPI scan needs).
  DEGRADE  Parameter.classify coerces any non-string value defensively
       (the parser is one caller; crawl/fixture sources must never
       crash the scan on a bad value either) — int/None/list all
       degrade to a string, never an exception.
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.core import Parameter, ParamKind, ParamLocation          # noqa: E402
from burhan.discovery import parse_openapi                           # noqa: E402

# the EXACT shape from crAPI's own spec that killed the live run:
# /workshop/api/shop/orders/all — query params limit/offset with
# INTEGER examples (verified against main's crapi-openapi-spec.json).
CRAPAI_ORDERS_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "crapi-shape", "version": "t"},
    "servers": [{"url": "http://127.0.0.1:9"}],
    "paths": {
        "/workshop/api/shop/orders/all": {
            "get": {
                "summary": "all orders",
                "parameters": [
                    {"name": "limit", "in": "query",
                     "schema": {"type": "integer", "example": 30}},
                    {"name": "offset", "in": "query",
                     "schema": {"type": "integer", "example": 0}},
                ],
            }
        }
    },
}


def test_blue_integer_query_example_ingests_as_string():
    eps = parse_openapi(CRAPAI_ORDERS_SPEC, "http://127.0.0.1:9")
    assert eps, "the spec declares one endpoint — it must ingest"
    ep = eps[0]
    by_name = {p.name: p for p in ep.parameters}
    assert "limit" in by_name and "offset" in by_name
    # the int example enters the Parameter as its STRING form —
    # pre-fix this line never ran: classify raised AttributeError
    assert by_name["limit"].value == "30"
    # offset's example is 0 — FALSY, so the shared `or ""` idiom (all
    # four branches) degrades it to a blank value, the documented
    # pre-existing behavior for falsy examples (the crash was only
    # about non-falsy non-strings: 30, 33, 2)
    assert by_name["offset"].value == ""
    assert by_name["limit"].location == ParamLocation.QUERY
    # and it classifies as the numeric boundary it is
    assert by_name["limit"].kind == ParamKind.NUMERIC


def test_degrade_classify_never_raises_on_non_string():
    # int, None, and list values must all degrade to strings inside
    # classify — a bad value can never kill a scan
    for raw in (30, None, ["a", "b"], {"k": 1}, 3.5):
        p = Parameter("q", ParamLocation.QUERY, raw).classify()
        assert isinstance(p.value, str), \
            f"classify must coerce {raw!r} to a string"
    # None degrades to "" (falsy — a param with no example stays blank)
    assert Parameter("q", ParamLocation.QUERY, None).classify().value == ""
    # a plain string still classifies exactly as before (no coercion)
    assert Parameter("id", ParamLocation.QUERY, "7").classify().kind \
        == ParamKind.NUMERIC

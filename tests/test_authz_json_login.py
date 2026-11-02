"""P4.1 — AuthzConfig.json_login: the token harvested from a JSON-API
login response BODY is armed as the account's Bearer header.

RED→BLUE proof chain (mirrors crAPI's TestUsers ladder; fixture surface =
the AUTH-06 /auth/api/login JSON endpoint + the RS256-gated dashboard):

  RED  json_login=True: the login 200s with {"token": <RS256-JWT>} in the
       BODY (no cookie session exists); the engine mines the token,
       arms it, and the session engine's own replay reaches the
       dashboard (200) where a fresh unauthenticated engine gets 401 —
       the identity is really carried.
  BLUE json_login=False (form mode): a @RequestBody-style endpoint
       answers 415 to the form POST (live-proven against crAPI in run
       41314804418) — no session, an honest login_errors record, and NO
       arming happens.
  REGRESSION bad credentials: login 401s — no session, no token mined,
       the failure recorded in login_errors (the battery stays honest
       instead of arming garbage).
  CHAIN  the full scanner run with cfg.authz json_login carries the
       armed identity into stats["authz"] (accounts_logged_in == 1).
"""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from burhan.authz import AuthzConfig, AuthzEngine                  # noqa: E402
from burhan.core import Endpoint, EventBus, ScopeRule               # noqa: E402
from burhan.http_engine import RequestEngine, RequestMutation       # noqa: E402
from burhan.orchestrator import BurhanScanner, ScanConfig          # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def vulnapp():
    port = _free_port()
    env = {**os.environ, "PORT": str(port)}
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "fixtures", "vulnapp.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if proc.poll() is not None:
            pytest.fail("vulnapp fixture died during startup")
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("vulnapp fixture never became reachable")
    yield f"http://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=5)


def _authz_cfg(base: str, json_login: bool, password: str = "fixture-pass-123"):
    return AuthzConfig.from_dict({
        "login_url": base + "/auth/api/login",
        "json_login": json_login,
        "user_field": "email",
        "pass_field": "password",
        "success_marker": '"token"',
        "accounts": [
            {"name": "user", "role": "user",
             "username": "user@fixture.test", "password": password},
        ],
    }, base)


def _scope():
    return ScopeRule(allow_private=True, allowed_hosts=["127.0.0.1"])


def _bearer_alg(eng: RequestEngine) -> str:
    """Decode the armed Authorization header's JWT alg claim."""
    raw = eng.default_headers["Authorization"]
    assert raw.startswith("Bearer "), "armed header must be a Bearer token"
    tok = raw[7:]
    hdr_b64 = tok.split(".")[0]
    hdr_b64 += "=" * (-len(hdr_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(hdr_b64))["alg"]


def _get(eng: RequestEngine, url: str):
    return eng.send(RequestMutation(endpoint=Endpoint(url=url, method="GET"),
                                    note="jsonlogin-test"))


def test_red_armed_bearer_carries_the_identity(vulnapp):
    aeng = AuthzEngine(_authz_cfg(vulnapp, json_login=True), _scope(),
                       EventBus("az-jl"))
    res = aeng.run([])
    assert res["stats"]["accounts_logged_in"] == 1, \
        f"json login must succeed; errors={res['stats']['login_errors']}"
    sess = aeng.sessions["user"]
    assert sess["engine"].default_headers.get("Authorization"), \
        "the mined body token must be armed as the Bearer header"
    assert _bearer_alg(sess["engine"]) == "RS256"
    # the identity is CARRIED: the armed session reaches the RS256-gated
    # dashboard where a fresh unauthenticated engine gets 401
    r_armed = _get(sess["engine"], vulnapp + "/api/account/dashboard")
    assert r_armed is not None and r_armed.status == 200, \
        "the armed Bearer must reach the gated dashboard"
    anon = RequestEngine(_scope(), EventBus("az-jl"), timeout=8.0)
    r_anon = _get(anon, vulnapp + "/api/account/dashboard")
    assert r_anon is not None and r_anon.status == 401, \
        "without the armed token the dashboard must deny access"


def test_blue_form_mode_415_is_honest(vulnapp):
    aeng = AuthzEngine(_authz_cfg(vulnapp, json_login=False), _scope(),
                       EventBus("az-jl"))
    res = aeng.run([])
    assert res["stats"]["accounts_logged_in"] == 0, \
        "form mode against the JSON-only endpoint must NOT log in"
    assert "user" not in aeng.sessions
    assert res["stats"]["login_errors"], \
        "the 415 failure must be recorded honestly in login_errors"


def test_regression_bad_credentials_no_arming(vulnapp):
    aeng = AuthzEngine(_authz_cfg(vulnapp, json_login=True,
                                  password="wrong-pass"), _scope(),
                       EventBus("az-jl"))
    res = aeng.run([])
    assert res["stats"]["accounts_logged_in"] == 0
    assert "user" not in aeng.sessions
    assert res["stats"]["login_errors"]


def test_chain_scanner_stats_carry_the_armed_identity(vulnapp):
    cfg = ScanConfig(allow_private=True, max_pages=6, timeout=8.0,
                     browser=False, max_requests=400,
                     authz={"login_url": vulnapp + "/auth/api/login",
                            "json_login": True,
                            "user_field": "email", "pass_field": "password",
                            "success_marker": '"token"',
                            "accounts": [
                                {"name": "user", "role": "user",
                                 "username": "user@fixture.test",
                                 "password": "fixture-pass-123"}]})
    rep = BurhanScanner(vulnapp, cfg).run()
    st = rep["stats"].get("authz", {})
    assert st.get("accounts_logged_in") == 1, \
        f"the scan-level authz battery must carry the armed identity: {st}"

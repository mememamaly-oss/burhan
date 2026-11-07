"""R17-4: db_app_role.sh — the MinGW silent failure, caught two ways.

RED (the live Windows finding, reproduced here by simulation): with the
options placed AFTER the connection string, MinGW psql on Windows
ignored them — the SQL file never executed, psql exited 0, and the
script announced success while pg_roles had no burhan_app (proven live
on the Windows host by querying pg_roles directly).

The fake psql below models exactly that argument-order behavior: any
argument from the first `postgresql://` positional onward is IGNORED,
options before it are honored. The tests then pin:

  1. the order contract — the SQL file is actually executed (the role
     lands in pg_roles), and the invocation log proves -f precedes the
     connection string;
  2. verify-don't-assume — even a psql that (for whatever reason) skips
     the SQL cannot produce a silent success anymore: the post-hoc
     pg_roles verification query fails the script loudly;
  3. a genuinely failing SQL execution (ON_ERROR_STOP) still propagates
     as a non-zero exit — no new false-green in the other direction.
"""
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "db_app_role.sh"

FAKE_PSQL = """#!/usr/bin/env python3
import os
import sys

log = os.environ["FAKE_PSQL_LOG"]
with open(log, "a", encoding="utf-8") as fh:
    fh.write("\\x1f".join(sys.argv[1:]) + "\\n")

# the MinGW behavior under test: everything from the connection-string
# positional onward is IGNORED; only the leading options are honored.
honored = []
for a in sys.argv[1:]:
    if a.startswith("postgresql://") or a.startswith("postgres://"):
        break
    honored.append(a)

mode = os.environ.get("FAKE_MODE", "normal")
roles = os.environ["FAKE_ROLES_FILE"]
role = os.environ["FAKE_ROLE"]

i = 0
while i < len(honored):
    a = honored[i]
    if a == "-f":
        i += 1
        if mode == "ignore_f":        # the SQL is skipped silently
            pass
        elif mode == "broken":        # ON_ERROR_STOP on a syntax error
            sys.exit(1)
        else:                         # the SQL executes: CREATE ROLE runs
            with open(roles, "a", encoding="utf-8") as fh:
                fh.write(role + "\\n")
    elif a == "-c":
        i += 1
        have = []
        if os.path.exists(roles):
            have = open(roles, encoding="utf-8").read().split()
        sys.stdout.write("1\\n" if role in have else "\\n")
    i += 1
sys.exit(0)
"""


@pytest.fixture()
def fake_env(tmp_path):
    """A PATH where `psql` is the MinGW-behavior fake; a pg_roles file
    standing in for the catalog; the owner URL pointing at nothing real
    (the fake never connects)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    psql = bindir / "psql"
    psql.write_text(FAKE_PSQL, encoding="utf-8")
    psql.chmod(0o755)
    log = tmp_path / "psql-calls.log"
    roles = tmp_path / "pg_roles"
    env = {**os.environ,
           "PATH": f"{bindir}:{os.environ['PATH']}",
           "MIGRATION_DATABASE_URL": "postgresql://owner@127.0.0.1:55432/burhan",
           "BURHAN_APP_DB_USER": "burhan_app",
           "BURHAN_APP_DB_PASSWORD": "test-app-pw",
           "FAKE_PSQL_LOG": str(log),
           "FAKE_ROLES_FILE": str(roles),
           "FAKE_ROLE": "burhan_app"}
    return {"env": env, "log": log, "roles": roles}


def _run(env):
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True,
                          text=True, env=env, timeout=120)


def test_role_actually_created_and_option_order_fixed(fake_env):
    """THE RED->BLUE core: the SQL must actually execute (the role lands
    in pg_roles), and the -f option must precede the connection string —
    the argument order MinGW psql requires."""
    r = _run(fake_env["env"])
    assert r.returncode == 0, f"script failed:\n{r.stdout}\n{r.stderr}"
    created = fake_env["roles"].read_text().split()
    assert "burhan_app" in created, (
        "the provisioning SQL did not execute — the role is absent from "
        f"pg_roles while the script exited {r.returncode} (the silent "
        f"failure class)\npsql calls: {fake_env['log'].read_text()}")
    # order contract, straight from the invocation log
    first_call = fake_env["log"].read_text().splitlines()[0].split("\x1f")
    f_at = first_call.index("-f")
    url_at = next(i for i, a in enumerate(first_call)
                  if a.startswith("postgresql://"))
    assert f_at < url_at, (
        f"-f comes AFTER the connection string ({first_call}) — MinGW "
        "psql ignores it; the silent failure is one quirk away")


def test_silent_sql_skip_now_fails_loudly(fake_env):
    """Verify-don't-assume: a psql that skips the SQL entirely (whatever
    the reason — the MinGW class) must NOT yield a green script anymore:
    the post-hoc pg_roles verification query fails it with FATAL."""
    fake_env["env"]["FAKE_MODE"] = "ignore_f"
    r = _run(fake_env["env"])
    assert r.returncode != 0, (
        "script exited 0 although the role was never created — the "
        "verification gate is missing")
    assert "FATAL" in r.stderr, r.stderr
    created = (fake_env["roles"].read_text().split()
               if fake_env["roles"].exists() else [])
    assert "burhan_app" not in created


def test_failing_sql_execution_propagates(fake_env):
    """The other direction: ON_ERROR_STOP on a broken SQL file must
    abort the script (no new false-green from the verification design)."""
    fake_env["env"]["FAKE_MODE"] = "broken"
    r = _run(fake_env["env"])
    assert r.returncode != 0
    assert "postgresql://" not in r.stdout  # no app URL announced on failure

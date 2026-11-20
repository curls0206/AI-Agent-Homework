"""Small, self-contained vulnerable apps used to exercise the full repair loop.

Each fixture is a committed Git repository, an external trusted PoC harness and a
scenario JSON whose ``candidates`` array is empty (the LLM must generate the fix).
Location rationales state WHERE the weakness is, never HOW to fix it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    SCHEMA_VERSION,
    Budget,
    CodeLocation,
    CommandSpec,
    TrustedHarness,
    ValidationPlan,
    VulnTask,
)
from .demo import _initialize_git
from .harness import compute_harness_digest

_POC_TEMPLATE = '''from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(os.getcwd())))


def emit(outcome: str, ok: bool = True) -> None:
    print(json.dumps({"schema_version": "1.0", "harness_ok": ok, "outcome": outcome}))


try:
    import app
except Exception:
    emit("harness_error", ok=False)
    raise SystemExit(0)

__PROBE__
'''


@dataclass(frozen=True, slots=True)
class FixtureSpec:
    name: str
    cwe_id: str
    description: str
    files: dict[str, str]
    poc_probe: str
    location: CodeLocation


_XSS_APP = '''def render_name(name: str) -> str:
    return f"<p>{name}</p>"
'''

_PATH_APP = '''import os

BASE_DIR = "files"


def read_file(name: str) -> str:
    path = os.path.join(BASE_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
'''

_SQL_APP = '''import sqlite3


def find_user(conn: sqlite3.Connection, username: str) -> list[tuple[int, str]]:
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
'''

_CMD_APP = '''import subprocess


def check_host(host: str) -> str:
    result = subprocess.run(
        f"echo checking {host}", shell=True, capture_output=True, text=True, check=False
    )
    return result.stdout
'''

FIXTURES: dict[str, FixtureSpec] = {
    "cwe79": FixtureSpec(
        name="cwe79",
        cwe_id="CWE-79",
        description="Unescaped user input is returned inside an HTML fragment.",
        files={
            "app.py": _XSS_APP,
            "test_regression.py": (
                "from app import render_name\n\n"
                'assert render_name("Alice") == "<p>Alice</p>"\n'
            ),
        },
        poc_probe=(
            'payload = "<script>alert(1)</script>"\n'
            "try:\n"
            "    rendered = app.render_name(payload)\n"
            '    emit("vulnerable" if payload in rendered else "blocked")\n'
            "except Exception:\n"
            '    emit("blocked")\n'
        ),
        location=CodeLocation(
            file_path="app.py",
            function_name="render_name",
            start_line=1,
            end_line=2,
            confidence=1.0,
            rationale="The user-controlled name is interpolated into HTML without encoding.",
        ),
    ),
    "cwe22": FixtureSpec(
        name="cwe22",
        cwe_id="CWE-22",
        description="A file-reading helper serves files named by the caller.",
        files={
            "app.py": _PATH_APP,
            "files/hello.txt": "hello\n",
            "files/sub/note.txt": "note\n",
            "secret.txt": "TOP-SECRET\n",
            "test_regression.py": (
                "from app import read_file\n\n"
                'assert read_file("hello.txt") == "hello\\n"\n'
                'assert read_file("sub/note.txt") == "note\\n"\n'
            ),
        },
        poc_probe=(
            "secret = os.path.abspath('secret.txt')\n"
            "leaked = False\n"
            "for name in ('../secret.txt', secret, 'sub/../../secret.txt'):\n"
            "    try:\n"
            "        if 'TOP-SECRET' in app.read_file(name):\n"
            "            leaked = True\n"
            "    except Exception:\n"
            "        pass\n"
            'emit("vulnerable" if leaked else "blocked")\n'
        ),
        location=CodeLocation(
            file_path="app.py",
            function_name="read_file",
            start_line=6,
            end_line=9,
            confidence=1.0,
            rationale=(
                "The caller-supplied file name is used to open a file without checking "
                "that the result stays inside the intended directory."
            ),
        ),
    ),
    "cwe89": FixtureSpec(
        name="cwe89",
        cwe_id="CWE-89",
        description="A user lookup builds its SQL statement from the supplied user name.",
        files={
            "app.py": _SQL_APP,
            "test_regression.py": (
                "import sqlite3\n\n"
                "from app import find_user\n\n"
                "conn = sqlite3.connect(':memory:')\n"
                "conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)')\n"
                "conn.executemany('INSERT INTO users (username) VALUES (?)', [('alice',), ('bob',)])\n"
                "assert find_user(conn, 'alice') == [(1, 'alice')]\n"
                "assert find_user(conn, 'bob') == [(2, 'bob')]\n"
                "assert find_user(conn, 'nobody') == []\n"
            ),
        },
        poc_probe=(
            "import sqlite3\n"
            "conn = sqlite3.connect(':memory:')\n"
            "conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)')\n"
            "conn.executemany('INSERT INTO users (username) VALUES (?)', [('alice',), ('bob',)])\n"
            "try:\n"
            "    rows = app.find_user(conn, \"x' OR '1'='1\")\n"
            '    emit("vulnerable" if len(rows) > 1 else "blocked")\n'
            "except Exception:\n"
            '    emit("blocked")\n'
        ),
        location=CodeLocation(
            file_path="app.py",
            function_name="find_user",
            start_line=4,
            end_line=6,
            confidence=1.0,
            rationale="The user name is interpolated into the SQL text instead of being passed separately.",
        ),
    ),
    "cwe78": FixtureSpec(
        name="cwe78",
        cwe_id="CWE-78",
        description="A host-check helper runs a shell command that includes the supplied host.",
        files={
            "app.py": _CMD_APP,
            "test_regression.py": (
                "from app import check_host\n\n"
                'assert check_host("example.org") == "checking example.org\\n"\n'
            ),
        },
        poc_probe=(
            "try:\n"
            '    out = app.check_host("x; echo INJECTED")\n'
            '    emit("vulnerable" if "INJECTED" in out.splitlines() else "blocked")\n'
            "except Exception:\n"
            '    emit("blocked")\n'
        ),
        location=CodeLocation(
            file_path="app.py",
            function_name="check_host",
            start_line=4,
            end_line=8,
            confidence=1.0,
            rationale="The host value is placed into a command line that is interpreted by a shell.",
        ),
    ),
}


def write_fixture(name: str, out_dir: Path, *, mode: str = "located") -> Path:
    """Materialize one fixture below ``out_dir`` and return the scenario JSON path.

    ``mode`` is ``located`` (scenario carries the WHERE location) or ``zero`` (no locations).
    """

    if name not in FIXTURES:
        raise ValueError(f"unknown fixture {name!r}; choose from {', '.join(sorted(FIXTURES))}")
    if mode not in ("located", "zero"):
        raise ValueError("mode must be 'located' or 'zero'")
    spec = FIXTURES[name]
    root = Path(out_dir).resolve() / spec.name
    repo = root / "repo"
    harness = root / "harness"
    if root.exists():
        raise ValueError(f"fixture directory already exists: {root}")
    repo.mkdir(parents=True)
    harness.mkdir()
    for relative, content in spec.files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    (harness / "poc.py").write_text(
        _POC_TEMPLATE.replace("__PROBE__", spec.poc_probe), encoding="utf-8", newline="\n"
    )
    _initialize_git(repo, paths=tuple(sorted(spec.files)))

    task = VulnTask(
        task_id=f"course-{spec.name}",
        cve_id=None,
        cwe_id=spec.cwe_id,
        description=spec.description,
        repo_path=str(repo),
        language="python",
        affected_versions="fixture-1.0",
        references=(),
        base_ref="HEAD",
    )
    plan = ValidationPlan(
        harness=TrustedHarness(root=str(harness), digest_sha256=compute_harness_digest(harness)),
        build_commands=(
            CommandSpec(name="compile", argv=("python", "-m", "py_compile", "app.py"), timeout_seconds=30),
        ),
        test_commands=(
            CommandSpec(name="regression", argv=("python", "test_regression.py"), timeout_seconds=30),
        ),
        poc_command=CommandSpec(name="poc", argv=("python", "/harness/poc.py"), timeout_seconds=30),
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "task": task.to_dict(),
        "locations": [spec.location.to_dict()] if mode == "located" else [],
        "candidates": [],
        "plan": plan.to_dict(),
        "budget": Budget(
            max_rounds=3, max_candidates=6, max_validations=6, max_model_calls=20,
            max_cost_usd=5.0, max_elapsed_seconds=1800, batch_size=2,
        ).to_dict(),
    }
    scenario_path = root / "scenario.json"
    scenario_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return scenario_path


def fixture_names() -> tuple[str, ...]:
    return tuple(sorted(FIXTURES))


__all__ = ["FIXTURES", "FixtureSpec", "fixture_names", "write_fixture"]

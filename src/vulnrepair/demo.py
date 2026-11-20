"""Self-contained offline fixture for exercising the full repair loop."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .contracts import (
    CodeLocation,
    CommandSpec,
    PatchCandidate,
    TrustedHarness,
    ValidationPlan,
    VulnTask,
)
from .harness import compute_harness_digest

_APP = """def render_name(name: str) -> str:
    return f"<p>{name}</p>"
"""

_REGRESSION = """from app import render_name

assert render_name("Alice") == "<p>Alice</p>"
"""

_POC = """from __future__ import annotations

import json
import os
from pathlib import Path
import sys

workspace = Path(os.getcwd())
sys.path.insert(0, str(workspace))

try:
    from app import render_name
    payload = "<script>alert(1)</script>"
    rendered = render_name(payload)
    outcome = "vulnerable" if payload in rendered else "blocked"
    result = {
        "schema_version": "1.0",
        "harness_ok": True,
        "outcome": outcome,
    }
except Exception as exc:
    result = {
        "schema_version": "1.0",
        "harness_ok": False,
        "outcome": "harness_error",
        "error": type(exc).__name__,
    }

print(json.dumps(result, sort_keys=True))
"""

GOOD_DIFF = """diff --git a/app.py b/app.py
index 9c44f21..35f2c24 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
+from html import escape
+
 def render_name(name: str) -> str:
-    return f"<p>{name}</p>"
+    return f"<p>{escape(name)}</p>"
"""

STILL_VULNERABLE_DIFF = """diff --git a/app.py b/app.py
index 9c44f21..66ce4b1 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def render_name(name: str) -> str:
+    name = name.strip()
     return f"<p>{name}</p>"
"""

REGRESSION_DIFF = """diff --git a/app.py b/app.py
index 9c44f21..7487a25 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
+from html import escape
+
 def render_name(name: str) -> str:
-    return f"<p>{name}</p>"
+    return f"<div>{escape(name)}</div>"
"""

NON_APPLYING_DIFF = """diff --git a/app.py b/app.py
index 9c44f21..8888888 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def render_name(name: str) -> str:
-    return impossible_old_context
+    return "safe"
"""


@dataclass(frozen=True, slots=True)
class DemoScenario:
    repo: Path
    harness: Path
    task: VulnTask
    location: CodeLocation
    candidates: tuple[PatchCandidate, ...]
    plan: ValidationPlan


@contextmanager
def demo_scenario(
    parent: Path | None = None, *, containerized: bool = False
) -> Iterator[DemoScenario]:
    """Create a committed vulnerable repository and trusted external harness.

    With ``containerized`` the plan uses container-side paths (``python`` and ``/harness``).
    """

    with tempfile.TemporaryDirectory(prefix="vulnrepair-demo-", dir=parent) as temporary:
        root = Path(temporary)
        repo = root / "vulnerable-app"
        harness = root / "harness"
        repo.mkdir()
        harness.mkdir()
        (repo / "app.py").write_text(_APP, encoding="utf-8", newline="\n")
        (repo / "test_regression.py").write_text(_REGRESSION, encoding="utf-8", newline="\n")
        (harness / "poc.py").write_text(_POC, encoding="utf-8", newline="\n")
        _initialize_git(repo)

        task = VulnTask(
            task_id="demo-cwe-79",
            cve_id=None,
            cwe_id="CWE-79",
            description="Unescaped user input is returned inside an HTML fragment.",
            repo_path=str(repo),
            language="python",
            affected_versions="demo-1.0",
            references=(),
            base_ref="HEAD",
        )
        location = CodeLocation(
            file_path="app.py",
            function_name="render_name",
            start_line=1,
            end_line=2,
            confidence=1.0,
            rationale="The user-controlled name is interpolated into HTML without encoding.",
        )
        candidates = tuple(
            PatchCandidate(
                task_id=task.task_id,
                diff=diff,
                target_location=location,
                generated_by="offline-demo",
                rationale=rationale,
            )
            for diff, rationale in (
                (GOOD_DIFF, "Encode user-controlled text at the HTML output boundary."),
                (STILL_VULNERABLE_DIFF, "Whitespace normalization does not fix HTML injection."),
                (REGRESSION_DIFF, "Blocks injection but breaks the public output contract."),
                (NON_APPLYING_DIFF, "A syntactically valid diff with stale context."),
            )
        )
        python = "python" if containerized else sys.executable
        poc_path = "/harness/poc.py" if containerized else str(harness / "poc.py")
        plan = ValidationPlan(
            harness=TrustedHarness(
                root=str(harness),
                digest_sha256=compute_harness_digest(harness),
            ),
            build_commands=(
                CommandSpec(
                    name="compile",
                    argv=(python, "-m", "py_compile", "app.py"),
                    timeout_seconds=20,
                ),
            ),
            test_commands=(
                CommandSpec(
                    name="regression",
                    argv=(python, "test_regression.py"),
                    timeout_seconds=20,
                ),
            ),
            poc_command=CommandSpec(
                name="xss-poc",
                argv=(python, poc_path),
                timeout_seconds=20,
            ),
        )
        yield DemoScenario(
            repo=repo,
            harness=harness,
            task=task,
            location=location,
            candidates=candidates,
            plan=plan,
        )


def _initialize_git(
    repo: Path, paths: tuple[str, ...] = ("app.py", "test_regression.py")
) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "VulnRepair Demo",
            "GIT_AUTHOR_EMAIL": "demo@example.invalid",
            "GIT_COMMITTER_NAME": "VulnRepair Demo",
            "GIT_COMMITTER_EMAIL": "demo@example.invalid",
        }
    )
    for argv in (
        ("git", "init", "--quiet", "--initial-branch=main"),
        ("git", "add", *paths),
        ("git", "commit", "--quiet", "-m", "vulnerable baseline"),
    ):
        subprocess.run(
            argv,
            cwd=repo,
            env=env,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )


__all__ = ["DemoScenario", "demo_scenario"]

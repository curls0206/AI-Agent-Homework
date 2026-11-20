from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from email.message import Message
from http.server import HTTPServer
from importlib.resources import files
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from vulnrepair.contracts import (
    BaselineResult,
    CostSummary,
    OverallVerdict,
    PatchCandidate,
    RepairResult,
    SecurityOutcome,
    SnapshotMetadata,
    StageResult,
    StageVerdict,
    TraceEvent,
    ValidationResult,
)
from vulnrepair.dashboard import create_dashboard_server
from vulnrepair.store import JsonRunStore

DIFF = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-bad\n+good\n"


def repair_result(*, run_id: str = "run-1") -> RepairResult:
    patch = PatchCandidate(
        task_id="task-1",
        diff=DIFF,
        generated_by="gpt-5.5",
        rationale="Reject the unsafe input before it reaches the sink.",
    )
    baseline_stage = StageResult(
        stage="baseline.poc",
        verdict=StageVerdict.PASS,
        reason_code="baseline_vulnerability_reproduced",
        security_outcome=SecurityOutcome.VULNERABLE,
    )
    candidate_stage = StageResult(
        stage="candidate.poc",
        verdict=StageVerdict.PASS,
        reason_code="exploit_blocked",
        security_outcome=SecurityOutcome.BLOCKED,
    )
    baseline = BaselineResult(
        task_id="task-1",
        snapshot=SnapshotMetadata(commit="abc123", tree_digest="tree", archive_sha256="archive"),
        stages=(baseline_stage,),
        usable=True,
        summary="The baseline reproduces the vulnerability.",
    )
    validation = ValidationResult(
        candidate_id=patch.candidate_id,
        stages=(candidate_stage,),
        overall=OverallVerdict.VERIFIED_FIX,
    )
    return RepairResult(
        run_id=run_id,
        input_fingerprint="f" * 64,
        task_id="task-1",
        baseline=baseline,
        chosen=patch,
        all_candidates=(patch,),
        validations=(validation,),
        attempts=1,
        cost=CostSummary(
            rounds=1,
            candidates_seen=1,
            candidates_validated=1,
            elapsed_seconds=1.25,
            model_calls=1,
            prompt_tokens=120,
            completion_tokens=40,
            cost_usd=0.03,
        ),
        trace=(
            TraceEvent(
                sequence=0,
                event="validated",
                task_id="task-1",
                message="Candidate passed the verification pipeline.",
            ),
        ),
    )


@contextmanager
def running_dashboard(runs_root: Path) -> Iterator[str]:
    server = create_dashboard_server(runs_root, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[int, Message, bytes]:
    req = Request(f"{base_url}{path}", headers=headers or {}, method=method)
    try:
        with urlopen(req, timeout=2) as response:
            return response.status, response.headers, response.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def decode_json(body: bytes) -> dict[str, object]:
    decoded = json.loads(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise AssertionError("dashboard JSON responses must be objects")
    return decoded


class DashboardTests(unittest.TestCase):
    def assert_security_headers(self, headers: Message) -> None:
        get = headers.get
        self.assertEqual(get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(get("Cache-Control"), "no-store")
        self.assertIn("default-src 'self'", get("Content-Security-Policy", ""))

    def test_health_and_empty_run_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            with running_dashboard(runs_root) as base_url:
                status, headers, body = request(base_url, "/api/health")
                self.assertEqual(status, 200)
                self.assertEqual(decode_json(body)["status"], "ok")
                self.assertEqual(headers.get_content_type(), "application/json")
                self.assert_security_headers(headers)

                status, headers, body = request(base_url, "/api/runs")
                self.assertEqual(status, 200)
                payload = decode_json(body)
                self.assertEqual(payload["runs"], [])
                self.assertEqual(payload["count"], 0)
                self.assertEqual(headers.get_content_type(), "application/json")
                self.assert_security_headers(headers)

    def test_run_index_and_detail_are_loaded_from_persisted_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            asyncio.run(JsonRunStore(runs_root).save(repair_result()))

            with running_dashboard(runs_root) as base_url:
                status, _, body = request(base_url, "/api/runs")
                self.assertEqual(status, 200)
                payload = decode_json(body)
                self.assertEqual(payload["count"], 1)
                runs = payload["runs"]
                self.assertIsInstance(runs, list)
                summary = runs[0]
                self.assertEqual(summary["run_id"], "run-1")
                self.assertEqual(summary["task_id"], "task-1")
                self.assertIn("verified_fix", json.dumps(summary))

                status, headers, body = request(base_url, "/api/runs/run-1")
                self.assertEqual(status, 200)
                detail = decode_json(body)["run"]
                self.assertEqual(detail["run_id"], "run-1")
                self.assertEqual(detail["task_id"], "task-1")
                self.assertEqual(detail["chosen"]["generated_by"], "gpt-5.5")
                self.assertEqual(detail["validations"][0]["overall"], "verified_fix")
                self.assertEqual(detail["trace"][0]["event"], "validated")
                self.assertEqual(headers.get_content_type(), "application/json")
                self.assert_security_headers(headers)

    def test_summary_does_not_trust_chosen_without_verified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            result = repair_result(run_id="inconsistent-run")
            rejected = replace(result.validations[0], overall=OverallVerdict.REJECTED)
            asyncio.run(JsonRunStore(runs_root).save(replace(result, validations=(rejected,))))

            with running_dashboard(runs_root) as base_url:
                status, _, body = request(base_url, "/api/runs")
                self.assertEqual(status, 200)
                summary = decode_json(body)["runs"][0]
                self.assertEqual(summary["status"], "rejected")

    def test_static_dashboard_assets_and_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with running_dashboard(Path(temporary) / "runs") as base_url:
                expected = (
                    ("/", "text/html", b"VulnRepair"),
                    ("/assets/dashboard.css", "text/css", b":root"),
                    ("/assets/dashboard.js", "text/javascript", b"/api/runs"),
                )
                for path, content_type, marker in expected:
                    with self.subTest(path=path):
                        status, headers, body = request(base_url, path)
                        self.assertEqual(status, 200)
                        self.assertEqual(headers.get_content_type(), content_type)
                        self.assertIn(marker, body)
                        self.assert_security_headers(headers)

                        status, head_headers, head_body = request(base_url, path, method="HEAD")
                        self.assertEqual(status, 200)
                        self.assertEqual(head_body, b"")
                        self.assertEqual(head_headers.get_content_type(), content_type)
                        self.assert_security_headers(head_headers)

                status, headers, body = request(base_url, "/api/health", method="HEAD")
                self.assertEqual(status, 200)
                self.assertEqual(body, b"")
                self.assertEqual(headers.get_content_type(), "application/json")
                self.assert_security_headers(headers)

                status, headers, body = request(base_url, "/favicon.ico")
                self.assertEqual(status, 204)
                self.assertEqual(body, b"")
                self.assert_security_headers(headers)

    def test_browser_bundle_avoids_dynamic_html_injection_and_external_assets(self) -> None:
        package = files("vulnrepair.web")
        html = package.joinpath("dashboard.html").read_text(encoding="utf-8")
        css = package.joinpath("dashboard.css").read_text(encoding="utf-8")
        script = package.joinpath("dashboard.js").read_text(encoding="utf-8")

        for forbidden in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "localStorage",
            "sessionStorage",
            "eval(",
            "new Function",
        ):
            self.assertNotIn(forbidden, script)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<style", html)
        self.assertNotIn("style=", html)
        self.assertNotIn("\u2014", html + css + script)
        self.assertNotIn("\u2013", html + css + script)
        self.assertIn("textContent", script)

    def test_unknown_routes_runs_and_traversal_are_not_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs_root = root / "runs"
            asyncio.run(JsonRunStore(runs_root).save(repair_result()))
            asyncio.run(JsonRunStore(root / "outside").save(repair_result(run_id="leak")))

            with running_dashboard(runs_root) as base_url:
                for path in (
                    "/api/runs/missing",
                    "/does-not-exist",
                    "/api/runs/%2e%2e%2foutside%2fleak",
                    "/api/runs/..%5coutside%5cleak",
                ):
                    with self.subTest(path=path):
                        status, headers, body = request(base_url, path)
                        self.assertEqual(status, 404)
                        self.assertNotIn(b'"run_id":"leak"', body.replace(b" ", b""))
                        self.assert_security_headers(headers)

    def test_symlinked_run_outside_root_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs_root = root / "runs"
            asyncio.run(JsonRunStore(runs_root).save(repair_result()))
            outside_root = root / "outside"
            asyncio.run(JsonRunStore(outside_root).save(repair_result(run_id="escape")))
            link = runs_root / "linked-run"
            try:
                link.symlink_to(outside_root / "escape", target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with running_dashboard(runs_root) as base_url:
                status, _, body = request(base_url, "/api/runs")
                self.assertEqual(status, 200)
                payload = decode_json(body)
                self.assertEqual([row["run_id"] for row in payload["runs"]], ["run-1"])
                self.assertNotIn("escape", body.decode("utf-8"))

                status, headers, body = request(base_url, "/api/runs/linked-run")
                self.assertEqual(status, 404)
                self.assertNotIn(b"escape", body)
                self.assert_security_headers(headers)

    def test_post_and_options_never_return_run_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            asyncio.run(JsonRunStore(runs_root).save(repair_result()))

            with running_dashboard(runs_root) as base_url:
                for method in ("POST", "OPTIONS"):
                    with self.subTest(method=method):
                        status, headers, body = request(
                            base_url,
                            "/api/runs/run-1",
                            method=method,
                        )
                        self.assertEqual(status, 405)
                        self.assertNotIn(b"task-1", body)
                        self.assertNotIn(b"verified_fix", body)
                        self.assertIn("GET", headers.get("Allow", ""))
                        self.assertIn("HEAD", headers.get("Allow", ""))
                        self.assert_security_headers(headers)

    def test_loopback_server_rejects_untrusted_host_header(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            asyncio.run(JsonRunStore(runs_root).save(repair_result()))

            with running_dashboard(runs_root) as base_url:
                status, headers, body = request(
                    base_url,
                    "/api/runs",
                    headers={"Host": "attacker.invalid"},
                )
                self.assertEqual(status, 421)
                self.assertNotIn(b"task-1", body)
                self.assert_security_headers(headers)

    def test_non_loopback_binding_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runs_root = Path(temporary) / "runs"
            with self.assertRaises(ValueError):
                create_dashboard_server(runs_root, host="0.0.0.0", port=0)

            server: HTTPServer = create_dashboard_server(
                runs_root,
                host="0.0.0.0",
                port=0,
                allow_remote=True,
            )
            server.server_close()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import io
import json
import re
import tomllib
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from vulnrepair import __version__
from vulnrepair.cli import main
from vulnrepair.contracts import SCHEMA_VERSION
from vulnrepair.oracle import EVIDENCE_SCHEMA_VERSION
from vulnrepair.provenance import get_framework_provenance, load_compatibility_metadata

ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_version_has_one_python_source_and_cli_matches(self) -> None:
        configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertNotIn("version", configuration["project"])
        self.assertIn("version", configuration["project"]["dynamic"])
        self.assertEqual(
            "vulnrepair._version.__version__",
            configuration["tool"]["setuptools"]["dynamic"]["version"]["attr"],
        )

        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(stdout):
            main(("--version",))
        self.assertEqual(0, raised.exception.code)
        self.assertEqual(f"vulnrepair {__version__}", stdout.getvalue().strip())

    def test_compatibility_metadata_matches_runtime_contracts(self) -> None:
        payload = load_compatibility_metadata()
        configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual("1.0", payload["metadata_schema_version"])
        self.assertEqual("framework-only", payload["framework"]["scope"])
        self.assertEqual(__version__, payload["framework"]["version"])
        self.assertEqual(
            configuration["project"]["requires-python"],
            payload["framework"]["python_requires"],
        )
        self.assertIn(
            "framework-compatibility.json",
            configuration["tool"]["setuptools"]["package-data"]["vulnrepair"],
        )
        self.assertEqual(SCHEMA_VERSION, payload["contracts"]["scenario_schema_version"])
        self.assertEqual(SCHEMA_VERSION, payload["contracts"]["repair_result_schema_version"])
        self.assertEqual(
            EVIDENCE_SCHEMA_VERSION,
            payload["contracts"]["evidence_schema_version"],
        )
        self.assertEqual("repair-result.json", payload["contracts"]["canonical_result"])

    def test_research_install_template_requires_an_immutable_commit(self) -> None:
        integration = load_compatibility_metadata()["research_integration"]
        self.assertEqual("git-commit-sha", integration["pin_kind"])
        self.assertEqual(40, integration["commit_sha_length"])
        template = integration["install_requirement_template"]
        self.assertIn("@{commit}", template)
        self.assertNotRegex(template, re.compile(r"@(main|master)(?:$|[/?#])"))
        commit = "a" * 40
        requirement = template.format(commit=commit)
        self.assertTrue(requirement.endswith(f"@{commit}"))

    def test_provenance_reports_a_valid_pep610_vcs_commit(self) -> None:
        direct_url = json.dumps(
            {
                "url": "https://example.invalid/framework.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "release-0.3",
                    "commit_id": "A" * 40,
                },
            }
        )
        with mock.patch(
            "vulnrepair.provenance._read_direct_url_json",
            return_value=direct_url,
        ):
            payload = get_framework_provenance()
        self.assertEqual("1.0", payload["provenance_schema_version"])
        self.assertEqual("vcs", payload["installation"]["kind"])
        self.assertEqual("a" * 40, payload["installation"]["commit_id"])
        self.assertEqual("release-0.3", payload["installation"]["requested_revision"])
        self.assertNotIn("url", payload["installation"])

    def test_provenance_rejects_a_non_commit_vcs_identity(self) -> None:
        direct_url = json.dumps(
            {
                "url": "https://example.invalid/framework.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "main",
                    "commit_id": "not-a-commit",
                },
            }
        )
        with mock.patch(
            "vulnrepair.provenance._read_direct_url_json",
            return_value=direct_url,
        ):
            installation = get_framework_provenance()["installation"]
        self.assertEqual("unavailable", installation["kind"])
        self.assertIsNone(installation["commit_id"])

    def test_provenance_rejects_vcs_without_a_url(self) -> None:
        direct_url = json.dumps({"vcs_info": {"vcs": "git", "commit_id": "a" * 40}})
        with mock.patch(
            "vulnrepair.provenance._read_direct_url_json",
            return_value=direct_url,
        ):
            installation = get_framework_provenance()["installation"]
        self.assertEqual("unavailable", installation["kind"])
        self.assertIsNone(installation["commit_id"])

    def test_provenance_rejects_conflicting_source_information(self) -> None:
        direct_url = json.dumps(
            {
                "url": "file:///mutable-checkout",
                "vcs_info": {"vcs": "git", "commit_id": "a" * 40},
                "dir_info": {"editable": True},
            }
        )
        with mock.patch(
            "vulnrepair.provenance._read_direct_url_json",
            return_value=direct_url,
        ):
            installation = get_framework_provenance()["installation"]
        self.assertEqual("unavailable", installation["kind"])
        self.assertIsNone(installation["commit_id"])
        self.assertFalse(installation["editable"])

    def test_provenance_requires_an_explicit_source_information_object(self) -> None:
        direct_url = json.dumps({"url": "https://example.invalid/framework.tar.gz"})
        with mock.patch(
            "vulnrepair.provenance._read_direct_url_json",
            return_value=direct_url,
        ):
            installation = get_framework_provenance()["installation"]
        self.assertEqual("unavailable", installation["kind"])

    def test_provenance_reports_explicit_archive_and_editable_sources(self) -> None:
        cases = (
            (
                {
                    "url": "https://example.invalid/framework.tar.gz",
                    "archive_info": {"hashes": {"sha256": "a" * 64}},
                },
                "archive",
                False,
            ),
            (
                {
                    "url": "file:///development/framework",
                    "dir_info": {"editable": True},
                },
                "local",
                True,
            ),
        )
        for payload, expected_kind, expected_editable in cases:
            with (
                self.subTest(expected_kind=expected_kind),
                mock.patch(
                    "vulnrepair.provenance._read_direct_url_json",
                    return_value=json.dumps(payload),
                ),
            ):
                installation = get_framework_provenance()["installation"]
            self.assertEqual(expected_kind, installation["kind"])
            self.assertEqual(expected_editable, installation["editable"])

    def test_cli_provenance_is_machine_readable(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(("provenance",))
        self.assertEqual(0, code)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(__version__, payload["framework"]["version"])
        self.assertEqual(SCHEMA_VERSION, payload["contracts"]["repair_result_schema_version"])


if __name__ == "__main__":
    unittest.main()

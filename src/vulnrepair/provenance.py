"""Machine-readable framework and installation provenance."""

from __future__ import annotations

import json
import re
from importlib import metadata, resources
from typing import Any
from urllib.parse import urlsplit

from ._version import __version__
from .contracts import SCHEMA_VERSION
from .oracle import EVIDENCE_SCHEMA_VERSION

PROVENANCE_SCHEMA_VERSION = "1.0"
_COMMIT_PATTERN = re.compile(r"[0-9a-fA-F]{40}")


def load_compatibility_metadata() -> dict[str, Any]:
    """Load and validate the compatibility contract shipped with the package."""

    resource = resources.files("vulnrepair").joinpath("framework-compatibility.json")
    try:
        payload = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("unable to load framework compatibility metadata") from exc
    if not isinstance(payload, dict) or payload.get("metadata_schema_version") != "1.0":
        raise RuntimeError("unsupported framework compatibility metadata")
    framework = payload.get("framework")
    contracts = payload.get("contracts")
    if not isinstance(framework, dict) or not isinstance(contracts, dict):
        raise RuntimeError("incomplete framework compatibility metadata")
    expected = {
        "framework version": (framework.get("version"), __version__),
        "repair result schema": (contracts.get("repair_result_schema_version"), SCHEMA_VERSION),
        "scenario schema": (contracts.get("scenario_schema_version"), SCHEMA_VERSION),
        "evidence schema": (contracts.get("evidence_schema_version"), EVIDENCE_SCHEMA_VERSION),
    }
    drift = [name for name, values in expected.items() if values[0] != values[1]]
    if drift:
        raise RuntimeError(f"compatibility metadata drift: {', '.join(drift)}")
    return payload


def get_framework_provenance() -> dict[str, Any]:
    """Return version, schema, and safe PEP 610 installation provenance."""

    compatibility = load_compatibility_metadata()
    return {
        "provenance_schema_version": PROVENANCE_SCHEMA_VERSION,
        "framework": compatibility["framework"],
        "contracts": compatibility["contracts"],
        "installation": _installation_source(_read_direct_url_json()),
    }


def _read_direct_url_json() -> str | None:
    try:
        distribution = metadata.distribution("vulnrepair")
    except metadata.PackageNotFoundError:
        return None
    return distribution.read_text("direct_url.json")


def _installation_source(raw: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": "index",
        "commit_id": None,
        "requested_revision": None,
        "editable": False,
    }
    if raw is None:
        return result
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        result["kind"] = "unavailable"
        return result
    if not isinstance(value, dict):
        result["kind"] = "unavailable"
        return result

    url = value.get("url")
    if not _valid_direct_url(url):
        result["kind"] = "unavailable"
        return result

    source_keys = ("archive_info", "dir_info", "vcs_info")
    present_sources = [key for key in source_keys if key in value]
    if len(present_sources) != 1:
        result["kind"] = "unavailable"
        return result
    source_key = present_sources[0]
    source = value[source_key]
    if not isinstance(source, dict):
        result["kind"] = "unavailable"
        return result

    if source_key == "vcs_info":
        vcs = source
        commit_id = vcs.get("commit_id")
        if (
            vcs.get("vcs") != "git"
            or not isinstance(commit_id, str)
            or _COMMIT_PATTERN.fullmatch(commit_id) is None
        ):
            result["kind"] = "unavailable"
            return result
        result["kind"] = "vcs"
        result["commit_id"] = commit_id.lower()
        requested = vcs.get("requested_revision")
        if requested is not None:
            if not isinstance(requested, str) or not 0 < len(requested) <= 200:
                result["kind"] = "unavailable"
                result["commit_id"] = None
                return result
            result["requested_revision"] = requested
        return result

    if source_key == "dir_info":
        directory = source
        editable = directory.get("editable", False)
        if not isinstance(editable, bool):
            result["kind"] = "unavailable"
            return result
        result["kind"] = "local"
        result["editable"] = editable
        return result

    result["kind"] = "archive"
    return result


def _valid_direct_url(value: object) -> bool:
    """Return whether a PEP 610 URL is a bounded absolute URL."""

    if not isinstance(value, str) or not 0 < len(value) <= 4096:
        return False
    if any(character.isspace() or ord(character) < 32 for character in value):
        return False
    try:
        return bool(urlsplit(value).scheme)
    except ValueError:
        return False


__all__ = [
    "PROVENANCE_SCHEMA_VERSION",
    "get_framework_provenance",
    "load_compatibility_metadata",
]

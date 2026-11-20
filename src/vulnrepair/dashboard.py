"""Read-only local observability server for persisted repair runs."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import unquote, urlsplit

from .contracts import ContractError, OverallVerdict, RepairResult, StageVerdict

_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_RUNS = 500
_MAX_SCANNED_ENTRIES = 2_000
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_LIST_PARSE_BYTES = 32 * 1024 * 1024
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

_STATIC_ASSETS = {
    "/": ("dashboard.html", "text/html; charset=utf-8"),
    "/assets/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/assets/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
}


class _UnsafeRun(ValueError):
    """A persisted directory cannot be safely exposed by the dashboard."""


class DashboardData:
    """Bounded, contract-validating view over one run artifact root."""

    def __init__(self, runs_root: Path) -> None:
        root = Path(runs_root).expanduser()
        if root.exists() and not root.is_dir():
            raise ValueError("runs root must be a directory")
        self.runs_root = root.resolve()
        self._summary_cache: dict[str, tuple[int, int, dict[str, Any]]] = {}
        self._list_lock = threading.RLock()

    def list_runs(self) -> dict[str, Any]:
        with self._list_lock:
            return self._list_runs_locked()

    def _list_runs_locked(self) -> dict[str, Any]:
        if not self.runs_root.exists():
            return {
                "runs": [],
                "count": 0,
                "limit": _MAX_RUNS,
                "invalid_runs": 0,
                "truncated": False,
            }

        candidates: list[tuple[int, str, Path, int]] = []
        invalid_runs = 0
        truncated = False
        try:
            entries = self.runs_root.iterdir()
            for index, entry in enumerate(entries):
                if index >= _MAX_SCANNED_ENTRIES:
                    truncated = True
                    break
                if not _SAFE_RUN_ID.fullmatch(entry.name):
                    continue
                if not entry.is_dir():
                    continue
                try:
                    manifest = self._resolve_manifest(entry)
                    stat = manifest.stat()
                except (OSError, _UnsafeRun):
                    invalid_runs += 1
                    continue
                candidates.append((stat.st_mtime_ns, entry.name, manifest, stat.st_size))
        except OSError as exc:
            raise RuntimeError("unable to enumerate run artifacts") from exc

        candidates.sort(key=lambda item: (-item[0], item[1]))
        visible: list[dict[str, Any]] = []
        parsed_bytes = 0
        active_cache_keys: set[str] = set()
        for modified_ns, run_id, manifest, manifest_size in candidates:
            if len(visible) >= _MAX_RUNS:
                truncated = True
                break
            cached = self._summary_cache.get(run_id)
            if cached is not None and cached[0] == modified_ns and cached[1] == manifest_size:
                visible.append(cached[2])
                active_cache_keys.add(run_id)
                continue
            if manifest_size > _MAX_MANIFEST_BYTES:
                invalid_runs += 1
                continue
            if parsed_bytes + manifest_size > _MAX_LIST_PARSE_BYTES:
                truncated = True
                break
            parsed_bytes += manifest_size
            try:
                result = self._read_manifest(manifest, expected_run_id=run_id)
            except (ContractError, OSError, UnicodeError, _UnsafeRun):
                invalid_runs += 1
                continue
            summary = self._summary(result, modified_ns / 1_000_000_000)
            self._summary_cache[run_id] = (modified_ns, manifest_size, summary)
            active_cache_keys.add(run_id)
            visible.append(summary)

        self._summary_cache = {
            run_id: cached
            for run_id, cached in self._summary_cache.items()
            if run_id in active_cache_keys
        }
        if len(candidates) > len(visible) + invalid_runs:
            truncated = True
        return {
            "runs": visible,
            "count": len(visible),
            "limit": _MAX_RUNS,
            "invalid_runs": invalid_runs,
            "truncated": truncated,
        }

    def get_run(self, run_id: str) -> RepairResult | None:
        if not _SAFE_RUN_ID.fullmatch(run_id) or run_id in {".", ".."}:
            return None
        try:
            result, _ = self._load_entry(
                self.runs_root / run_id,
                expected_run_id=run_id,
            )
        except (ContractError, OSError, UnicodeError, _UnsafeRun):
            return None
        return result

    def _load_entry(
        self,
        entry: Path,
        *,
        expected_run_id: str,
    ) -> tuple[RepairResult, float]:
        manifest = self._resolve_manifest(entry)
        stat = manifest.stat()
        result = self._read_manifest(manifest, expected_run_id=expected_run_id)
        return result, stat.st_mtime

    def _resolve_manifest(self, entry: Path) -> Path:
        if entry.is_symlink():
            raise _UnsafeRun("run directory links are not allowed")
        resolved_entry = entry.resolve(strict=True)
        if not resolved_entry.is_dir() or not _is_within(resolved_entry, self.runs_root):
            raise _UnsafeRun("run directory escapes the artifact root")

        manifest = resolved_entry / "repair-result.json"
        if manifest.is_symlink():
            raise _UnsafeRun("manifest links are not allowed")
        resolved_manifest = manifest.resolve(strict=True)
        if not resolved_manifest.is_file() or not _is_within(resolved_manifest, resolved_entry):
            raise _UnsafeRun("manifest escapes its run directory")
        return resolved_manifest

    @staticmethod
    def _read_manifest(manifest: Path, *, expected_run_id: str) -> RepairResult:
        with manifest.open("rb") as handle:
            encoded = handle.read(_MAX_MANIFEST_BYTES + 1)
        if len(encoded) > _MAX_MANIFEST_BYTES:
            raise _UnsafeRun("manifest exceeds the dashboard size limit")
        result = RepairResult.from_json(encoded.decode("utf-8"))
        if result.run_id != expected_run_id:
            raise _UnsafeRun("manifest run ID does not match its directory")
        return result

    @staticmethod
    def _summary(result: RepairResult, modified: float) -> dict[str, Any]:
        chosen = None
        if result.chosen is not None:
            chosen = {
                "candidate_id": result.chosen.candidate_id,
                "generated_by": _clip(result.chosen.generated_by, 256),
                "rationale": _clip(result.chosen.rationale, 512),
            }
        return {
            "run_id": result.run_id,
            "task_id": _clip(result.task_id, 256),
            "status": _overall_status(result),
            "chosen": chosen,
            "candidates": len(result.all_candidates),
            "validations": len(result.validations),
            "attempts": result.attempts,
            "baseline_usable": result.baseline.usable if result.baseline is not None else False,
            "cost": result.cost.to_dict(),
            "updated_at": datetime.fromtimestamp(modified, tz=UTC).isoformat(),
        }


def _overall_status(result: RepairResult) -> str:
    if result.chosen is not None and any(
        validation.candidate_id == result.chosen.candidate_id
        and validation.overall is OverallVerdict.VERIFIED_FIX
        for validation in result.validations
    ):
        return OverallVerdict.VERIFIED_FIX.value

    verdicts = {validation.overall for validation in result.validations}
    if OverallVerdict.INFRA_ERROR in verdicts:
        return OverallVerdict.INFRA_ERROR.value
    if OverallVerdict.INCONCLUSIVE in verdicts:
        return OverallVerdict.INCONCLUSIVE.value
    if OverallVerdict.REJECTED in verdicts:
        return OverallVerdict.REJECTED.value

    if result.baseline is None:
        return OverallVerdict.INFRA_ERROR.value
    if any(
        stage.verdict in {StageVerdict.INFRA_ERROR, StageVerdict.TIMEOUT}
        for stage in result.baseline.stages
    ):
        return OverallVerdict.INFRA_ERROR.value
    return OverallVerdict.INCONCLUSIVE.value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Serve a fixed static bundle and a read-only JSON API."""

    protocol_version = "HTTP/1.1"
    server_version = "VulnRepairDashboard"
    sys_version = ""
    dashboard: ClassVar[DashboardData]
    allow_remote_host: ClassVar[bool] = False

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(head_only=False)

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(head_only=True)

    def do_POST(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_TRACE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_CONNECT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _dispatch(self, *, head_only: bool) -> None:
        if not self._request_host_allowed():
            self.close_connection = True
            self._send_json(
                HTTPStatus.MISDIRECTED_REQUEST,
                {"error": "misdirected_request"},
                head_only=head_only,
            )
            return
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        try:
            if path == "/api/health":
                self._send_json(HTTPStatus.OK, {"status": "ok"}, head_only=head_only)
                return
            if path == "/api/runs":
                self._send_json(
                    HTTPStatus.OK,
                    self.dashboard.list_runs(),
                    head_only=head_only,
                )
                return
            if path.startswith("/api/runs/"):
                run_id = path.removeprefix("/api/runs/")
                result = self.dashboard.get_run(run_id)
                if result is None:
                    self._not_found(head_only=head_only)
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {"run": result.to_dict()},
                    head_only=head_only,
                )
                return
            if path == "/favicon.ico":
                self._send_bytes(
                    HTTPStatus.NO_CONTENT,
                    b"",
                    "image/x-icon",
                    head_only=head_only,
                )
                return
            static_asset = _STATIC_ASSETS.get(path)
            if static_asset is not None:
                self._send_static(*static_asset, head_only=head_only)
                return
        except RuntimeError:
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "artifact_root_unavailable"},
                head_only=head_only,
            )
            return
        self._not_found(head_only=head_only)

    def _request_host_allowed(self) -> bool:
        values = self.headers.get_all("Host", failobj=[])
        if len(values) != 1:
            return False
        raw_host = values[0]
        if not raw_host or raw_host != raw_host.strip() or "/" in raw_host or "\\" in raw_host:
            return False
        try:
            parsed = urlsplit(f"//{raw_host}")
            hostname = parsed.hostname
            request_port = parsed.port
        except ValueError:
            return False
        if hostname is None or parsed.username is not None or parsed.password is not None:
            return False
        if self.allow_remote_host:
            return True
        if not _is_literal_loopback(hostname):
            return False
        server_address = self.server.server_address
        if not isinstance(server_address, tuple) or len(server_address) < 2:
            return False
        bound_port = int(server_address[1])
        return request_port is None or request_port == bound_port

    def _send_static(self, resource_name: str, content_type: str, *, head_only: bool) -> None:
        try:
            body = files("vulnrepair.web").joinpath(resource_name).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError, OSError):
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "dashboard_asset_unavailable"},
                head_only=head_only,
            )
            return
        self._send_bytes(HTTPStatus.OK, body, content_type, head_only=head_only)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: dict[str, Any],
        *,
        head_only: bool,
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > _MAX_RESPONSE_BYTES and status.value < 400:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            body = b'{"error":"dashboard_response_too_large"}'
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            head_only=head_only,
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        head_only: bool,
    ) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; connect-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'; img-src 'self'; "
            "object-src 'none'; script-src 'self'; style-src 'self'",
        )
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _not_found(self, *, head_only: bool) -> None:
        self._send_json(
            HTTPStatus.NOT_FOUND,
            {"error": "not_found"},
            head_only=head_only,
        )

    def _method_not_allowed(self) -> None:
        body = b'{"error":"method_not_allowed"}'
        self.close_connection = True
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED.value)
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; connect-src 'self'; "
            "form-action 'none'; frame-ancestors 'none'; img-src 'self'; "
            "object-src 'none'; script-src 'self'; style-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32
    _request_slots: threading.BoundedSemaphore

    def server_activate(self) -> None:
        self._request_slots = threading.BoundedSemaphore(32)
        super().server_activate()

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class DashboardIPv6HTTPServer(DashboardHTTPServer):
    address_family = socket.AF_INET6


def create_dashboard_server(
    runs_root: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_remote: bool = False,
) -> ThreadingHTTPServer:
    """Create a configured server without starting its request loop."""

    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")
    bind_host = host.strip().removeprefix("[").removesuffix("]")
    if not bind_host:
        if not allow_remote:
            raise ValueError("binding all interfaces requires allow_remote=True")
    elif not _is_loopback(bind_host) and not allow_remote:
        raise ValueError("non-loopback dashboard binding requires allow_remote=True")

    dashboard = DashboardData(runs_root)

    class BoundDashboardRequestHandler(DashboardRequestHandler):
        pass

    BoundDashboardRequestHandler.dashboard = dashboard
    BoundDashboardRequestHandler.allow_remote_host = allow_remote
    server_class: type[DashboardHTTPServer]
    server_class = DashboardIPv6HTTPServer if _is_ipv6_literal(bind_host) else DashboardHTTPServer
    return server_class((bind_host, port), BoundDashboardRequestHandler)


def serve_dashboard(
    runs_root: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_remote: bool = False,
) -> None:
    """Serve the dashboard until interrupted."""

    server = create_dashboard_server(
        runs_root,
        host=host,
        port=port,
        allow_remote=allow_remote,
    )
    bound_host, bound_port = server.server_address[:2]
    host_text = bound_host.decode("ascii") if isinstance(bound_host, bytes) else str(bound_host)
    port_number = int(bound_port)
    display_host = f"[{host_text}]" if ":" in host_text else host_text
    print(f"VulnRepair dashboard: http://{display_host}:{port_number}/")
    if not _is_loopback(host):
        print("Warning: remote mode has no built-in authentication or TLS.")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _is_loopback(host: str) -> bool:
    normalized = host.strip().removeprefix("[").removesuffix("]")
    if normalized.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not addresses:
        return False
    try:
        return all(ipaddress.ip_address(address[4][0]).is_loopback for address in addresses)
    except ValueError:
        return False


def _is_literal_loopback(host: str) -> bool:
    normalized = host.strip().removeprefix("[").removesuffix("]")
    if normalized.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_ipv6_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


__all__ = ["create_dashboard_server", "serve_dashboard"]

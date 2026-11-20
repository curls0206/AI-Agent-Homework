"""Windows Job Object containment and the trusted launch barrier.

The command runner starts this file as a tiny wrapper process.  The wrapper
blocks on stdin until the coordinator has placed it in a Job Object, closing
the race in which an uncontained command could create descendants before job
assignment.  Every process subsequently created by the wrapper inherits the
job membership.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from collections.abc import Sequence
from typing import Any, cast

_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_SPAWN_ERROR_EXIT = 255
_SPAWN_ERROR_MARKER = "VULNREPAIR_WINDOWS_WRAPPER_SPAWN_ERROR:"


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class WindowsJob:
    """Own a kill-on-close Windows Job Object handle."""

    def __init__(self) -> None:
        if "WinDLL" not in ctypes.__dict__:
            raise OSError("Windows Job Objects are only available on Windows")
        loader = cast(Any, ctypes.__dict__["WinDLL"])
        self._kernel32: Any = loader("kernel32", use_last_error=True)
        self._process_handle: int | None = None
        self._configure_functions()
        handle = self._kernel32.CreateJobObjectW(None, None)
        if not handle:
            self._raise_last_error("CreateJobObjectW")
        self._handle: int | None = int(handle)
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        configured = self._kernel32.SetInformationJobObject(
            self._handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not configured:
            self.close()
            self._raise_last_error("SetInformationJobObject")

    def _configure_functions(self) -> None:
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        self._kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._kernel32.SetInformationJobObject.restype = ctypes.c_int
        self._kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self._kernel32.OpenProcess.restype = ctypes.c_void_p
        self._kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._kernel32.AssignProcessToJobObject.restype = ctypes.c_int
        self._kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self._kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = ctypes.c_int

    def assign_pid(self, pid: int) -> None:
        """Assign a still-blocked wrapper process to this job."""

        if self._handle is None:
            raise OSError("Windows Job Object is already closed")
        if self._process_handle is not None:
            raise OSError("Windows Job Object already has an assigned process")
        process_handle = self._kernel32.OpenProcess(
            _PROCESS_TERMINATE | _PROCESS_SET_QUOTA | _SYNCHRONIZE,
            False,
            pid,
        )
        if not process_handle:
            self._raise_last_error("OpenProcess")
        try:
            assigned = self._kernel32.AssignProcessToJobObject(self._handle, process_handle)
            if not assigned:
                self._raise_last_error("AssignProcessToJobObject")
            self._process_handle = int(process_handle)
        except BaseException:
            self._kernel32.CloseHandle(process_handle)
            raise

    def process_exited(self) -> bool:
        """Poll the wrapper's process handle without waiting on inherited pipes."""

        if self._process_handle is None:
            raise OSError("Windows Job Object has no assigned process")
        result = int(self._kernel32.WaitForSingleObject(self._process_handle, 0))
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        self._raise_last_error("WaitForSingleObject")
        return False

    def close(self) -> None:
        """Close the sole job handle, terminating all remaining members."""

        job_handle, self._handle = self._handle, None
        process_handle, self._process_handle = self._process_handle, None
        if job_handle is not None:
            self._kernel32.CloseHandle(job_handle)
        if process_handle is not None:
            self._kernel32.CloseHandle(process_handle)

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        get_last_error = cast(Any, ctypes.__dict__["get_last_error"])
        error_code = int(get_last_error())
        raise OSError(error_code, f"{operation} failed", None, error_code)


def launch_barrier(argv: Sequence[str]) -> int:
    """Wait for job assignment, then run one command without a shell."""

    if not argv:
        print(f"{_SPAWN_ERROR_MARKER} command argv is empty", file=sys.stderr)
        return _SPAWN_ERROR_EXIT
    release = sys.stdin.buffer.read(1)
    if release != b"\x00":
        return _SPAWN_ERROR_EXIT
    try:
        process = subprocess.Popen(tuple(argv), stdin=subprocess.DEVNULL)
    except (OSError, ValueError) as exc:
        print(f"{_SPAWN_ERROR_MARKER} {exc}", file=sys.stderr)
        return _SPAWN_ERROR_EXIT
    return process.wait()


if __name__ == "__main__":
    raise SystemExit(launch_barrier(sys.argv[1:]))

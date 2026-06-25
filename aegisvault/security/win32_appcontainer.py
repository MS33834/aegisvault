# ruff: noqa: N801, PLW0602, PLW0603

"""Windows AppContainer sandbox helpers using direct Win32 ``ctypes`` calls.

This module wraps the low-level Win32 API calls required to create, use,
and destroy AppContainer profiles on Windows. When the host platform is not
Windows the public functions raise ``NotImplementedError``.

Exported functions
------------------
- ``create_appcontainer_profile(name, description)`` → SID string
- ``run_in_appcontainer(sid, command_line, **kw)`` →
  ``(returncode, stdout, stderr)``
- ``delete_appcontainer_profile(name)`` → None
"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes

# ── Type aliases ──────────────────────────────────────────────────────
PSID = ctypes.c_void_p
HANDLE = wintypes.HANDLE
LPCWSTR = wintypes.LPCWSTR
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
WORD = wintypes.WORD
BYTE = ctypes.c_byte
ULONG_PTR = ctypes.c_ulonglong
SIZE_T = ctypes.c_size_t
LPVOID = ctypes.c_void_p
INVALID_HANDLE_VALUE = HANDLE(-1).value
# On 64-bit Python, c_void_p(-1).value returns the integral representation
# of ((void *)-1) as a Python int (0xFFFFFFFFFFFFFFFF).  Assigning this back
# into a HANDLE field of a ctypes struct correctly reproduces the Win32
# INVALID_HANDLE_VALUE because ctypes truncation/promotion follows the
# field's type rather than the Python int width.


# ── Win32 constants ───────────────────────────────────────────────────

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: int = 0x0002000E
EXTENDED_STARTUPINFO_PRESENT: int = 0x00080000
CREATE_UNICODE_ENVIRONMENT: int = 0x00000400

_S_OK: int = 0x00000000
_E_FILE_NOT_FOUND: int = 0x80070002  # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)

_HANDLE_FLAG_INHERIT: int = 1
_HANDLE_FLAG_PROTECT_FROM_CLOSE: int = 2
_WAIT_TIMEOUT: int = 0x00000102
_STILL_ACTIVE: int = 259
_STARTF_USESTDHANDLES: int = 0x00000100


# ── Exceptions ────────────────────────────────────────────────────────


class AppContainerError(Exception):
    """Raised when an AppContainer Win32 operation fails."""


# ── Structures ────────────────────────────────────────────────────────


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", PSID),
        ("Attributes", DWORD),
    ]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", PSID),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", DWORD),
        ("Reserved", DWORD),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", wintypes.STARTUPINFO),
        ("lpAttributeList", LPVOID),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle", BOOL),
    ]


# ── Win32 function prototypes (lazy-loaded on Windows) ────────────────

_win32_loaded = False
_lock = threading.Lock()

# Module-level placeholders — assigned inside _ensure_win32().
_CreateAppContainerProfile: object = None
_DeleteAppContainerProfile: object = None
_FreeSid: object = None
_ConvertSidToStringSidW: object = None
_ConvertStringSidToSidW: object = None
_LocalFree: object = None
_CreateProcessW: object = None
_CreatePipe: object = None
_SetHandleInformation: object = None
_InitializeProcThreadAttributeList: object = None
_UpdateProcThreadAttribute: object = None
_DeleteProcThreadAttributeList: object = None
_CloseHandle: object = None
_WaitForSingleObject: object = None
_GetExitCodeProcess: object = None
_ReadFile: object = None
_TerminateProcess: object = None
_GetLastError: object = None


def _ensure_win32() -> None:
    """Load Win32 DLL entry points on first call.  Idempotent."""
    global _win32_loaded  # noqa: PLW0603
    if sys.platform != "win32":
        return
    if _win32_loaded:
        return
    with _lock:
        if _win32_loaded:
            return

    global _CreateAppContainerProfile
    global _DeleteAppContainerProfile
    global _FreeSid
    global _ConvertSidToStringSidW
    global _ConvertStringSidToSidW
    global _LocalFree
    global _CreateProcessW
    global _CreatePipe
    global _SetHandleInformation
    global _InitializeProcThreadAttributeList
    global _UpdateProcThreadAttribute
    global _DeleteProcThreadAttributeList
    global _CloseHandle
    global _WaitForSingleObject
    global _GetExitCodeProcess
    global _ReadFile
    global _TerminateProcess
    global _GetLastError

    _userenv = ctypes.WinDLL("userenv", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    # ── userenv.dll ───────────────────────────────────────────────
    _CreateAppContainerProfile = _userenv.CreateAppContainerProfile
    _CreateAppContainerProfile.argtypes = [
        LPCWSTR,
        LPCWSTR,
        LPCWSTR,
        ctypes.POINTER(SID_AND_ATTRIBUTES),
        DWORD,
        ctypes.POINTER(PSID),
    ]
    _CreateAppContainerProfile.restype = wintypes.HRESULT

    _DeleteAppContainerProfile = _userenv.DeleteAppContainerProfile
    _DeleteAppContainerProfile.argtypes = [LPCWSTR]
    _DeleteAppContainerProfile.restype = wintypes.HRESULT

    # ── advapi32.dll ──────────────────────────────────────────────
    _FreeSid = _advapi32.FreeSid
    _FreeSid.argtypes = [PSID]
    _FreeSid.restype = ctypes.c_void_p

    _ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = [PSID, ctypes.POINTER(wintypes.LPWSTR)]
    _ConvertSidToStringSidW.restype = BOOL

    _ConvertStringSidToSidW = _advapi32.ConvertStringSidToSidW
    _ConvertStringSidToSidW.argtypes = [LPCWSTR, ctypes.POINTER(PSID)]
    _ConvertStringSidToSidW.restype = BOOL

    # ── kernel32.dll ──────────────────────────────────────────────
    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = [ctypes.c_void_p]
    _LocalFree.restype = ctypes.c_void_p

    _CreateProcessW = _kernel32.CreateProcessW
    _CreateProcessW.argtypes = [
        LPCWSTR,
        wintypes.LPWSTR,
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        BOOL,
        DWORD,
        LPVOID,
        LPCWSTR,
        ctypes.POINTER(STARTUPINFOEXW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    _CreateProcessW.restype = BOOL

    _CreatePipe = _kernel32.CreatePipe
    _CreatePipe.argtypes = [
        ctypes.POINTER(HANDLE),
        ctypes.POINTER(HANDLE),
        ctypes.POINTER(SECURITY_ATTRIBUTES),
        DWORD,
    ]
    _CreatePipe.restype = BOOL

    _SetHandleInformation = _kernel32.SetHandleInformation
    _SetHandleInformation.argtypes = [HANDLE, DWORD, DWORD]
    _SetHandleInformation.restype = BOOL

    _InitializeProcThreadAttributeList = _kernel32.InitializeProcThreadAttributeList
    _InitializeProcThreadAttributeList.argtypes = [
        LPVOID,
        DWORD,
        DWORD,
        ctypes.POINTER(SIZE_T),
    ]
    _InitializeProcThreadAttributeList.restype = BOOL

    _UpdateProcThreadAttribute = _kernel32.UpdateProcThreadAttribute
    _UpdateProcThreadAttribute.argtypes = [
        LPVOID,
        DWORD,
        ULONG_PTR,
        LPVOID,
        SIZE_T,
        LPVOID,
        ctypes.POINTER(SIZE_T),
    ]
    _UpdateProcThreadAttribute.restype = BOOL

    _DeleteProcThreadAttributeList = _kernel32.DeleteProcThreadAttributeList
    _DeleteProcThreadAttributeList.argtypes = [LPVOID]
    _DeleteProcThreadAttributeList.restype = None

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [HANDLE]
    _CloseHandle.restype = BOOL

    _WaitForSingleObject = _kernel32.WaitForSingleObject
    _WaitForSingleObject.argtypes = [HANDLE, DWORD]
    _WaitForSingleObject.restype = DWORD

    _GetExitCodeProcess = _kernel32.GetExitCodeProcess
    _GetExitCodeProcess.argtypes = [HANDLE, ctypes.POINTER(DWORD)]
    _GetExitCodeProcess.restype = BOOL

    _ReadFile = _kernel32.ReadFile
    _ReadFile.argtypes = [
        HANDLE,
        LPVOID,
        DWORD,
        ctypes.POINTER(DWORD),
        ctypes.c_void_p,
    ]
    _ReadFile.restype = BOOL

    _TerminateProcess = _kernel32.TerminateProcess
    _TerminateProcess.argtypes = [HANDLE, DWORD]
    _TerminateProcess.restype = BOOL

    _GetLastError = _kernel32.GetLastError
    _GetLastError.restype = DWORD

    _win32_loaded = True


# ── Non-Windows guard ─────────────────────────────────────────────────


def _require_windows() -> None:
    if sys.platform != "win32":
        raise NotImplementedError("AppContainer Win32 APIs are only available on Windows")
    _ensure_win32()


# ── Public API ────────────────────────────────────────────────────────


def create_appcontainer_profile(name: str, description: str = "") -> str:
    """Create a Windows AppContainer profile and return its SID string.

    Raises ``AppContainerError`` on Win32 failure.
    On non-Windows platforms raises ``NotImplementedError``.
    """
    _require_windows()

    sid_ptr = PSID()
    hr = _CreateAppContainerProfile(name, name, description or name, None, 0, ctypes.byref(sid_ptr))
    if hr != _S_OK:
        raise AppContainerError(
            f"CreateAppContainerProfile failed for '{name}': HRESULT 0x{hr:08X}"
        )

    sid_str_ptr = wintypes.LPWSTR()
    if not _ConvertSidToStringSidW(sid_ptr, ctypes.byref(sid_str_ptr)):
        _FreeSid(sid_ptr)
        raise AppContainerError(f"ConvertSidToStringSidW failed for '{name}'")

    sid_str: str = sid_str_ptr.value or ""
    _LocalFree(sid_str_ptr)
    _FreeSid(sid_ptr)
    return sid_str


def run_in_appcontainer(
    appcontainer_sid: str,
    command_line: str,
    *,
    working_directory: str | None = None,
    timeout_ms: int = 0,
) -> tuple[int, str, str]:
    """Run *command_line* inside the AppContainer identified by *appcontainer_sid*.

    The process is created with a LowBox token that inherits the AppContainer
    identity.  stdout and stderr are captured via anonymous pipes.

    Parameters
    ----------
    appcontainer_sid:
        SID string returned by ``create_appcontainer_profile()``.
    command_line:
        Full command line including the executable and arguments.
    working_directory:
        Working directory for the child process.
    timeout_ms:
        Maximum wait time in milliseconds.  0 means wait indefinitely.

    Returns
    -------
    ``(returncode, stdout_text, stderr_text)``
    """
    _require_windows()

    sid_ptr = PSID()
    if not _ConvertStringSidToSidW(appcontainer_sid, ctypes.byref(sid_ptr)):
        raise AppContainerError(f"ConvertStringSidToSidW failed for SID '{appcontainer_sid}'")
    try:
        return _run_lowbox_impl(
            sid_ptr,
            command_line,
            working_directory=working_directory,
            timeout_ms=timeout_ms,
        )
    finally:
        _FreeSid(sid_ptr)


def delete_appcontainer_profile(name: str) -> None:
    """Delete the Windows AppContainer profile named *name*.

    Silently succeeds if the profile does not exist.
    Raises ``AppContainerError`` on other failures.
    On non-Windows platforms raises ``NotImplementedError``.
    """
    _require_windows()

    hr = _DeleteAppContainerProfile(name)
    if hr != _S_OK and hr != _E_FILE_NOT_FOUND:
        raise AppContainerError(
            f"DeleteAppContainerProfile failed for '{name}': HRESULT 0x{hr:08X}"
        )


# ── Internal helpers ──────────────────────────────────────────────────


def _pipename() -> str:
    """Return a unique pipe name segment."""
    return f"aegisvault-pipe-{id(ctypes)}-{threading.get_ident()}"


def _run_lowbox_impl(
    sid_ptr: PSID,
    command_line: str,
    *,
    working_directory: str | None,
    timeout_ms: int,
) -> tuple[int, str, str]:
    """Core implementation of LowBox process creation and I/O capture."""

    # ── Create anonymous pipes for stdout / stderr ──────────────────
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.bInheritHandle = True
    sa.lpSecurityDescriptor = None

    stdout_read = HANDLE()
    stdout_write = HANDLE()
    if not _CreatePipe(ctypes.byref(stdout_read), ctypes.byref(stdout_write), ctypes.byref(sa), 0):
        raise AppContainerError("CreatePipe for stdout failed")
    try:
        _SetHandleInformation(stdout_read, _HANDLE_FLAG_INHERIT, 0)

        stderr_read = HANDLE()
        stderr_write = HANDLE()
        if not _CreatePipe(
            ctypes.byref(stderr_read), ctypes.byref(stderr_write), ctypes.byref(sa), 0
        ):
            raise AppContainerError("CreatePipe for stderr failed")
        try:
            _SetHandleInformation(stderr_read, _HANDLE_FLAG_INHERIT, 0)

            # ── Build SECURITY_CAPABILITIES ────────────────────────
            caps = SECURITY_CAPABILITIES()
            caps.AppContainerSid = sid_ptr
            caps.CapabilityCount = 0

            # ── Build attribute list (1 attribute) ────────────────
            attr_list_size = SIZE_T()
            _InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_list_size))
            attr_list_buf = (ctypes.c_byte * attr_list_size.value)()
            if not _InitializeProcThreadAttributeList(
                attr_list_buf, 1, 0, ctypes.byref(attr_list_size)
            ):
                raise AppContainerError("InitializeProcThreadAttributeList failed")
            try:
                if not _UpdateProcThreadAttribute(
                    attr_list_buf,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(caps),
                    ctypes.sizeof(caps),
                    None,
                    None,
                ):
                    raise AppContainerError(
                        "UpdateProcThreadAttribute (SECURITY_CAPABILITIES) " "failed"
                    )

                # ── Build STARTUPINFOEX ───────────────────────────
                si = STARTUPINFOEXW()
                si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
                si.StartupInfo.hStdOutput = stdout_write
                si.StartupInfo.hStdError = stderr_write
                si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE
                si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
                si.lpAttributeList = ctypes.cast(attr_list_buf, LPVOID)

                cmd_buf = ctypes.create_unicode_buffer(command_line)
                creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT

                pi = PROCESS_INFORMATION()
                if not _CreateProcessW(
                    None,
                    cmd_buf,
                    None,
                    None,
                    True,  # inherit handles (for stdout/stderr pipes)
                    creation_flags,
                    None,
                    working_directory,
                    ctypes.byref(si),
                    ctypes.byref(pi),
                ):
                    raise AppContainerError(f"CreateProcessW failed for '{command_line}'")

                _CloseHandle(stdout_write)
                _CloseHandle(stderr_write)
                stdout_write = None  # type: ignore[assignment]
                stderr_write = None  # type: ignore[assignment]

                try:
                    process_handle = pi.hProcess
                    thread_handle = pi.hThread

                    try:
                        wait_result = _WaitForSingleObject(
                            process_handle,
                            timeout_ms if timeout_ms > 0 else 0xFFFFFFFF,
                        )
                        if wait_result == _WAIT_TIMEOUT:
                            _TerminateProcess(process_handle, 1)
                            raise AppContainerError(f"Process timed out after {timeout_ms} ms")

                        exit_code = DWORD()
                        _GetExitCodeProcess(process_handle, ctypes.byref(exit_code))
                    finally:
                        _CloseHandle(process_handle)
                        _CloseHandle(thread_handle)

                    stdout_data = _read_pipe(stdout_read)
                    stderr_data = _read_pipe(stderr_read)

                    return (exit_code.value, stdout_data, stderr_data)
                finally:
                    if stdout_write is not None:
                        _CloseHandle(stdout_write)
                    if stderr_write is not None:
                        _CloseHandle(stderr_write)
            finally:
                _DeleteProcThreadAttributeList(attr_list_buf)
        finally:
            if stderr_write is not None:
                _CloseHandle(stderr_write)
            _CloseHandle(stderr_read)
    finally:
        if stdout_write is not None:
            _CloseHandle(stdout_write)
        _CloseHandle(stdout_read)


def _read_pipe(handle: HANDLE) -> str:
    """Read all available data from *handle* and return as a string."""
    buf = ctypes.create_string_buffer(4096)
    parts: list[bytes] = []
    while True:
        bytes_read = DWORD()
        success = _ReadFile(handle, buf, DWORD(len(buf)), ctypes.byref(bytes_read), None)
        if not success or bytes_read.value == 0:
            break
        parts.append(buf.raw[: bytes_read.value])
    return b"".join(parts).decode("utf-8", errors="replace")

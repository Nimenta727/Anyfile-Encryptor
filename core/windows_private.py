"""Windows-only creation of files with a protected, explicit DACL.

No inherited ACEs: current process user and LOCAL SYSTEM only. Does not defend
against privileged administrators, an untrusted parent, or endpoint compromise.
"""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import secrets

if os.name == "nt":
    import msvcrt

    kernel = C.WinDLL("kernel32", use_last_error=True)
    adv = C.WinDLL("advapi32", use_last_error=True)

    def api(dll, name, result, *args):
        f = getattr(dll, name)
        f.restype = result
        f.argtypes = args
        return f

    ptr = C.c_void_p
    dword_p = C.POINTER(W.DWORD)
    handle_p = C.POINTER(W.HANDLE)
    close = api(kernel, "CloseHandle", W.BOOL, W.HANDLE)
    free = api(kernel, "LocalFree", ptr, ptr)
    process = api(kernel, "GetCurrentProcess", W.HANDLE)
    open_token = api(adv, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, handle_p)
    token_info = api(adv, "GetTokenInformation", W.BOOL, W.HANDLE, C.c_int, ptr, W.DWORD, dword_p)
    sid_string = api(adv, "ConvertSidToStringSidW", W.BOOL, ptr, C.POINTER(ptr))
    make_sd = api(adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL,
                  W.LPCWSTR, W.DWORD, C.POINTER(ptr), dword_p)

    class SecurityAttributes(C.Structure):
        _fields_ = [("nLength", W.DWORD), ("lpSecurityDescriptor", ptr), ("bInheritHandle", W.BOOL)]

    create = api(kernel, "CreateFileW", W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD,
                 C.POINTER(SecurityAttributes), W.DWORD, W.DWORD, W.HANDLE)
    invalid = C.c_void_p(-1).value

    def current_sid():
        token = W.HANDLE()
        if not open_token(process(), 8, C.byref(token)):
            raise C.WinError(C.get_last_error())
        try:
            size = W.DWORD()
            token_info(token, 1, None, 0, C.byref(size))
            if not size.value or size.value > 65536:
                raise OSError("Unable to query Windows user SID")
            buf = C.create_string_buffer(size.value)
            if not token_info(token, 1, buf, size, C.byref(size)):
                raise C.WinError(C.get_last_error())
            sid = C.cast(buf, C.POINTER(ptr))[0]  # TOKEN_USER begins with SID pointer
            text = ptr()
            if not sid_string(sid, C.byref(text)):
                raise C.WinError(C.get_last_error())
            try:
                return C.wstring_at(text)
            finally:
                free(text)
        finally:
            close(token)


def private_temp(directory):
    if os.name != "nt":
        raise RuntimeError("Windows-only function")
    descriptor = ptr()
    # D:P marks DACL protected. FA = FILE_ALL_ACCESS, SY = LOCAL SYSTEM.
    if not make_sd("D:P(A;;FA;;;" + current_sid() + ")(A;;FA;;;SY)", 1,
                   C.byref(descriptor), None):
        raise C.WinError(C.get_last_error())
    try:
        sa = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
        for _ in range(16):
            name = str(Path(directory) / (".mosaic-hdt-" + secrets.token_hex(16) + ".tmp"))
            # CREATE_NEW, no sharing until closed; no permissive retry.
            handle = create(name, 0xC0000000, 0, C.byref(sa), 1, 0x80, None)
            if handle == invalid:
                error = C.get_last_error()
                if error in (80, 183):
                    continue
                raise C.WinError(error)
            try:
                return msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY), name
            except BaseException:
                close(handle)
                try:
                    os.unlink(name)
                except OSError:
                    pass
                raise
        raise FileExistsError("Could not allocate a private temporary file")
    finally:
        free(descriptor)

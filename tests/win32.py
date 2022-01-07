# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

from libpcap._platform import is_windows

if is_windows:

    import ctypes
    from ctypes import windll
    from ctypes import wintypes
    from ctypes import WINFUNCTYPE
    from ctypes.wintypes import (
        CHAR, WCHAR, BOOLEAN, BOOL, BYTE, WORD, DWORD, SHORT, USHORT, INT,
        UINT, LONG, ULONG, LARGE_INTEGER, ULARGE_INTEGER, FLOAT, DOUBLE,
        LPBYTE, PBYTE, LPWORD, PWORD, LPDWORD, PDWORD, LPLONG, PLONG, LPSTR,
        LPCSTR, LPVOID, LPCVOID, LPVOID as PVOID, HANDLE, LPHANDLE, PHANDLE,
        WPARAM, LPARAM, FILETIME, LPFILETIME,
    )

    from ctypes.wintypes import WPARAM as ULONG_PTR # workaround
    PULONG_PTR = ctypes.POINTER(ULONG_PTR)

    ULONG32   = ctypes.c_uint32
    ULONGLONG = ctypes.c_uint64
    DWORDLONG = ctypes.c_uint64
    SIZE_T    = ctypes.c_size_t

    WAIT_ABANDONED = 0x00000080
    WAIT_OBJECT_0  = 0x00000000
    WAIT_TIMEOUT   = 0x00000102
    WAIT_FAILED    = 0xFFFFFFFF

    IGNORE   = 0
    INFINITE = 0xFFFFFFFF

    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
    FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x00002000
    FORMAT_MESSAGE_FROM_HMODULE    = 0x00000800
    FORMAT_MESSAGE_FROM_STRING     = 0x00000400
    FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
    FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
    FORMAT_MESSAGE_MAX_WIDTH_MASK  = 0x000000FF

    GetCurrentProcess = windll.kernel32.GetCurrentProcess
    GetCurrentProcess.restype  = HANDLE
    GetCurrentProcess.argtypes = []

    GetProcessTimes = windll.kernel32.GetProcessTimes
    GetProcessTimes.restype  = BOOL
    GetProcessTimes.argtypes = [HANDLE,
                                LPFILETIME,
                                LPFILETIME,
                                LPFILETIME,
                                LPFILETIME]

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
        ("nLength",              DWORD),
        ("lpSecurityDescriptor", LPVOID),
        ("bInheritHandle",       BOOL),
    ]
    LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)

    LPTHREAD_START_ROUTINE = WINFUNCTYPE(DWORD, LPVOID)
    CreateThread = windll.kernel32.CreateThread
    CreateThread.restype  = HANDLE
    CreateThread.argtypes = [LPSECURITY_ATTRIBUTES,
                             SIZE_T,
                             LPTHREAD_START_ROUTINE,
                             LPVOID,
                             DWORD,
                             LPDWORD]

    WaitForSingleObject = windll.kernel32.WaitForSingleObject
    WaitForSingleObject.restype  = DWORD
    WaitForSingleObject.argtypes = [HANDLE,
                                    DWORD]

    SetEvent = windll.kernel32.SetEvent
    SetEvent.restype  = BOOL
    SetEvent.argtypes = [HANDLE]

    Sleep = windll.kernel32.Sleep
    Sleep.restype  = None
    Sleep.argtypes = [DWORD]

    PHANDLER_ROUTINE = WINFUNCTYPE(BOOL, DWORD)
    SetConsoleCtrlHandler = windll.kernel32.SetConsoleCtrlHandler
    SetConsoleCtrlHandler.restype  = BOOL
    SetConsoleCtrlHandler.argtypes = [PHANDLER_ROUTINE,
                                      BOOL]

    CloseHandle = windll.kernel32.CloseHandle
    CloseHandle.restype  = BOOL
    CloseHandle.argtypes = [HANDLE]

    GetLastError = windll.kernel32.GetLastError
    GetLastError.restype  = DWORD
    GetLastError.argtypes = []

    FormatMessageA = windll.kernel32.FormatMessageA
    FormatMessageA.restype  = DWORD
    FormatMessageA.argtypes = [DWORD,
                               LPCVOID,
                               DWORD,
                               DWORD,
                               LPSTR,
                               DWORD,
                               LPVOID]

    del ctypes

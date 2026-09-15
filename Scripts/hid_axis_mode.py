#!/usr/bin/env python3
r"""
hid_axis_mode.py - report whether each connected pointing device declares its
X and Y axes ABSOLUTE or RELATIVE in its HID report descriptor.

DESCRIPTION
    Enumerates HID collections two ways and merges them by device instance:

      * GetRawInputDeviceList (user32) - per terminal-services session, so it is
        empty or short outside the interactive session, but it authoritatively
        marks a collection as mouse-class.
      * CM_Get_Device_Interface_ListW (cfgmgr32) - every present
        GUID_DEVINTERFACE_HID interface, from the PnP manager, with no session
        affinity. This is the path that survives session 0.

    The second path is the workaround this script exists for. An EDR remote
    scripting terminal - Cortex XDR and equivalents - runs as SYSTEM in
    session 0, where the raw input device list is empty. Enumerating only that
    way returns nothing, which reads as "no absolute pointer" when it actually
    means the probe was blind. The PnP query has no session affinity, so it
    still sees the console user's devices.

    Each merged collection is opened with CreateFileW at zero access rights (no
    administrator rights needed, and the only access that works on mouse and
    keyboard collections) and its descriptor read via HidD_GetPreparsedData and
    HidP_GetValueCaps. The IsAbsolute field of the X and Y HIDP_VALUE_CAPS is
    the reported axis mode; it is the decoded Relative flag of the descriptor's
    Input main item, and there is no registry equivalent.

    Only Pointer (usage page 0x01, usage 0x01) and Mouse (0x01/0x02) top-level
    collections count as pointing devices. Digitizer-page (0x0D) collections are
    absolute by design and are excluded unless --include-digitizers is passed.

    A device must be connected to be read. Output always carries the session id,
    per-source enumeration counts and per-device errors, and grades visibility
    as full, partial or none, so an empty result is never mistaken for a
    conclusive negative. IsAbsolute reflects only what a device declares.

PARAMETERS
    --absolute-only
        Show only devices with an absolute X or Y axis. Failed probes are still
        shown - their axis mode is unknown, not relative.

    --include-digitizers
        Also treat Digitizer-page (0x0D) collections - touchpads, touchscreens,
        pens - as pointing devices.

    --method auto|rawinput|hid
        Enumeration source. auto uses both; rawinput and hid isolate one, which
        is how you tell which layer went blind.

    --json
        Emit the result as JSON instead of the readable report.

    --out-file PATH
        Write the output to this path as UTF-8 without BOM, as well as to stdout.

    run_script(absolute_only=False, method="auto", include_digitizers=False)
        Cortex entry point. Takes the same three options and returns the dict
        that --json prints. Only modules on the Cortex allowed list are used:
        argparse, ctypes, json, os, platform, sys (ctypes.wintypes included).

EXAMPLES
    python hid_axis_mode.py
    python hid_axis_mode.py --absolute-only
    python hid_axis_mode.py --json --out-file C:\temp\hid_axis.json
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import platform
import sys

# --- constants -------------------------------------------------------------
RIDI_DEVICENAME = 0x20000007
RIM_TYPEMOUSE = 0
RIM_TYPEKEYBOARD = 1
GENERIC_NONE = 0
FILE_SHARE_RW = 3          # FILE_SHARE_READ | FILE_SHARE_WRITE
OPEN_EXISTING = 3
HIDP_INPUT = 0
HIDP_STATUS_SUCCESS = 0x00110000   # NTSTATUS-style, returned as a signed int

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_FOUND = 1168
# A cfgmgr32 interface path can name a device that has already gone away, or a
# non-openable child (the '\KBD' suffixed ones). These codes mean "not there",
# not "you were denied", and must not be counted as lost visibility.
ABSENT_DEVICE_ERRORS = (2, 3, 433, 1167)
# HidD_GetPreparsedData returning ERROR_NOT_FOUND means the interface has no
# HID report descriptor at all, so it cannot be a pointing device and nothing
# was lost by not reading it. MEASURED on a 1,093-endpoint fleet run
# (2026-09-03): 458 of 481 unreadable interfaces were exactly this, 456 of them
# the Intel Bluetooth HID enumerator Vid_8087&Pid_0AC2. Counting them as lost
# visibility is what turned 172 endpoints INCONCLUSIVE for no reason.
NO_DESCRIPTOR_ERRORS = {"HidD_GetPreparsedData": (ERROR_NOT_FOUND,)}

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

# cfgmgr32
CM_GET_DEVICE_INTERFACE_LIST_PRESENT = 0x00000001
CR_SUCCESS = 0x00000000
CR_BUFFER_SMALL = 0x0000001A

# HIDP_VALUE_CAPS is a 72-byte record; HIDP_CAPS is 64 bytes.
VALUE_CAPS_STRIDE = 72
CAPS_SIZE = 64
CAPS_USAGE_OFF = 0                 # Usage, USHORT      (top-level collection)
CAPS_USAGE_PAGE_OFF = 2            # UsagePage, USHORT  (top-level collection)
CAPS_NUM_INPUT_VALUE_OFF = 48      # NumberInputValueCaps, USHORT

# Per HIDP_VALUE_CAPS field offsets used here:
VC_USAGE_PAGE_OFF = 0              # UsagePage, USHORT
VC_IS_RANGE_OFF = 12               # IsRange, BOOLEAN
VC_IS_ABSOLUTE_OFF = 15            # IsAbsolute, BOOLEAN
VC_NOTRANGE_USAGE_OFF = 56         # NotRange.Usage, USHORT (valid IsRange == 0)

# INVALID_HANDLE_VALUE as an unsigned pointer-sized value, for comparison
# against a c_void_p return.
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GRIDI_FAIL = ctypes.c_uint(-1).value   # (UINT)-1, returned on info-query error
WTS_INVALID_SESSION = 0xFFFFFFFF
NAME_SAM_COMPATIBLE = 2            # EXTENDED_NAME_FORMAT, domain-qualified

# Top-level collection labels, from the HID usage tables.
TOP_LEVEL_NAMES = {
    (0x01, 0x01): "Pointer",
    (0x01, 0x02): "Mouse",
    (0x01, 0x04): "Joystick",
    (0x01, 0x05): "Game Pad",
    (0x01, 0x06): "Keyboard",
    (0x01, 0x07): "Keypad",
    (0x01, 0x08): "Multi-axis Controller",
    (0x0C, 0x01): "Consumer Control",
    (0x0D, 0x01): "Digitizer",
    (0x0D, 0x02): "Pen",
    (0x0D, 0x03): "Light Pen",
    (0x0D, 0x04): "Touch Screen",
    (0x0D, 0x05): "Touch Pad",
    (0x0D, 0x0E): "Device Configuration",
    (0x0D, 0x20): "Stylus",
}

# What counts as a pointing device. A gamepad also declares absolute X/Y, so
# this filter is load-bearing, not cosmetic.
POINTER_USAGES = ((0x01, 0x01), (0x01, 0x02))
# The Digitizer page (0x0D) is deliberately NOT a pointing device here: a
# touchpad, touchscreen or pen declares ABSOLUTE by design. Pass
# include_digitizers=True for a touch-hardware question.
DIGITIZER_USAGE_PAGE = 0x0D

# Symbolic names for the Win32 errors this probe actually runs into, so a
# Cortex results pane shows 'ERROR_ACCESS_DENIED' rather than a bare 5.
WIN32_ERROR_NAMES = {
    0: "ERROR_SUCCESS",
    1: "ERROR_INVALID_FUNCTION",
    2: "ERROR_FILE_NOT_FOUND",
    3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED",
    6: "ERROR_INVALID_HANDLE",
    8: "ERROR_NOT_ENOUGH_MEMORY",
    21: "ERROR_NOT_READY",
    31: "ERROR_GEN_FAILURE",
    32: "ERROR_SHARING_VIOLATION",
    50: "ERROR_NOT_SUPPORTED",
    87: "ERROR_INVALID_PARAMETER",
    122: "ERROR_INSUFFICIENT_BUFFER",
    433: "ERROR_NO_SUCH_DEVICE",
    995: "ERROR_OPERATION_ABORTED",
    998: "ERROR_NOACCESS",
    1167: "ERROR_DEVICE_NOT_CONNECTED",
    1359: "ERROR_INTERNAL_ERROR",
    1400: "ERROR_INVALID_WINDOW_HANDLE",
    1816: "ERROR_NOT_ENOUGH_QUOTA",
}

# HIDP_STATUS_* NTSTATUS-style codes returned by the HidP_* parsers.
HIDP_STATUS_NAMES = {
    0x00110000: "HIDP_STATUS_SUCCESS",
    0x80110001: "HIDP_STATUS_NULL",
    0xC0110001: "HIDP_STATUS_INVALID_PREPARSED_DATA",
    0xC0110002: "HIDP_STATUS_INVALID_REPORT_TYPE",
    0xC0110003: "HIDP_STATUS_INVALID_REPORT_LENGTH",
    0xC0110004: "HIDP_STATUS_USAGE_NOT_FOUND",
    0xC0110005: "HIDP_STATUS_VALUE_OUT_OF_RANGE",
    0xC0110006: "HIDP_STATUS_BAD_LOG_PHY_VALUES",
    0xC0110007: "HIDP_STATUS_BUFFER_TOO_SMALL",
    0xC0110008: "HIDP_STATUS_INTERNAL_ERROR",
    0xC0110009: "HIDP_STATUS_I8042_TRANS_UNKNOWN",
    0xC011000A: "HIDP_STATUS_INCOMPATIBLE_REPORT_ID",
    0xC011000B: "HIDP_STATUS_NOT_VALUE_ARRAY",
    0xC011000C: "HIDP_STATUS_IS_VALUE_ARRAY",
    0xC011000D: "HIDP_STATUS_DATA_INDEX_NOT_FOUND",
    0xC011000E: "HIDP_STATUS_DATA_INDEX_OUT_OF_RANGE",
    0xC011000F: "HIDP_STATUS_BUTTON_NOT_PRESSED",
    0xC0110010: "HIDP_STATUS_REPORT_DOES_NOT_EXIST",
    0xC0110020: "HIDP_STATUS_NOT_IMPLEMENTED",
}

SESSION_0_WARNING = (
    "SESSION 0. This process is in the non-interactive services session, so a "
    "zero or partial result may mean the probe was blind rather than clean. "
    "GetRawInputDeviceList is per-session and is expected to be empty here; "
    "the cfgmgr32 PnP path should still see the devices. If it is also empty, "
    "or every CreateFileW returns err=5 ERROR_ACCESS_DENIED, re-run in the "
    "interactive user session - for example a scheduled task with "
    "LogonType=InteractiveToken."
)


class RAWINPUTDEVICELIST(ctypes.Structure):
    _fields_ = [("hDevice", wt.HANDLE), ("dwType", wt.DWORD)]


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


def _hid_interface_guid():
    """GUID_DEVINTERFACE_HID {4D1E55B2-F16F-11CF-88CB-001111000030}."""
    return GUID(0x4D1E55B2, 0xF16F, 0x11CF,
                (ctypes.c_ubyte * 8)(0x88, 0xCB, 0x00, 0x11,
                                     0x11, 0x00, 0x00, 0x30))


# --- API binding -----------------------------------------------------------
# Loaded lazily so this module still imports on a non-Windows host (run_script
# reports a clean error there instead of blowing up at import time).
_APIS = None


def _load_apis():
    """Bind the Win32 entry points with explicit argtypes/restype."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    hid = ctypes.WinDLL("hid", use_last_error=True)
    cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)

    user32.GetRawInputDeviceList.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wt.UINT), wt.UINT]
    user32.GetRawInputDeviceList.restype = wt.UINT

    user32.GetRawInputDeviceInfoW.argtypes = [
        wt.HANDLE, wt.UINT, ctypes.c_void_p, ctypes.POINTER(wt.UINT)]
    user32.GetRawInputDeviceInfoW.restype = wt.UINT

    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
        wt.DWORD, wt.DWORD, ctypes.c_void_p]
    kernel32.CreateFileW.restype = ctypes.c_void_p

    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wt.BOOL

    kernel32.GetCurrentProcessId.argtypes = []
    kernel32.GetCurrentProcessId.restype = wt.DWORD

    kernel32.ProcessIdToSessionId.argtypes = [wt.DWORD,
                                              ctypes.POINTER(wt.DWORD)]
    kernel32.ProcessIdToSessionId.restype = wt.BOOL

    kernel32.WTSGetActiveConsoleSessionId.argtypes = []
    kernel32.WTSGetActiveConsoleSessionId.restype = wt.DWORD

    kernel32.FormatMessageW.argtypes = [
        wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD,
        wt.LPWSTR, wt.DWORD, ctypes.c_void_p]
    kernel32.FormatMessageW.restype = wt.DWORD

    hid.HidD_GetPreparsedData.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    hid.HidD_GetPreparsedData.restype = wt.BOOL

    hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
    hid.HidD_FreePreparsedData.restype = wt.BOOL

    hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    hid.HidP_GetCaps.restype = ctypes.c_long

    hid.HidP_GetValueCaps.argtypes = [
        ctypes.c_int, ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ushort), ctypes.c_void_p]
    hid.HidP_GetValueCaps.restype = ctypes.c_long

    cfgmgr32.CM_Get_Device_Interface_List_SizeW.argtypes = [
        ctypes.POINTER(wt.ULONG), ctypes.POINTER(GUID), wt.LPCWSTR, wt.ULONG]
    cfgmgr32.CM_Get_Device_Interface_List_SizeW.restype = wt.DWORD

    cfgmgr32.CM_Get_Device_Interface_ListW.argtypes = [
        ctypes.POINTER(GUID), wt.LPCWSTR, wt.LPWSTR, wt.ULONG, wt.ULONG]
    cfgmgr32.CM_Get_Device_Interface_ListW.restype = wt.DWORD

    return {"user32": user32, "kernel32": kernel32, "hid": hid,
            "cfgmgr32": cfgmgr32}


def _apis():
    global _APIS
    if _APIS is None:
        _APIS = _load_apis()
    return _APIS


# --- diagnostics helpers ---------------------------------------------------

def _win32_text(code):
    """Human text for a Win32 error: the symbolic name, or the system message
    from FormatMessageW for a code the table does not name."""
    name = WIN32_ERROR_NAMES.get(code)
    if name:
        return name
    try:
        buf = ctypes.create_unicode_buffer(512)
        n = _apis()["kernel32"].FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None, wt.DWORD(code), 0, buf, 512, None)
        if n:
            return buf.value.strip().replace("\r", " ").replace("\n", " ")
    except Exception:
        pass
    return "unknown error"


def _hidp_status_text(status):
    """Human text for an NTSTATUS-style HIDP_STATUS_* value."""
    return HIDP_STATUS_NAMES.get(status & 0xFFFFFFFF, "unrecognised HIDP_STATUS")


def _session_id():
    """Terminal-services session of this process. 0 is the non-interactive
    services session, where a Cortex agent script runs. None if the call
    fails."""
    try:
        k = _apis()["kernel32"]
        sid = wt.DWORD(0)
        if k.ProcessIdToSessionId(k.GetCurrentProcessId(), ctypes.byref(sid)):
            return int(sid.value)
    except Exception:
        pass
    return None


def _console_session_id():
    """Session that owns the physical console, and therefore the physical HID
    devices. Readable from session 0. None when nobody is at the console."""
    try:
        sid = _apis()["kernel32"].WTSGetActiveConsoleSessionId()
        if sid == WTS_INVALID_SESSION:
            return None
        return int(sid)
    except Exception:
        return None


def _process_user():
    """Account this process runs as - the SYSTEM account under Cortex.
    Best effort; prefers the domain-qualified form GetUserNameExW returns,
    which is what the PowerShell report shows."""
    try:
        secur32 = ctypes.WinDLL("secur32", use_last_error=True)
        secur32.GetUserNameExW.argtypes = [ctypes.c_int, wt.LPWSTR,
                                           ctypes.POINTER(wt.ULONG)]
        secur32.GetUserNameExW.restype = ctypes.c_ubyte
        size = wt.ULONG(257)
        buf = ctypes.create_unicode_buffer(size.value)
        if secur32.GetUserNameExW(NAME_SAM_COMPATIBLE, buf,
                                  ctypes.byref(size)) and buf.value:
            return buf.value
    except Exception:
        pass
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.GetUserNameW.argtypes = [wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        advapi32.GetUserNameW.restype = wt.BOOL
        size = wt.DWORD(257)
        buf = ctypes.create_unicode_buffer(size.value)
        if advapi32.GetUserNameW(buf, ctypes.byref(size)):
            return buf.value
    except Exception:
        pass
    return None


# --- path helpers ----------------------------------------------------------

def _u16(buf, off):
    """Read a little-endian USHORT from a bytes-like buffer at off."""
    return buf[off] | (buf[off + 1] << 8)


def _instance_key(path):
    """Collapse the two spellings of the same HID collection to one key.

    A raw input path and a cfgmgr32 path for the same collection differ only in
    the trailing interface GUID:
      \\\\?\\HID#VID_1D6B&PID_0104&MI_01#7&29d7c321&0&0000#{378de44c-...}
      \\\\?\\HID#VID_1D6B&PID_0104&MI_01#7&29d7c321&0&0000#{4d1e55b2-...}
    The hardware id and instance id in the middle are the identity.
    """
    if not path:
        return ""
    parts = path.upper().split("#")
    if len(parts) >= 3:
        return "#".join(parts[1:3])
    return path.upper()


def _hardware_id(path):
    """The middle 'VID_xxxx&PID_xxxx&MI_xx' style segment of an interface
    path, which is more informative than VID/PID alone for I2C/ACPI devices
    spelled VEN_xxxx."""
    parts = path.split("#")
    return parts[1] if len(parts) >= 2 else ""


def _parse_vid_pid(path):
    """Pull VID/PID out of a HID interface path without regex (re is not on
    the Cortex allow list). Returns (vid, pid) uppercased, or (None, None).
    Internal buses spell it VEN_xxxx and have no PID; _hardware_id covers those.
    """
    up = path.upper()

    def _hex4(marker):
        i = up.find(marker)
        if i < 0:
            return None
        frag = up[i + len(marker):i + len(marker) + 4]
        if len(frag) == 4 and all(c in "0123456789ABCDEF" for c in frag):
            return frag
        return None

    vid = _hex4("VID_") or _hex4("VEN_")
    return vid, _hex4("PID_")


def _axis_label(usage_page, usage):
    if usage_page == 0x01 and usage == 0x30:
        return "X"
    if usage_page == 0x01 and usage == 0x31:
        return "Y"
    if usage_page == 0x01 and usage == 0x38:
        return "Wheel"
    return "UP%02X/U%02X" % (usage_page, usage)


def _top_level_label(usage_page, usage):
    name = TOP_LEVEL_NAMES.get((usage_page, usage))
    if name:
        return "%s (UP%02X/U%02X)" % (name, usage_page, usage)
    return "UP%02X/U%02X" % (usage_page, usage)


def _is_pointer_collection(usage_page, usage, include_digitizers=False):
    if (usage_page, usage) in POINTER_USAGES:
        return True
    return bool(include_digitizers and usage_page == DIGITIZER_USAGE_PAGE)


# --- enumeration -----------------------------------------------------------

def _enumerate_hid_interfaces(cfgmgr32):
    """Session-independent enumeration via the PnP manager. Returns
    (paths, stats). CM_Get_Device_Interface_ListW is a PnP query, not a
    windowing call, so it has no window station or desktop dependency and
    still works as SYSTEM in session 0."""
    stats = {"available": False, "interface_count": 0, "error": None}
    guid = _hid_interface_guid()
    flags = CM_GET_DEVICE_INTERFACE_LIST_PRESENT

    for _ in range(3):
        size = wt.ULONG(0)
        cr = cfgmgr32.CM_Get_Device_Interface_List_SizeW(
            ctypes.byref(size), ctypes.byref(guid), None, flags)
        if cr != CR_SUCCESS:
            stats["error"] = ("CM_Get_Device_Interface_List_SizeW returned "
                              "CONFIGRET %d" % cr)
            return [], stats
        if size.value == 0:
            stats["available"] = True
            stats["error"] = ("the PnP manager reports 0 present "
                              "GUID_DEVINTERFACE_HID interfaces")
            return [], stats
        buf = ctypes.create_unicode_buffer(size.value)
        cr = cfgmgr32.CM_Get_Device_Interface_ListW(
            ctypes.byref(guid), None, buf, size.value, flags)
        if cr == CR_BUFFER_SMALL:
            continue                     # device arrived mid-call; re-size.
        if cr != CR_SUCCESS:
            stats["error"] = ("CM_Get_Device_Interface_ListW returned "
                              "CONFIGRET %d" % cr)
            return [], stats
        paths = [p for p in buf[:size.value].split("\0") if p]
        stats["available"] = True
        stats["interface_count"] = len(paths)
        return paths, stats

    stats["error"] = ("CM_Get_Device_Interface_ListW kept returning "
                      "CR_BUFFER_SMALL - the device list is churning")
    return [], stats


def _device_path(user32, hdevice):
    """Resolve the interface path for a raw input device handle.

    Returns (path, error_dict_or_None). An unnamed device is reported rather
    than silently skipped - a handle that will not resolve to a path is itself
    a diagnostic.
    """
    size = wt.UINT(0)
    ctypes.set_last_error(0)
    user32.GetRawInputDeviceInfoW(hdevice, RIDI_DEVICENAME, None,
                                  ctypes.byref(size))
    if size.value == 0:
        return "", {"api": "GetRawInputDeviceInfoW(RIDI_DEVICENAME, size)",
                    "code": ctypes.get_last_error()}
    buf = ctypes.create_unicode_buffer(size.value + 1)
    ctypes.set_last_error(0)
    ret = user32.GetRawInputDeviceInfoW(hdevice, RIDI_DEVICENAME, buf,
                                        ctypes.byref(size))
    if ret == GRIDI_FAIL:
        return "", {"api": "GetRawInputDeviceInfoW(RIDI_DEVICENAME)",
                    "code": ctypes.get_last_error()}
    if not buf.value:
        return "", {"api": "GetRawInputDeviceInfoW(RIDI_DEVICENAME)",
                    "code": 0}
    return buf.value, None


def _enumerate_rawinput(user32):
    """Per-session enumeration via win32k. Expected to be empty or short in
    session 0; kept because it authoritatively marks a collection mouse-class.

    Returns (list of {path, path_error}, stats). Every failure leaves a reason
    behind, so a blind run cannot look like a clean one."""
    stats = {
        "available": False,
        "raw_device_total": 0,
        "raw_device_count": 0,
        "type_counts": {"mouse": 0, "keyboard": 0, "other_hid": 0},
        "unnamed_devices": 0,
        "error": None,
    }
    cb = ctypes.sizeof(RAWINPUTDEVICELIST)

    count = wt.UINT(0)
    ctypes.set_last_error(0)
    probe = user32.GetRawInputDeviceList(None, ctypes.byref(count), cb)
    if probe == GRIDI_FAIL:
        err = ctypes.get_last_error()
        stats["error"] = ("GetRawInputDeviceList(count probe) failed: err=%d %s"
                          % (err, _win32_text(err)))
        return [], stats

    stats["available"] = True
    stats["raw_device_total"] = int(count.value)
    if count.value == 0:
        stats["error"] = (
            "GetRawInputDeviceList reported 0 raw input devices of any type. "
            "The call succeeded; this session's device list is empty. Expected "
            "in session 0 - the raw input device list is per-session.")
        return [], stats

    got = GRIDI_FAIL
    arr = None
    for _ in range(2):
        arr = (RAWINPUTDEVICELIST * count.value)()
        ctypes.set_last_error(0)
        got = user32.GetRawInputDeviceList(arr, ctypes.byref(count), cb)
        if got != GRIDI_FAIL:
            break
        err = ctypes.get_last_error()
        if err != ERROR_INSUFFICIENT_BUFFER:
            stats["error"] = ("GetRawInputDeviceList(fetch) failed: err=%d %s"
                              % (err, _win32_text(err)))
            return [], stats
        # count now holds the required size; loop and retry once.
    if got == GRIDI_FAIL:
        err = ctypes.get_last_error()
        stats["error"] = ("GetRawInputDeviceList(fetch) failed twice: err=%d %s"
                          % (err, _win32_text(err)))
        return [], stats

    stats["raw_device_total"] = int(got)
    found = []
    for i in range(got):
        dwtype = arr[i].dwType
        if dwtype == RIM_TYPEMOUSE:
            stats["type_counts"]["mouse"] += 1
            path, path_err = _device_path(user32, arr[i].hDevice)
            if path_err is not None:
                stats["unnamed_devices"] += 1
            found.append({"path": path, "path_error": path_err})
        elif dwtype == RIM_TYPEKEYBOARD:
            stats["type_counts"]["keyboard"] += 1
        else:
            stats["type_counts"]["other_hid"] += 1
    stats["raw_device_count"] = stats["type_counts"]["mouse"]
    if not found:
        stats["error"] = (
            "GetRawInputDeviceList returned %d device(s) but none of type "
            "RIM_TYPEMOUSE." % got)
    return found, stats


# --- descriptor reading ----------------------------------------------------

def _read_caps(hid, pp):
    """Return (top_usage_page, top_usage, n_input_value_caps, error)."""
    caps = ctypes.create_string_buffer(CAPS_SIZE)
    st = hid.HidP_GetCaps(pp, caps)
    if st != HIDP_STATUS_SUCCESS:
        return None, None, 0, {"api": "HidP_GetCaps", "code": st}
    raw = caps.raw
    return (_u16(raw, CAPS_USAGE_PAGE_OFF),
            _u16(raw, CAPS_USAGE_OFF),
            _u16(raw, CAPS_NUM_INPUT_VALUE_OFF),
            None)


def _read_axes(hid, pp, n_input_val):
    """Return (axes, error). axes is a list of
    {"axis": str, "mode": "ABSOLUTE"|"relative"}."""
    if n_input_val == 0:
        return [], None
    vc = ctypes.create_string_buffer(VALUE_CAPS_STRIDE * n_input_val)
    length = ctypes.c_ushort(n_input_val)
    st = hid.HidP_GetValueCaps(HIDP_INPUT, vc, ctypes.byref(length), pp)
    if st != HIDP_STATUS_SUCCESS:
        return None, {"api": "HidP_GetValueCaps", "code": st}

    raw = vc.raw
    axes = []
    for k in range(length.value):
        base = k * VALUE_CAPS_STRIDE
        usage_page = _u16(raw, base + VC_USAGE_PAGE_OFF)
        is_range = raw[base + VC_IS_RANGE_OFF]
        is_absolute = raw[base + VC_IS_ABSOLUTE_OFF]
        # NotRange.Usage is only meaningful when the cap is not a range.
        usage = _u16(raw, base + VC_NOTRANGE_USAGE_OFF) if is_range == 0 else 0
        axes.append({
            "axis": _axis_label(usage_page, usage),
            "mode": "ABSOLUTE" if is_absolute != 0 else "relative",
        })
    return axes, None


def _new_entry(path):
    return {
        "path": path,
        "hardware_id": _hardware_id(path),
        "vid": None,
        "pid": None,
        "top_level_collection": None,
        "is_pointer_collection": None,
        "axis_summary": "",
        "axis_mode_known": False,
        "has_absolute_axis": False,
        "error": None,
        "error_api": None,
        "error_code": None,
    }


def _probe(apis, entry, include_digitizers=False):
    """Open one HID collection and read its axis modes, in place.

    Always returns the entry; a failure is recorded in entry['error'] with the
    failing API and the Win32 or NTSTATUS code, rather than dropping the device.
    """
    kernel32 = apis["kernel32"]
    hid = apis["hid"]
    path = entry["path"]
    entry["vid"], entry["pid"] = _parse_vid_pid(path)

    def fail(api, code, ntstatus=False):
        entry["error_api"] = api
        if ntstatus:
            entry["error_code"] = "0x%08X" % (code & 0xFFFFFFFF)
            entry["error"] = "%s returned 0x%08X %s" % (
                api, code & 0xFFFFFFFF, _hidp_status_text(code))
        else:
            entry["error_code"] = int(code)
            entry["error"] = "%s failed: err=%d %s" % (
                api, code, _win32_text(code))
        return entry

    if not path:
        return fail("GetRawInputDeviceInfoW(RIDI_DEVICENAME)", 0)

    # CreateFileW + HidD_GetPreparsedData rather than the cleaner
    # RIDI_PREPARSEDDATA query, which returns empty for mouse collections
    # because Windows routes those through a legacy parser.
    ctypes.set_last_error(0)
    fh = kernel32.CreateFileW(path, GENERIC_NONE, FILE_SHARE_RW, None,
                              OPEN_EXISTING, 0, None)
    if fh is None or fh == INVALID_HANDLE_VALUE:
        return fail("CreateFileW", ctypes.get_last_error())

    try:
        pp = ctypes.c_void_p()
        ctypes.set_last_error(0)
        if not hid.HidD_GetPreparsedData(fh, ctypes.byref(pp)):
            return fail("HidD_GetPreparsedData", ctypes.get_last_error())
        try:
            up, usage, n_val, err = _read_caps(hid, pp)
            if err is not None:
                return fail(err["api"], err["code"], ntstatus=True)
            entry["top_level_collection"] = _top_level_label(up, usage)
            entry["is_pointer_collection"] = _is_pointer_collection(
                up, usage, include_digitizers)

            axes, err = _read_axes(hid, pp, n_val)
            if err is not None:
                return fail(err["api"], err["code"], ntstatus=True)
            entry["axis_summary"] = " ".join(
                "%s=%s" % (a["axis"], a["mode"]) for a in axes)
            entry["axis_mode_known"] = any(a["axis"] in ("X", "Y")
                                           for a in axes)
            entry["has_absolute_axis"] = any(
                a["mode"] == "ABSOLUTE" and a["axis"] in ("X", "Y")
                for a in axes)
        finally:
            hid.HidD_FreePreparsedData(pp)
    finally:
        kernel32.CloseHandle(fh)

    return entry


def _collect(apis, method, include_digitizers=False):
    """Enumerate both ways, merge by device instance, probe each collection
    once. Returns (devices, extras)."""
    use_raw = method in ("auto", "rawinput")
    use_hid = method in ("auto", "hid")

    raw_found, raw_stats = (_enumerate_rawinput(apis["user32"]) if use_raw
                            else ([], {"available": None, "error":
                                       "skipped (--method %s)" % method,
                                       "raw_device_total": 0,
                                       "raw_device_count": 0,
                                       "type_counts": {},
                                       "unnamed_devices": 0}))
    hid_paths, hid_stats = (_enumerate_hid_interfaces(apis["cfgmgr32"])
                            if use_hid
                            else ([], {"available": None, "error":
                                       "skipped (--method %s)" % method,
                                       "interface_count": 0}))

    # Merge. Raw input first so a mouse-class collection keeps that provenance,
    # then prefer the cfgmgr32 spelling of the path when both exist - it is the
    # session-independent one.
    merged = {}
    for item in raw_found:
        key = _instance_key(item["path"]) or ("rawinput-unnamed-%d" % len(merged))
        if key not in merged:
            merged[key] = {"path": item["path"], "sources": ["rawinput"],
                           "alt_paths": []}
        if item["path_error"] is not None:
            merged[key]["path_error"] = item["path_error"]
    for path in hid_paths:
        key = _instance_key(path)
        if key in merged:
            merged[key]["sources"].append("pnp_hid_interface")
            merged[key]["alt_paths"].append(merged[key]["path"])
            merged[key]["path"] = path       # prefer the PnP path
        else:
            merged[key] = {"path": path, "sources": ["pnp_hid_interface"],
                           "alt_paths": []}

    devices = []
    absent = 0
    unreadable = []

    for m in merged.values():
        entry = _new_entry(m["path"])
        _probe(apis, entry, include_digitizers)

        # If the preferred path would not open, try the other spelling before
        # calling it a failure.
        if entry["error"] is not None and m["alt_paths"]:
            for alt in m["alt_paths"]:
                retry = _new_entry(alt)
                _probe(apis, retry, include_digitizers)
                if retry["error"] is None:
                    entry = retry
                    break

        from_rawinput = "rawinput" in m["sources"]

        if entry["error"] is not None:
            code = entry["error_code"]
            api = entry["error_api"]
            # Two classes of failure are NOT lost visibility: the path names a
            # device that has already gone, or the interface opened but carries
            # no HID report descriptor at all (HidD_GetPreparsedData ->
            # ERROR_NOT_FOUND). Neither can be a pointing device.
            benign = (
                (api == "CreateFileW" and isinstance(code, int)
                 and code in ABSENT_DEVICE_ERRORS)
                or (isinstance(code, int)
                    and code in NO_DESCRIPTOR_ERRORS.get(api, ())))
            if not from_rawinput and benign:
                absent += 1
                continue
            if not from_rawinput:
                unreadable.append({"path": entry["path"],
                                   "error": entry["error"],
                                   "error_api": entry["error_api"],
                                   "error_code": entry["error_code"]})
                continue
            # A raw-input-sourced device is known to be a mouse, so a failure
            # here is a real hole in the result and must be surfaced.
            devices.append(entry)
            continue

        # Keep anything raw input called a mouse, plus any pointer collection
        # whose X/Y modes were actually read. A gamepad declares absolute X/Y,
        # so filtering on the top-level collection is load-bearing.
        if from_rawinput or (entry["is_pointer_collection"]
                             and entry["axis_mode_known"]):
            devices.append(entry)

    extras = {
        "rawinput": raw_stats,
        "pnp_hid_interface": hid_stats,
        "interfaces_absent": absent,
        "unreadable_interfaces": unreadable,
    }
    return devices, extras


# --- entry point -----------------------------------------------------------

# The nine fields that leave this script, in output order. Everything else the
# probe computes - session_id, probe_had_visibility, the per-source enumeration
# counts, the warnings list - is diagnostic scaffolding kept INTERNAL and folded
# into 'interpretation' instead. Two consequences worth knowing:
#   * Dropping our own 'status' also removes a real problem: the XSIAM action
#     results TSV already has a 'Status' column of its own ("Completed
#     Successfully"), so ours collided with it and a csv.DictReader silently
#     kept only one of the two.
#   * 'interpretation' is now the sole carrier of the session-0 safety net.
#     _build_warnings appends the full diagnostic reasons to it whenever
#     visibility was partial, so a blind run still cannot read as a clean one.
OUTPUT_FIELDS = ("host", "hid_interface_count", "device_count",
                 "devices_probed", "devices_failed", "any_absolute_axis",
                 "interpretation", "unreadable_interfaces", "devices")

# error_api and error_code are dropped because the error string already spells
# out both ("CreateFileW failed: err=5 ERROR_ACCESS_DENIED (Access is
# denied.)"). is_pointer_collection is always true for anything that reaches
# the output, and axis_mode_known is readable off axis_summary.
DEVICE_FIELDS = ("path", "hardware_id", "vid", "pid",
                 "top_level_collection", "axis_summary",
                 "has_absolute_axis", "error")

UNREADABLE_FIELDS = ("path", "error")


def run_script(absolute_only=False, method="auto", include_digitizers=False):
    """Cortex XSIAM agent script entry point. Returns a JSON-able dict
    restricted to OUTPUT_FIELDS."""
    return _project(_run_probe(absolute_only=absolute_only, method=method,
                               include_digitizers=include_digitizers))


def _project(full):
    """Reduce the internal result to the fields that are actually wanted."""
    out = {}
    for k in OUTPUT_FIELDS:
        v = full.get(k)
        if k == "devices":
            v = [dict((f, d.get(f)) for f in DEVICE_FIELDS) for d in (v or [])]
        elif k == "unreadable_interfaces":
            v = [dict((f, u.get(f)) for f in UNREADABLE_FIELDS)
                 for u in (v or [])]
        out[k] = v
    return out


def _run_probe(absolute_only=False, method="auto",
               include_digitizers=False):
    """The full probe run. Returns the rich internal dict; run_script projects
    it down to OUTPUT_FIELDS.

    Named _run_probe, not _probe: _probe is the per-device routine above, and
    shadowing it made _collect call this function instead, recursing."""
    absolute_only = _as_bool(absolute_only)
    include_digitizers = _as_bool(include_digitizers)
    method = str(method or "auto").strip().lower()
    if method not in ("auto", "rawinput", "hid"):
        method = "auto"

    if platform.system() != "Windows":
        return {"status": "error",
                "host": platform.node(),
                "probe_had_visibility": False,
                "devices": [],
                "unreadable_interfaces": [],
                "hid_interface_count": 0,
                "device_count": 0,
                "devices_probed": 0,
                "devices_failed": 0,
                "any_absolute_axis": False,
                "interpretation": "hid_axis_mode requires Windows; got %s"
                                  % platform.system()}

    result = {
        "status": "ok",
        "host": platform.node(),
        "running_as": None,
        "session_id": None,
        "in_session_0": None,
        "console_session_id": None,
        "probe_had_visibility": False,
        "raw_device_total": 0,
        "raw_device_count": 0,
        "hid_interface_count": 0,
        "devices_probed": 0,
        "devices_failed": 0,
        "device_count": 0,
        "any_absolute_axis": False,
        "visibility": "none",
        "devices": [],
        "unreadable_interfaces": [],
        "warnings": [],
        "interpretation": "",
    }

    # Session identity is gathered first and independently of the probe: if the
    # probe explodes, we still want to know where it was standing.
    try:
        sid = _session_id()
        result["session_id"] = sid
        result["in_session_0"] = (sid == 0) if sid is not None else None
        result["console_session_id"] = _console_session_id()
        result["running_as"] = _process_user()
    except Exception as e:
        result["warnings"].append("session identity unavailable: %s" % e)

    try:
        devices, extras = _collect(_apis(), method, include_digitizers)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        # traceback is not on the Cortex allowed-module list. If the sandbox
        # will not import it, that must not turn a diagnosable failure into an
        # unhandled one.
        try:
            import traceback
            result["traceback"] = traceback.format_exc()
        except Exception:
            result["traceback"] = None
        result["interpretation"] = (
            "The probe raised an exception before it finished enumerating, so "
            "this result says nothing about whether an absolute-mode pointing "
            "device is present.")
        _append_session_warning(result)
        return result

    raw = extras["rawinput"]
    pnp = extras["pnp_hid_interface"]
    result["raw_device_total"] = raw.get("raw_device_total", 0)
    result["raw_device_count"] = raw.get("raw_device_count", 0)
    result["hid_interface_count"] = pnp.get("interface_count", 0)
    result["unreadable_interfaces"] = extras["unreadable_interfaces"]

    failed = [d for d in devices if d["error"] is not None]
    result["devices_probed"] = len(devices) - len(failed)
    result["devices_failed"] = len(failed)
    result["any_absolute_axis"] = any(d["has_absolute_axis"] for d in devices)

    shown = devices
    if absolute_only:
        # Keep failed probes even under the filter. A device whose axis mode
        # could not be read is UNKNOWN, not relative, and dropping it is how a
        # blind run comes back looking clean.
        shown = [d for d in devices
                 if d["has_absolute_axis"] or d["error"] is not None]
    result["devices"] = shown
    result["device_count"] = len(shown)

    sources_ok = [name for name, st in (("rawinput", raw),
                                        ("pnp_hid_interface", pnp))
                  if st.get("available") and not st.get("error")]
    # Graded, not boolean. Note what is deliberately NOT a condition:
    # devices_probed > 0. An endpoint with no mouse-class pointer at all is not
    # blind, it is a conclusive negative.
    all_descriptorless = False
    if not sources_ok:
        result["visibility"] = "none"
    elif failed or extras["unreadable_interfaces"]:
        result["visibility"] = "partial"
    elif (result["hid_interface_count"] > 0
          and extras["interfaces_absent"] >= result["hid_interface_count"]):
        # Safety net: every interface absent or descriptorless is not credible.
        result["visibility"] = "partial"
        all_descriptorless = True
    else:
        result["visibility"] = "full"
    result["probe_had_visibility"] = result["visibility"] == "full"

    _build_warnings(result, extras, failed, sources_ok, all_descriptorless)
    return result


def _append_session_warning(result):
    if result.get("in_session_0"):
        if SESSION_0_WARNING not in result["warnings"]:
            result["warnings"].insert(0, SESSION_0_WARNING)


def _build_warnings(result, extras, failed, sources_ok,
                    all_descriptorless=False):
    """Populate warnings[] and interpretation. Every path that can produce a
    thin result must leave a reason behind here."""
    _append_session_warning(result)

    sid = result["session_id"]
    csid = result["console_session_id"]
    if sid is not None and csid is not None and sid != csid:
        result["warnings"].append(
            "Session %d, but the physical console session is %d. The raw input "
            "device list is per-session and may not contain the console's "
            "devices; the PnP (cfgmgr32) source is unaffected." % (sid, csid))
    if csid is None:
        result["warnings"].append(
            "WTSGetActiveConsoleSessionId reports no active console session.")

    raw = extras["rawinput"]
    pnp = extras["pnp_hid_interface"]
    if raw.get("error"):
        result["warnings"].append("rawinput enumeration: %s" % raw["error"])
    if raw.get("unnamed_devices"):
        result["warnings"].append(
            "%d raw input mouse handle(s) would not resolve to an interface "
            "path." % raw["unnamed_devices"])
    if pnp.get("error"):
        result["warnings"].append(
            "PnP (cfgmgr32) enumeration: %s" % pnp["error"])
    if not sources_ok:
        result["warnings"].append(
            "BOTH enumeration sources failed. No pointing device was "
            "observed.")

    if failed:
        result["warnings"].append(
            "%d mouse-class device(s) enumerated but could not be probed - see "
            "the per-device 'error' field. Their axis modes are UNKNOWN, not "
            "relative." % len(failed))
    if extras["unreadable_interfaces"]:
        result["warnings"].append(
            "%d HID interface(s) could not be opened for a reason other than "
            "'not present' - see unreadable_interfaces. Any could have been a "
            "pointing device." % len(extras["unreadable_interfaces"]))
    if result["devices_probed"] == 0 and sources_ok:
        result["warnings"].append(
            "Enumeration worked but nothing was opened and parsed - suspect "
            "the CreateFileW / HID descriptor step rather than enumeration.")
    if all_descriptorless:
        result["warnings"].append(
            "All %d enumerated HID interface(s) were absent or had no report "
            "descriptor. Nothing was parsed, so this is not a clean negative."
            % result["hid_interface_count"])

    vis = result["visibility"]
    abs_devs = [d for d in result["devices"] if d["has_absolute_axis"]]
    n_unreadable = len(result["unreadable_interfaces"])

    def _where():
        return ("as %s, session %s, console %s"
                % (result["running_as"], result["session_id"],
                   result["console_session_id"]))

    def _inconclusive(lead):
        if result["status"] == "ok":
            result["status"] = "incomplete"
        result["interpretation"] = lead
        if result["in_session_0"]:
            result["interpretation"] += (
                " Ran in session 0; re-run in the interactive user session "
                "before concluding.")
        # warnings[] is internal, so the reasons have to travel here or they
        # are lost. This is the one case where verbosity is the point.
        if result["warnings"]:
            result["interpretation"] += (
                " REASONS: " + " | ".join(result["warnings"]))

    # The governing rule: PRESENCE of evidence is conclusive whatever the
    # visibility grade; only ABSENCE of evidence needs full visibility.
    if vis == "none":
        _inconclusive("INCONCLUSIVE - both enumeration sources failed (%s)."
                      % _where())
        return

    caveat = ""
    if vis == "partial":
        caveat = (" Visibility partial: %d device(s) failed, %d interface(s) "
                  "unreadable." % (result["devices_failed"], n_unreadable))

    if abs_devs:
        ids = ", ".join(d["hardware_id"] or "unknown" for d in abs_devs)
        result["interpretation"] = (
            "ABSOLUTE POINTER DETECTED ON %s." % ids) + caveat
    elif vis == "full":
        if result["devices_probed"] == 0:
            result["interpretation"] = (
                "NO POINTING DEVICE DETECTED (%d HID interface(s) enumerated, "
                "none a Pointer or Mouse collection)."
                % result["hid_interface_count"])
        else:
            result["interpretation"] = "NO ABSOLUTE POINTER DETECTED."
    else:
        _inconclusive(
            "INCONCLUSIVE - no absolute pointer seen, but visibility was "
            "incomplete (%d read, %d failed, %d interface(s) unreadable; %s)."
            % (result["devices_probed"], result["devices_failed"],
               n_unreadable, _where()))
        return

    if result["in_session_0"]:
        # Confirms the probe was not blind, which is why the cfgmgr32 path
        # exists.
        result["interpretation"] += (
            " (Session 0 probe as %s; console session %s, visibility %s.)"
            % (result["running_as"], result["console_session_id"], vis))


# --- readable report -------------------------------------------------------
# Same layout as hid_axis_mode.ps1, so the two tools read identically.

def _fmt(v):
    """Render None as empty rather than the string 'None'."""
    return "" if v is None else str(v)


def _counts_line(full):
    """One flat line repeating every count as text. A TSV flattener renders the
    integer 1 as "True" and mangles nested objects; a flat string cannot be
    mangled that way."""
    abs_n = len([d for d in (full.get("devices") or [])
                 if d.get("has_absolute_axis")])
    return ("session=%s console=%s running_as=%s rawinput_total=%s "
            "rawinput_mice=%s pnp_interfaces=%s probed=%s failed=%s "
            "unreadable=%s absolute_mouse_class=%s visibility=%s"
            % (_fmt(full.get("session_id")),
               _fmt(full.get("console_session_id")),
               _fmt(full.get("running_as")),
               full.get("raw_device_total", 0),
               full.get("raw_device_count", 0),
               full.get("hid_interface_count", 0),
               full.get("devices_probed", 0),
               full.get("devices_failed", 0),
               len(full.get("unreadable_interfaces") or []),
               abs_n, full.get("visibility", "none")))


def _render_report(full):
    """Render the internal result as the readable report."""
    unreadable = full.get("unreadable_interfaces") or []
    warnings = full.get("warnings") or []
    lines = [
        "host %s   session %s (console %s)%s"
        % (full.get("host"), _fmt(full.get("session_id")),
           _fmt(full.get("console_session_id")),
           "   <-- SESSION 0, NON-INTERACTIVE" if full.get("in_session_0")
           else ""),
        "running as %s   status %s   probe_had_visibility %s"
        % (_fmt(full.get("running_as")), full.get("status"),
           full.get("probe_had_visibility")),
        "enumeration: raw input %s device(s), %s mouse-class; PnP HID "
        "interfaces %s" % (full.get("raw_device_total", 0),
                           full.get("raw_device_count", 0),
                           full.get("hid_interface_count", 0)),
        "probed %s, failed %s, unreadable interfaces %d"
        % (full.get("devices_probed", 0), full.get("devices_failed", 0),
           len(unreadable)),
        _counts_line(full),
        "",
    ]
    for d in full.get("devices") or []:
        lines.append(d.get("path") or "")
        lines.append("      %s" % (d.get("top_level_collection") or ""))
        if d.get("error"):
            lines.append("      ERROR %s" % d["error"])
        else:
            for tok in (d.get("axis_summary") or "").split(" "):
                if not tok:
                    continue
                absolute = (tok.startswith("X=ABSOLUTE")
                            or tok.startswith("Y=ABSOLUTE"))
                lines.append("      %s%s" % (
                    tok,
                    "  <-- ABSOLUTE (redirection / emulation signature)"
                    if absolute else ""))
        lines.append("")
    for u in unreadable:
        lines.append("UNREADABLE %s" % u.get("path"))
        lines.append("      %s" % u.get("error"))
    if unreadable:
        lines.append("")
    for w in warnings:
        lines.append("WARNING: %s" % w)
    if warnings:
        lines.append("")
    lines.append(full.get("interpretation") or "")
    return "\n".join(lines)


def _as_bool(v):
    """Cortex passes script parameters as strings, and bool('false') is True -
    which would silently turn the filter on and hide every relative device."""
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def main():
    ap = argparse.ArgumentParser(
        description="Report whether each pointing device's X/Y axes are "
                    "declared ABSOLUTE or relative in its HID report "
                    "descriptor.")
    ap.add_argument("--absolute-only", action="store_true",
                    help="show only devices with an absolute X or Y axis "
                         "(failed probes are still shown - they are unknown, "
                         "not relative)")
    ap.add_argument("--include-digitizers", action="store_true",
                    help="also treat Digitizer-page (0x0D) collections - "
                         "touchpads, touchscreens, pens - as pointing devices. "
                         "Off by default: they are ABSOLUTE by design")
    ap.add_argument("--method", default="auto",
                    choices=["auto", "rawinput", "hid"],
                    help="enumeration source: auto (both, default), rawinput "
                         "(win32k, per-session), hid (cfgmgr32 PnP, "
                         "session-independent)")
    ap.add_argument("--json", action="store_true",
                    help="emit the run_script dict as JSON instead of the "
                         "readable report")
    ap.add_argument("--out-file", metavar="PATH",
                    help="also write the output to this path as UTF-8 "
                         "without BOM")

    # parse_known_args: under Cortex the script does not own sys.argv. The
    # agent runs it inside cortex-xdr-payload.exe and leaves its own switches
    # behind (-config payload_config.json -type 2), which parse_args() would
    # treat as fatal.
    args, unknown = ap.parse_known_args()
    if unknown:
        sys.stderr.write(
            "  note: ignoring %d argument(s) not intended for this script: %s\n"
            % (len(unknown), " ".join(unknown)))

    full = _run_probe(absolute_only=args.absolute_only, method=args.method,
                      include_digitizers=args.include_digitizers)

    if args.json:
        # stdout stays valid JSON and nothing else, and only OUTPUT_FIELDS.
        text = json.dumps(_project(full), indent=2)
    else:
        text = _render_report(full)

    if args.out_file:
        parent = os.path.dirname(args.out_file)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        # Default newline translation, so the file gets the platform line
        # ending the PowerShell report writes.
        with open(args.out_file, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)

    # Under --json the report is machine-only, so the suppressed diagnostics
    # go to stderr rather than being thrown away. The readable report already
    # carries them.
    if args.json:
        sys.stderr.write(
            "  probe: as %s in session %s (console %s), rawinput %s mouse of "
            "%s device(s), PnP %s interface(s), visibility %s\n"
            % (full.get("running_as"), full.get("session_id"),
               full.get("console_session_id"), full.get("raw_device_count"),
               full.get("raw_device_total"), full.get("hid_interface_count"),
               full.get("visibility")))
        for w in full.get("warnings", []):
            sys.stderr.write("  WARNING: %s\n" % w)
    return 0 if full.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())

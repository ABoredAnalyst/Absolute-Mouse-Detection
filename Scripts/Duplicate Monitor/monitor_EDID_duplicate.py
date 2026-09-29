#!/usr/bin/env python3
r"""
monitor_EDID_duplicate.py - flag historic monitor records that share a name and
serial but disagree on EDID content (PiKVM EDID-clone tell).

Reads HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY, groups records on (name, serial), 
and outputs every record of a group when:
  - it spans 2+ instance keys,
  - its records differ in PnP ID, manufacture date or preferred resolution, and
  - at least one record is 1920x1200 or below (the most a PiKVM can capture).
Placeholder monitors (no name, MS_* PnP ID, serial "1") are skipped. A byte-exact
EDID clone shows no difference and is not detected.

Output: CSV - Display Friendly Name, Serial Number, LastWrite, Made, Resolution,
Size, Connection Status, ContainerID. A header alone means nothing was flagged.

Cortex: entry point `run(include_all="false")`; include_all outputs every record.
Returns Status, Error, Computer, Csv, Rows, Notes.
CLI: python monitor_EDID_duplicate.py [--all] [--json]
"""

import csv
import ctypes
import datetime
import io
import json
import os
import sys

DISPLAY_ROOT = r"SYSTEM\CurrentControlSet\Enum\DISPLAY"

HKEY_LOCAL_MACHINE = 0x80000002
# KEY_READ | KEY_WOW64_64KEY
KEY_READ64 = 0x20019 | 0x0100
ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234
ERROR_NO_MORE_ITEMS = 259
REG_SZ = 1

CSV_COLUMNS = ("Display Friendly Name", "Serial Number", "LastWrite", "Made",
               "Resolution", "Size", "Connection Status", "ContainerID")

OUTPUT_KEYS = ("Status", "Error", "Computer", "Csv", "Rows", "Notes")



class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", ctypes.c_uint32), ("hi", ctypes.c_uint32)]


def _load_advapi():
    # HKEY is pointer-sized: c_void_p, or a 64-bit handle is truncated
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    vp = ctypes.c_void_p
    dw = ctypes.c_uint32
    adv.RegOpenKeyExW.argtypes = [vp, ctypes.c_wchar_p, dw, dw, ctypes.POINTER(vp)]
    adv.RegOpenKeyExW.restype = ctypes.c_long
    adv.RegCloseKey.argtypes = [vp]
    adv.RegCloseKey.restype = ctypes.c_long
    adv.RegEnumKeyExW.argtypes = [vp, dw, ctypes.c_wchar_p, ctypes.POINTER(dw),
                                  vp, vp, vp, ctypes.POINTER(_FILETIME)]
    adv.RegEnumKeyExW.restype = ctypes.c_long
    adv.RegQueryValueExW.argtypes = [vp, ctypes.c_wchar_p, vp, ctypes.POINTER(dw),
                                     vp, ctypes.POINTER(dw)]
    adv.RegQueryValueExW.restype = ctypes.c_long
    return adv


def _filetime_iso(ft):
    v = (ft.hi << 32) | ft.lo
    if not v:
        return None
    try:
        t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


class _Registry(object):
    def __init__(self):
        self.adv = _load_advapi()

    def _open(self, subkey):
        h = ctypes.c_void_p()
        rc = self.adv.RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ64,
                                    ctypes.byref(h))
        return h if rc == ERROR_SUCCESS else None

    def subkeys(self, subkey):
        """[(name, last_write_iso)]"""
        h = self._open(subkey)
        if h is None:
            return []
        out = []
        try:
            i = 0
            while True:
                buf = ctypes.create_unicode_buffer(256)
                n = ctypes.c_uint32(256)
                ft = _FILETIME()
                rc = self.adv.RegEnumKeyExW(h, i, buf, ctypes.byref(n),
                                            None, None, None, ctypes.byref(ft))
                if rc == ERROR_NO_MORE_ITEMS:
                    break
                if rc == ERROR_SUCCESS:
                    out.append((buf.value, _filetime_iso(ft)))
                elif rc != ERROR_MORE_DATA:
                    break
                i += 1
        finally:
            self.adv.RegCloseKey(h)
        return out

    def value(self, subkey, name):
        """(type, bytes) or None."""
        h = self._open(subkey)
        if h is None:
            return None
        try:
            typ = ctypes.c_uint32()
            size = ctypes.c_uint32(0)
            rc = self.adv.RegQueryValueExW(h, name, None, ctypes.byref(typ),
                                           None, ctypes.byref(size))
            if rc not in (ERROR_SUCCESS, ERROR_MORE_DATA) or size.value == 0:
                return None
            buf = ctypes.create_string_buffer(size.value)
            rc = self.adv.RegQueryValueExW(h, name, None, ctypes.byref(typ),
                                           buf, ctypes.byref(size))
            if rc != ERROR_SUCCESS:
                return None
            return typ.value, buf.raw[:size.value]
        finally:
            self.adv.RegCloseKey(h)

    def string(self, subkey, name):
        v = self.value(subkey, name)
        if not v or v[0] != REG_SZ:
            return None
        return v[1].decode("utf-16-le", "replace").rstrip("\x00") or None


def _present_checker():
    """f(instance_id) -> True / False / None. CM_Locate_DevNode only finds devnodes
    in the live device tree, so an unplugged monitor is False."""
    try:
        cm = ctypes.WinDLL("cfgmgr32")
        cm.CM_Locate_DevNodeW.argtypes = [ctypes.POINTER(ctypes.c_uint32),
                                          ctypes.c_wchar_p, ctypes.c_uint32]
        cm.CM_Locate_DevNodeW.restype = ctypes.c_uint32
    except Exception:
        return lambda _iid: None

    def check(iid):
        try:
            di = ctypes.c_uint32()
            return cm.CM_Locate_DevNodeW(ctypes.byref(di), iid, 0) == 0
        except Exception:
            return None
    return check



def _descriptor_text(edid, tag):
    for off in (54, 72, 90, 108):
        if (edid[off] == 0 and edid[off + 1] == 0 and edid[off + 2] == 0
                and edid[off + 3] == tag):
            chars = []
            for b in bytearray(edid[off + 5:off + 18]):
                if b == 0x0A:
                    break
                chars.append(chr(b))
            return "".join(chars).strip() or None
    return None


def _parse_edid(raw):
    e = bytearray(raw)
    if len(e) < 128:
        return None
    serial_num = e[12] | (e[13] << 8) | (e[14] << 16) | (e[15] << 24)
    pref = ""
    if (e[54] | e[55]) != 0:
        h = e[56] + ((e[58] & 0xF0) << 4)
        v = e[59] + ((e[61] & 0xF0) << 4)
        pref = "{0}x{1}".format(h, v)
    return {
        "Name": _descriptor_text(e, 0xFC),
        "SerialStr": _descriptor_text(e, 0xFF),
        "SerialNum": serial_num,
        "Made": "{0} wk{1}".format(1990 + e[17], e[16]),
        "PreferredResolution": pref,
        "Size": "{0}x{1} cm".format(e[21], e[22]) if e[21] and e[22] else "",
    }



def _collect_records():
    reg = _Registry()
    present = _present_checker()
    records = []
    for hw, _ in reg.subkeys(DISPLAY_ROOT):
        for inst, last_write in reg.subkeys(DISPLAY_ROOT + "\\" + hw):
            base = DISPLAY_ROOT + "\\" + hw + "\\" + inst
            v = reg.value(base + "\\Device Parameters", "EDID")
            if not v:
                continue
            p = _parse_edid(v[1])
            if not p:
                continue
            serial = p["SerialStr"] or (str(p["SerialNum"]) if p["SerialNum"] else None)
            iid = "DISPLAY\\" + hw + "\\" + inst
            records.append({
                "InstanceId": iid,
                "PnPId": hw,
                "Name": p["Name"],
                "Serial": serial,
                "Made": p["Made"],
                "PreferredResolution": p["PreferredResolution"],
                "Size": p["Size"],
                "ContainerId": reg.string(base, "ContainerID"),
                "Present": present(iid),
                "LastWrite": last_write,
            })
    return records


def _is_placeholder(r):
    return (not r["Name"] or r["PnPId"].upper().startswith("MS_")
            or (r["Serial"] or "").strip() == "1")


PIKVM_MAX_W, PIKVM_MAX_H = 1920, 1200


def _pikvm_capable(res):
    """Unknown or unparseable resolutions do not count."""
    try:
        w, h = res.split("x")
        return int(w) <= PIKVM_MAX_W and int(h) <= PIKVM_MAX_H
    except (AttributeError, ValueError):
        return False


def _flagged(records):
    """Every record of each group that meets the criteria in the module docstring."""
    groups = {}
    for r in records:
        if r["Serial"] and not _is_placeholder(r):
            groups.setdefault((r["Name"], r["Serial"]), []).append(r)

    out = []
    for key in sorted(groups, key=str):
        rows = groups[key]
        if len(set(r["InstanceId"] for r in rows)) < 2:
            continue
        if not any(_pikvm_capable(r["PreferredResolution"]) for r in rows):
            continue
        if (len(set(r["PnPId"] for r in rows)) > 1
                or len(set(r["Made"] for r in rows)) > 1
                or len(set(r["PreferredResolution"] for r in rows)) > 1):
            out.extend(sorted(rows, key=lambda r: r["LastWrite"] or ""))
    return out


def _as_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _status(present):
    return "Connected" if present is True else "Not connected" if present is False else "Unknown"


def _row(r):
    return {
        "Display Friendly Name": r["Name"] or "",
        "Serial Number": r["Serial"] or "",
        "LastWrite": r["LastWrite"] or "",
        "Made": r["Made"],
        "Resolution": r["PreferredResolution"],
        "Size": r["Size"],
        "Connection Status": _status(r["Present"]),
        "ContainerID": r["ContainerId"] or "",
    }


def _csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([r[c] for c in CSV_COLUMNS])
    return buf.getvalue()


def _empty(status, error=None):
    out = dict((k, None) for k in OUTPUT_KEYS)
    out.update({
        "Status": status,
        "Error": error,
        "Computer": os.environ.get("COMPUTERNAME", ""),
        "Csv": _csv([]),
        "Rows": [],
        "Notes": [],
    })
    return out


def run(include_all="false"):
    if os.name != "nt":
        return _empty("Error", "Windows only")
    try:
        records = _collect_records()
    except Exception as exc:
        return _empty("Error", "{0}: {1}".format(type(exc).__name__, exc))

    if _as_bool(include_all):
        chosen = sorted(records, key=lambda r: (r["Name"] or "", r["Serial"] or "",
                                                r["LastWrite"] or ""))
    else:
        chosen = _flagged(records)
    rows = [_row(r) for r in chosen]

    out = _empty("Success")
    out["Rows"] = rows
    out["Csv"] = _csv(rows)
    if not records:
        out["Notes"].append("No monitor EDID records found; an empty result is "
                            "not a negative.")
    return out


def main(argv):
    result = run("true" if "--all" in argv else "false")
    if "--json" in argv:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["Error"]:
        print("Error: {0}".format(result["Error"]))
    else:
        sys.stdout.write(result["Csv"])
        for n in result["Notes"]:
            print("# {0}".format(n))
    return 0 if result["Status"] == "Success" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

<#
.SYNOPSIS
    Report whether each connected pointing device declares its X and Y axes
    ABSOLUTE or RELATIVE in its HID report descriptor.

.DESCRIPTION
    Enumerates HID collections two ways and merges them by device instance:

      * GetRawInputDeviceList (user32) - per terminal-services session, so it is
        empty or short outside the interactive session, but it authoritatively
        marks a collection as mouse-class.
      * CM_Get_Device_Interface_ListW (cfgmgr32) - every present
        GUID_DEVINTERFACE_HID interface, from the PnP manager, with no session
        affinity.

    Each merged collection is opened with CreateFileW at zero access rights (no
    administrator rights needed, and the only access that works on mouse and
    keyboard collections) and its descriptor read via HidD_GetPreparsedData and
    HidP_GetValueCaps. The IsAbsolute field of the X and Y HIDP_VALUE_CAPS is
    the reported axis mode; it is the decoded Relative flag of the descriptor's
    Input main item, and there is no registry equivalent.

    Only Pointer (usage page 0x01, usage 0x01) and Mouse (0x01/0x02) top-level
    collections count as pointing devices. Digitizer-page (0x0D) collections are
    absolute by design and are excluded unless -IncludeDigitizers is passed.

    A device must be connected to be read. Output always carries the session id,
    per-source enumeration counts and per-device errors, and grades visibility
    as full, partial or none, so an empty result is never mistaken for a
    conclusive negative. IsAbsolute reflects only what a device declares.

.PARAMETER AbsoluteOnly
    Show only devices with an absolute X or Y axis. Failed probes are still
    shown - their axis mode is unknown, not relative.

.PARAMETER IncludeDigitizers
    Also treat Digitizer-page (0x0D) collections - touchpads, touchscreens,
    pens - as pointing devices.

.PARAMETER Json
    Emit the result as JSON instead of the readable report.

.PARAMETER OutFile
    Write the output to this path as UTF-8 without BOM, as well as to stdout.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -NoProfile -File hid_axis_mode.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -NoProfile -File hid_axis_mode.ps1 -AbsoluteOnly

.EXAMPLE
    powershell -ExecutionPolicy Bypass -NoProfile -File hid_axis_mode.ps1 -Json -OutFile C:\temp\hid_axis.json
#>
[CmdletBinding()]
param(
    [switch] $AbsoluteOnly,
    [switch] $IncludeDigitizers,
    [switch] $Json,
    [string] $OutFile
)

$ErrorActionPreference = 'Stop'

$cs = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// One enumeration source: its paths, its tallies, and why it found what it did.
public class HidEnumResult {
  public List<string> Paths = new List<string>();
  public int Total, Mice, Keyboards, Other, Unnamed, InterfaceCount;
  public string Error;
}

// One probed collection.
public class HidProbeResult {
  public string TopLevel = "", AxisSummary = "";
  public bool   IsPointer, HasAbsoluteXY;
  public string Error, ErrorApi, ErrorCode;
}

public class HidAxisMode {
  [StructLayout(LayoutKind.Sequential)] struct RIDL { public IntPtr hDevice; public uint dwType; }
  [StructLayout(LayoutKind.Sequential)]
  struct GUID { public uint Data1; public ushort Data2; public ushort Data3;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)] public byte[] Data4; }

  [DllImport("user32.dll", SetLastError=true)] static extern uint GetRawInputDeviceList(IntPtr l, ref uint n, uint cb);
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern uint GetRawInputDeviceInfoW(IntPtr h, uint cmd, IntPtr data, ref uint size);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern bool ProcessIdToSessionId(uint pid, out uint sid);
  [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
  [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
  [DllImport("hid.dll")] static extern bool HidD_GetPreparsedData(IntPtr h, out IntPtr pp);
  [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr pp);
  [DllImport("hid.dll")] static extern int HidP_GetCaps(IntPtr pp, byte[] caps);
  [DllImport("hid.dll")] static extern int HidP_GetValueCaps(int rt, byte[] vc, ref ushort len, IntPtr pp);
  [DllImport("cfgmgr32.dll", CharSet=CharSet.Unicode)]
  static extern int CM_Get_Device_Interface_List_SizeW(out uint len, ref GUID cls, string devid, uint flags);
  [DllImport("cfgmgr32.dll", CharSet=CharSet.Unicode)]
  static extern int CM_Get_Device_Interface_ListW(ref GUID cls, string devid, IntPtr buf, uint buflen, uint flags);

  const uint RIDI_DEVICENAME=0x20000007, RIM_TYPEMOUSE=0, RIM_TYPEKEYBOARD=1;
  const uint GENERIC_NONE=0, FILE_SHARE_RW=3, OPEN_EXISTING=3;
  const int HIDP_INPUT=0, HIDP_STATUS_SUCCESS=unchecked((int)0x00110000);
  const uint CM_PRESENT=1;
  const int CR_SUCCESS=0, CR_BUFFER_SMALL=0x1A;
  const uint INVALID=unchecked((uint)-1);

  // HIDP_CAPS (64 bytes): Usage USHORT @0, UsagePage USHORT @2,
  //   NumberInputValueCaps USHORT @48.
  // HIDP_VALUE_CAPS (72 bytes): UsagePage USHORT @0, IsRange BOOLEAN @12,
  //   IsAbsolute BOOLEAN @15, NotRange.Usage USHORT @56 (valid when !IsRange).
  const int CAPS_SIZE=64, VCAPS_SIZE=72;

  public static uint SessionId() { uint s; return ProcessIdToSessionId(GetCurrentProcessId(), out s) ? s : INVALID; }
  public static uint ConsoleSessionId() { return WTSGetActiveConsoleSessionId(); }

  static string DevName(IntPtr h){
    uint sz=0;
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, IntPtr.Zero, ref sz);
    if(sz==0) return "";
    IntPtr b=Marshal.AllocHGlobal((int)((sz+1)*2));
    try{
      if(GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, b, ref sz)==INVALID) return "";
      return Marshal.PtrToStringUni(b) ?? "";
    } finally { Marshal.FreeHGlobal(b); }
  }

  // Per-session enumeration through win32k. Expected to be empty in session 0.
  public static HidEnumResult RawInputMicePaths(){
    var r=new HidEnumResult();
    uint n=0, cb=(uint)Marshal.SizeOf(typeof(RIDL));
    if(GetRawInputDeviceList(IntPtr.Zero, ref n, cb)==INVALID){
      r.Error="GetRawInputDeviceList(count probe) failed: err="+Marshal.GetLastWin32Error(); return r; }
    if(n==0){ r.Error="GetRawInputDeviceList reported 0 raw input devices of any type. "+
                      "The call succeeded; this session's device list is empty. Expected in "+
                      "session 0 - the raw input device list is per-session."; return r; }
    IntPtr buf=Marshal.AllocHGlobal((int)(n*cb));
    try{
      uint got=GetRawInputDeviceList(buf, ref n, cb);
      if(got==INVALID){
        r.Error="GetRawInputDeviceList(fetch) failed: err="+Marshal.GetLastWin32Error(); return r; }
      r.Total=(int)got;
      for(int i=0;i<got;i++){
        var d=(RIDL)Marshal.PtrToStructure((IntPtr)(buf.ToInt64()+i*cb), typeof(RIDL));
        if(d.dwType==RIM_TYPEMOUSE){
          r.Mice++;
          string p=DevName(d.hDevice);
          if(p.Length==0) r.Unnamed++; else r.Paths.Add(p);
        } else if(d.dwType==RIM_TYPEKEYBOARD) r.Keyboards++;
        else r.Other++;
      }
      if(r.Paths.Count==0)
        r.Error="GetRawInputDeviceList returned "+got+" device(s) but no usable RIM_TYPEMOUSE path.";
      return r;
    } finally { Marshal.FreeHGlobal(buf); }
  }

  // Session-independent enumeration through the PnP manager.
  public static HidEnumResult HidInterfacePaths(){
    var r=new HidEnumResult();
    var g=new GUID(); g.Data1=0x4D1E55B2; g.Data2=0xF16F; g.Data3=0x11CF;
    g.Data4=new byte[]{0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30};
    for(int attempt=0; attempt<3; attempt++){
      uint len=0;
      int cr=CM_Get_Device_Interface_List_SizeW(out len, ref g, null, CM_PRESENT);
      if(cr!=CR_SUCCESS){ r.Error="CM_Get_Device_Interface_List_SizeW returned CONFIGRET "+cr; return r; }
      if(len==0){ r.Error="the PnP manager reports 0 present GUID_DEVINTERFACE_HID interfaces"; return r; }
      IntPtr buf=Marshal.AllocHGlobal((int)(len*2));
      string all;
      try{
        cr=CM_Get_Device_Interface_ListW(ref g, null, buf, len, CM_PRESENT);
        if(cr==CR_BUFFER_SMALL) continue;   // list grew between the two calls; re-size
        if(cr!=CR_SUCCESS){ r.Error="CM_Get_Device_Interface_ListW returned CONFIGRET "+cr; return r; }
        all=Marshal.PtrToStringUni(buf,(int)len);
      } finally { Marshal.FreeHGlobal(buf); }
      foreach(string s in all.Split('\0')) if(s.Length>0) r.Paths.Add(s);
      r.InterfaceCount=r.Paths.Count;
      return r;
    }
    r.Error="CM_Get_Device_Interface_ListW kept returning CR_BUFFER_SMALL - the device list is churning";
    return r;
  }

  static string TopLevelName(int up, int usage){
    if(up==0x01) switch(usage){
      case 0x01: return "Pointer";   case 0x02: return "Mouse";
      case 0x04: return "Joystick";  case 0x05: return "Game Pad";
      case 0x06: return "Keyboard";  case 0x07: return "Keypad";
      case 0x08: return "Multi-axis Controller"; }
    if(up==0x0C && usage==0x01) return "Consumer Control";
    if(up==0x0D) switch(usage){
      case 0x01: return "Digitizer"; case 0x02: return "Pen";
      case 0x03: return "Light Pen"; case 0x04: return "Touch Screen";
      case 0x05: return "Touch Pad"; case 0x0E: return "Device Configuration";
      case 0x20: return "Stylus"; }
    return null;
  }

  static string AxisLabel(int up, int usage){
    if(up==0x01){
      if(usage==0x30) return "X";
      if(usage==0x31) return "Y";
      if(usage==0x38) return "Wheel"; }
    return string.Format("UP{0:X2}/U{1:X2}", up, usage);
  }

  static HidProbeResult Fail(HidProbeResult r, string api, string message, string code){
    r.Error=message; r.ErrorApi=api; r.ErrorCode=code; return r;
  }

  // Open one collection and read the declared mode of each of its input axes.
  public static HidProbeResult Probe(string path, bool includeDigitizers){
    var r=new HidProbeResult();
    IntPtr fh=CreateFileW(path, GENERIC_NONE, FILE_SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
    if(fh==(IntPtr)(-1) || fh==IntPtr.Zero){
      int e=Marshal.GetLastWin32Error();
      return Fail(r, "CreateFileW", "CreateFileW failed: err="+e, e.ToString()); }
    IntPtr pp=IntPtr.Zero;
    try{
      if(!HidD_GetPreparsedData(fh, out pp)){
        int e=Marshal.GetLastWin32Error();
        return Fail(r, "HidD_GetPreparsedData", "HidD_GetPreparsedData failed: err="+e, e.ToString()); }
      byte[] caps=new byte[CAPS_SIZE];
      int st=HidP_GetCaps(pp, caps);
      if(st!=HIDP_STATUS_SUCCESS)
        return Fail(r, "HidP_GetCaps", "HidP_GetCaps returned 0x"+st.ToString("X8"), "0x"+st.ToString("X8"));
      int usage=BitConverter.ToUInt16(caps,0);
      int up=BitConverter.ToUInt16(caps,2);
      int nInputVal=BitConverter.ToUInt16(caps,48);
      string tl=TopLevelName(up,usage);
      r.TopLevel=(tl==null ? "" : tl+" ")+string.Format("(UP{0:X2}/U{1:X2})", up, usage);
      // A Digitizer-page collection declares ABSOLUTE by design, so it counts as
      // a pointing device only when asked for.
      r.IsPointer=(up==0x01 && (usage==0x01 || usage==0x02)) || (includeDigitizers && up==0x0D);
      if(nInputVal==0) return r;

      byte[] vc=new byte[VCAPS_SIZE*nInputVal];
      ushort len=(ushort)nInputVal;
      st=HidP_GetValueCaps(HIDP_INPUT, vc, ref len, pp);
      if(st!=HIDP_STATUS_SUCCESS)
        return Fail(r, "HidP_GetValueCaps", "HidP_GetValueCaps returned 0x"+st.ToString("X8"), "0x"+st.ToString("X8"));
      var sb=new StringBuilder();
      for(int k=0;k<len;k++){
        int b0=k*VCAPS_SIZE;
        int vup=BitConverter.ToUInt16(vc,b0+0);
        bool isRange=vc[b0+12]!=0;
        bool isAbsolute=vc[b0+15]!=0;
        string axis=AxisLabel(vup, isRange ? 0 : BitConverter.ToUInt16(vc,b0+56));
        if(sb.Length>0) sb.Append(" ");
        sb.Append(axis).Append("=").Append(isAbsolute ? "ABSOLUTE" : "relative");
        if(isAbsolute && (axis=="X" || axis=="Y")) r.HasAbsoluteXY=true;
      }
      r.AxisSummary=sb.ToString();
      return r;
    } finally { if(pp!=IntPtr.Zero) HidD_FreePreparsedData(pp); CloseHandle(fh); }
  }
}
"@

if (-not ('HidAxisMode' -as [type])) { Add-Type -TypeDefinition $cs -Language CSharp }

# --- helpers ---------------------------------------------------------------

# A raw input path and a cfgmgr32 path for the same collection differ only in
# the trailing interface GUID. The hardware id and instance id are the identity.
function Get-InstanceKey([string] $path) {
    if ([string]::IsNullOrEmpty($path)) { return '' }
    $p = $path.ToUpperInvariant().Split('#')
    if ($p.Count -ge 3) { return ($p[1] + '#' + $p[2]) }
    return $path.ToUpperInvariant()
}

function Get-HardwareId([string] $path) {
    $p = $path.Split('#')
    if ($p.Count -ge 2) { return $p[1] }
    return ''
}

# The four hex digits immediately following $marker in an upper-cased path.
function Get-Hex4([string] $up, [string] $marker) {
    $i = $up.IndexOf($marker)
    if ($i -lt 0) { return $null }
    $frag = $up.Substring($i + $marker.Length, [Math]::Min(4, $up.Length - $i - $marker.Length))
    if ($frag -match '^[0-9A-F]{4}$') { return $frag }
    return $null
}

# On a cfgmgr32 path these mean "not there", not "denied", and must not be
# counted as lost visibility: ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
# ERROR_NO_SUCH_DEVICE, ERROR_DEVICE_NOT_CONNECTED.
$AbsentDeviceErrors = @('2', '3', '433', '1167')
# HidD_GetPreparsedData returning ERROR_NOT_FOUND means the interface carries no
# HID report descriptor at all, so it cannot be a pointing device and nothing was
# lost. This is the bulk of unreadable interfaces on a normal endpoint.
$NoDescriptorError = '1168'

$Win32ErrorNames = @{
    '0'='ERROR_SUCCESS'; '1'='ERROR_INVALID_FUNCTION'; '2'='ERROR_FILE_NOT_FOUND';
    '3'='ERROR_PATH_NOT_FOUND'; '5'='ERROR_ACCESS_DENIED'; '6'='ERROR_INVALID_HANDLE';
    '21'='ERROR_NOT_READY'; '31'='ERROR_GEN_FAILURE'; '32'='ERROR_SHARING_VIOLATION';
    '50'='ERROR_NOT_SUPPORTED'; '87'='ERROR_INVALID_PARAMETER';
    '122'='ERROR_INSUFFICIENT_BUFFER'; '433'='ERROR_NO_SUCH_DEVICE';
    '998'='ERROR_NOACCESS'; '1167'='ERROR_DEVICE_NOT_CONNECTED';
    '1359'='ERROR_INTERNAL_ERROR'; '1400'='ERROR_INVALID_WINDOW_HANDLE'
}

function Expand-ErrorText([string] $err, [string] $code) {
    if ($code -and $Win32ErrorNames.ContainsKey($code)) { return ($err + ' ' + $Win32ErrorNames[$code]) }
    return $err
}

# --- session identity (gathered first, independent of the probe) -----------

$sid  = [HidAxisMode]::SessionId()
$csid = [HidAxisMode]::ConsoleSessionId()
if ($sid  -eq 0xFFFFFFFF) { $sid  = $null }
if ($csid -eq 0xFFFFFFFF) { $csid = $null }

$result = [ordered]@{
    status                = 'ok'
    host                  = $env:COMPUTERNAME
    running_as            = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    session_id            = $sid
    in_session_0          = ($sid -eq 0)
    console_session_id    = $csid
    probe_had_visibility  = $false
    raw_device_total      = 0
    raw_device_count      = 0
    hid_interface_count   = 0
    devices_probed        = 0
    devices_failed        = 0
    device_count          = 0
    any_absolute_axis     = $false
    devices               = @()
    counts                = ''
    unreadable_interfaces = @()
    warnings              = @()
    interpretation        = ''
}

# --- enumerate both ways and merge by device instance ----------------------

$raw = [HidAxisMode]::RawInputMicePaths()
$pnp = [HidAxisMode]::HidInterfacePaths()

$merged = [ordered]@{}
foreach ($p in $raw.Paths) {
    $k = Get-InstanceKey $p
    if (-not $merged.Contains($k)) { $merged[$k] = @{ path = $p; sources = @('rawinput'); alt = @() } }
}
foreach ($p in $pnp.Paths) {
    $k = Get-InstanceKey $p
    if ($merged.Contains($k)) {
        $m = $merged[$k]
        $m.sources += 'pnp_hid_interface'
        $m.alt     += $m.path
        $m.path     = $p        # prefer the session-independent path
    } else {
        $merged[$k] = @{ path = $p; sources = @('pnp_hid_interface'); alt = @() }
    }
}

# --- probe every merged collection -----------------------------------------

# ArrayList, not List[object]: in Windows PowerShell 5.1 an @() around a
# New-Object-constructed List[object] throws 'Argument types do not match'.
$devices     = New-Object System.Collections.ArrayList
$unreadable  = New-Object System.Collections.ArrayList
$absentCount = 0

foreach ($k in $merged.Keys) {
    $m        = $merged[$k]
    $usedPath = $m.path
    $rec      = [HidAxisMode]::Probe($usedPath, $IncludeDigitizers.IsPresent)

    # If the preferred path will not open, try the other spelling of the same
    # instance before calling it a failure.
    if ($rec.Error) {
        foreach ($alt in $m.alt) {
            $retry = [HidAxisMode]::Probe($alt, $IncludeDigitizers.IsPresent)
            if (-not $retry.Error) { $rec = $retry; $usedPath = $alt; break }
        }
    }

    $fromRaw = $m.sources -contains 'rawinput'

    # A failure on a PnP-only interface is either benign (absent, or no report
    # descriptor) or a genuine blind spot. A failure on a raw-input-sourced path
    # is always a blind spot - a known mouse that would not open - so it falls
    # through and is reported as a device carrying an error.
    if ($rec.Error -and -not $fromRaw) {
        $benign = (($rec.ErrorApi -eq 'CreateFileW')           -and ($AbsentDeviceErrors -contains $rec.ErrorCode)) -or
                  (($rec.ErrorApi -eq 'HidD_GetPreparsedData') -and ($rec.ErrorCode -eq $NoDescriptorError))
        if ($benign) { $absentCount++; continue }
        [void] $unreadable.Add([pscustomobject] [ordered]@{
            path        = $usedPath
            hardware_id = (Get-HardwareId $usedPath)
            error       = (Expand-ErrorText $rec.Error $rec.ErrorCode)
            error_api   = $rec.ErrorApi
            error_code  = $rec.ErrorCode
        })
        continue
    }

    $up  = $usedPath.ToUpperInvariant()
    $vid = Get-Hex4 $up 'VID_'
    if ($null -eq $vid) { $vid = Get-Hex4 $up 'VEN_' }

    $entry = [pscustomobject] [ordered]@{
        path                  = $usedPath
        hardware_id           = (Get-HardwareId $usedPath)
        vid                   = $vid
        pid                   = (Get-Hex4 $up 'PID_')
        top_level_collection  = $rec.TopLevel
        is_pointer_collection = $rec.IsPointer
        axis_summary          = $rec.AxisSummary
        axis_mode_known       = ($rec.AxisSummary -match '(^|\s)(X|Y)=')
        has_absolute_axis     = $rec.HasAbsoluteXY
        error                 = (Expand-ErrorText $rec.Error $rec.ErrorCode)
        error_api             = $rec.ErrorApi
        error_code            = $rec.ErrorCode
    }

    # Keep anything raw input called a mouse, plus any pointer collection whose
    # X/Y modes were actually read. Everything else is not a pointing device.
    if ($fromRaw -or ($entry.is_pointer_collection -and $entry.axis_mode_known)) {
        [void] $devices.Add($entry)
    }
}

# --- assemble ---------------------------------------------------------------

$failed = @($devices | Where-Object { $_.error })
# -AbsoluteOnly retains every absolute device, so this set is the same before and
# after the display filter and only needs computing once.
$absDevs = @($devices | Where-Object { $_.has_absolute_axis })

$result.raw_device_total      = $raw.Total
$result.raw_device_count      = $raw.Mice
$result.hid_interface_count   = $pnp.InterfaceCount
$result.unreadable_interfaces = @($unreadable)
$result.devices_probed        = $devices.Count - $failed.Count
$result.devices_failed        = $failed.Count
$result.any_absolute_axis     = ($absDevs.Count -gt 0)

# Keep failed probes even under the filter. A device whose axis mode could not be
# read is UNKNOWN, not relative, and dropping it is how a blind run comes back
# looking clean.
$shown = if ($AbsoluteOnly) { @($devices | Where-Object { $_.has_absolute_axis -or $_.error }) }
         else               { @($devices) }
$result.devices      = $shown
$result.device_count = $shown.Count

$sourcesOk = @()
if (-not $raw.Error) { $sourcesOk += 'rawinput' }
if (-not $pnp.Error) { $sourcesOk += 'pnp_hid_interface' }

# Graded, not boolean. Note what is deliberately NOT a condition: devices_probed
# -gt 0. An endpoint with no mouse-class pointer at all is not blind, it is a
# conclusive negative.
$allDescriptorless = $false
if ($sourcesOk.Count -eq 0) { $visibility = 'none' }
elseif ($failed.Count -gt 0 -or $unreadable.Count -gt 0) { $visibility = 'partial' }
elseif ($result.hid_interface_count -gt 0 -and $absentCount -ge $result.hid_interface_count) {
    # Safety net: every interface absent or descriptorless is not credible.
    $visibility = 'partial'
    $allDescriptorless = $true
}
else { $visibility = 'full' }
$result.probe_had_visibility = ($visibility -eq 'full')

# --- warnings ---------------------------------------------------------------

$w = New-Object System.Collections.ArrayList
if ($result.in_session_0) {
    [void] $w.Add(
      'SESSION 0. This process is in the non-interactive services session, so a zero ' +
      'or partial result may mean the probe was blind rather than clean. ' +
      'GetRawInputDeviceList is per-session and is expected to be empty here; the ' +
      'cfgmgr32 PnP path should still see the devices. If it is also empty, or every ' +
      'CreateFileW returns err=5 ERROR_ACCESS_DENIED, re-run in the interactive user ' +
      'session - for example a scheduled task with LogonType=InteractiveToken.')
}
if ($null -ne $sid -and $null -ne $csid -and $sid -ne $csid) {
    # Extra parens: inside a method call, a bare '-f a, b' would be parsed as two
    # arguments to Add(), not one format expression.
    [void] $w.Add((("Session {0}, but the physical console session is {1}. The raw input " +
             "device list is per-session and may not contain the console's devices; " +
             "the PnP (cfgmgr32) source is unaffected.") -f $sid, $csid))
}
if ($null -eq $csid) {
    [void] $w.Add('WTSGetActiveConsoleSessionId reports no active console session.')
}
if ($raw.Error) { [void] $w.Add('rawinput enumeration: ' + $raw.Error) }
if ($raw.Unnamed -gt 0) {
    [void] $w.Add(("{0} raw input mouse handle(s) would not resolve to an interface path." -f $raw.Unnamed))
}
if ($pnp.Error) { [void] $w.Add('PnP (cfgmgr32) enumeration: ' + $pnp.Error) }
if ($sourcesOk.Count -eq 0) {
    [void] $w.Add('BOTH enumeration sources failed. No pointing device was observed.')
}
if ($failed.Count -gt 0) {
    [void] $w.Add((("{0} mouse-class device(s) enumerated but could not be probed - see the " +
             "per-device 'error' field. Their axis modes are UNKNOWN, not relative.") -f $failed.Count))
}
if ($unreadable.Count -gt 0) {
    [void] $w.Add((("{0} HID interface(s) could not be opened for a reason other than 'not " +
             "present' - see unreadable_interfaces. Any could have been a pointing " +
             "device.") -f $unreadable.Count))
}
if ($result.devices_probed -eq 0 -and $sourcesOk.Count -gt 0) {
    [void] $w.Add('Enumeration worked but nothing was opened and parsed - suspect the ' +
           'CreateFileW / HID descriptor step rather than enumeration.')
}
if ($allDescriptorless) {
    [void] $w.Add((('All {0} enumerated HID interface(s) were absent or had no report ' +
             'descriptor. Nothing was parsed, so this is not a clean negative.') -f $result.hid_interface_count))
}
$result.warnings = @($w)

# --- interpretation ---------------------------------------------------------

# The governing rule: PRESENCE of evidence is conclusive whatever the visibility
# grade; only ABSENCE of evidence needs full visibility.
# Every interpretation below is (concatenation) -f args: the format operator
# binds tighter than '+', so an unparenthesised concatenation would format only
# its last literal and drop the arguments.
$whereRan = ('as {0}, session {1}, console {2}' -f
             $result.running_as, $result.session_id, $result.console_session_id)

$caveat = ''
if ($visibility -eq 'partial') {
    $caveat = (' Visibility partial: {0} device(s) failed, {1} interface(s) unreadable.') -f
              $result.devices_failed, $unreadable.Count
}

if ($visibility -eq 'none') {
    $result.status = 'incomplete'
    $result.interpretation = 'INCONCLUSIVE - both enumeration sources failed ({0}).' -f $whereRan
} elseif ($absDevs.Count -gt 0) {
    $result.interpretation = ('ABSOLUTE POINTER DETECTED ON {0}.' -f
        (($absDevs | ForEach-Object { $_.hardware_id }) -join ', ')) + $caveat
} elseif ($visibility -eq 'full') {
    if ($result.devices_probed -eq 0) {
        $result.interpretation = ('NO POINTING DEVICE DETECTED ({0} HID interface(s) enumerated, ' +
            'none a Pointer or Mouse collection).') -f
            $result.hid_interface_count
    } else {
        $result.interpretation = 'NO ABSOLUTE POINTER DETECTED.'
    }
} else {
    $result.status = 'incomplete'
    $result.interpretation = ('INCONCLUSIVE - no absolute pointer seen, but visibility was ' +
        'incomplete ({0} read, {1} failed, {2} interface(s) unreadable; {3}).') -f
        $result.devices_probed, $result.devices_failed, $unreadable.Count, $whereRan
}

if ($result.status -eq 'incomplete') {
    if ($result.in_session_0) {
        $result.interpretation += ' Ran in session 0; re-run in the interactive user session before concluding.'
    }
    # -Json emits only the nine wanted fields, so suppressed warnings have to
    # travel in the interpretation or they are lost.
    if ($result.warnings.Count -gt 0) {
        $result.interpretation += (' REASONS: ' + ($result.warnings -join ' | '))
    }
} elseif ($result.in_session_0) {
    $result.interpretation += ((' (Session 0 probe as {0}; console session {1}, ' +
        'visibility {2}.)') -f
        $result.running_as, $result.console_session_id, $visibility)
}

# One flat line repeating every count as text, for the readable report. A TSV
# flattener renders the integer 1 as "True" and mangles nested objects; a flat
# string cannot be mangled that way.
$result.counts = ('session={0} console={1} running_as={2} rawinput_total={3} ' +
    'rawinput_mice={4} pnp_interfaces={5} probed={6} failed={7} unreadable={8} ' +
    'absolute_mouse_class={9} visibility={10}') -f
    $result.session_id, $result.console_session_id, $result.running_as,
    $result.raw_device_total, $result.raw_device_count, $result.hid_interface_count,
    $result.devices_probed, $result.devices_failed, $unreadable.Count,
    $absDevs.Count, $visibility

# --- output -----------------------------------------------------------------

if ($Json) {
    $text = [pscustomobject] [ordered]@{
        host                  = $result.host
        hid_interface_count   = $result.hid_interface_count
        device_count          = $result.device_count
        devices_probed        = $result.devices_probed
        devices_failed        = $result.devices_failed
        any_absolute_axis     = $result.any_absolute_axis
        interpretation        = $result.interpretation
        unreadable_interfaces = @($result.unreadable_interfaces | Select-Object path, error)
        devices               = @($result.devices | Select-Object path, hardware_id, vid, pid,
                                    top_level_collection, axis_summary,
                                    has_absolute_axis, error)
    } | ConvertTo-Json -Depth 8
} else {
    $lines = New-Object System.Collections.ArrayList
    [void] $lines.Add(("host {0}   session {1} (console {2}){3}" -f $result.host, $result.session_id,
        $result.console_session_id, $(if ($result.in_session_0) { '   <-- SESSION 0, NON-INTERACTIVE' } else { '' })))
    [void] $lines.Add(("running as {0}   status {1}   probe_had_visibility {2}" -f
        $result.running_as, $result.status, $result.probe_had_visibility))
    [void] $lines.Add(("enumeration: raw input {0} device(s), {1} mouse-class; PnP HID interfaces {2}" -f
        $result.raw_device_total, $result.raw_device_count, $result.hid_interface_count))
    [void] $lines.Add(("probed {0}, failed {1}, unreadable interfaces {2}" -f
        $result.devices_probed, $result.devices_failed, $result.unreadable_interfaces.Count))
    [void] $lines.Add($result.counts)
    [void] $lines.Add('')
    foreach ($d in $result.devices) {
        [void] $lines.Add($d.path)
        [void] $lines.Add(("      {0}" -f $d.top_level_collection))
        if ($d.error) {
            [void] $lines.Add(("      ERROR {0}" -f $d.error))
        } else {
            foreach ($a in ($d.axis_summary -split ' ')) {
                if (-not $a) { continue }
                $flag = ''
                if ($a -match '^(X|Y)=ABSOLUTE') { $flag = '  <-- ABSOLUTE (redirection / emulation signature)' }
                [void] $lines.Add(("      {0}{1}" -f $a, $flag))
            }
        }
        [void] $lines.Add('')
    }
    foreach ($u in $result.unreadable_interfaces) {
        [void] $lines.Add(("UNREADABLE {0}" -f $u.path))
        [void] $lines.Add(("      {0}" -f $u.error))
    }
    if ($result.unreadable_interfaces.Count) { [void] $lines.Add('') }
    foreach ($wr in $result.warnings) { [void] $lines.Add("WARNING: $wr") }
    if ($result.warnings.Count) { [void] $lines.Add('') }
    [void] $lines.Add($result.interpretation)
    $text = ($lines -join [Environment]::NewLine)
}

if ($OutFile) {
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, $text, (New-Object System.Text.UTF8Encoding($false)))
}
Write-Output $text

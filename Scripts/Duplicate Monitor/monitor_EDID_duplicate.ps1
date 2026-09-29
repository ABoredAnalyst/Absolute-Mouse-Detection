<#
.SYNOPSIS
    Flag historic monitor records that share a name and serial but disagree on EDID
    content (PiKVM EDID-clone tell).

.DESCRIPTION
    Reads HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY, groups records on (name, serial), 
    and outputs every record of a group when:
      - it spans 2+ instance keys,
      - its records differ in PnP ID, manufacture date or preferred resolution, and
      - at least one record is 1920x1200 or below (the most a PiKVM can capture).
    Placeholder monitors (no name, MS_* PnP ID, serial "1") are skipped. A byte-exact
    EDID clone shows no difference and is not detected.

    Output is CSV format. A header alone means nothing was flagged.

.PARAMETER All
    Output every monitor record, not only flagged groups.

.EXAMPLE
    .\duplicate_monitor_edid.ps1
    .\duplicate_monitor_edid.ps1 -All
#>
[CmdletBinding()]
param([switch]$All)

Set-StrictMode -Version 2

if (-not ('MonEdid' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class MonEdid {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegOpenKeyEx(IntPtr hKey, string sub, int opt, int sam, out IntPtr res);
    [DllImport("advapi32.dll")]
    static extern int RegCloseKey(IntPtr h);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern int RegQueryInfoKey(IntPtr h, IntPtr cls, IntPtr clsLen, IntPtr res,
        IntPtr subKeys, IntPtr maxSub, IntPtr maxCls, IntPtr vals, IntPtr maxName,
        IntPtr maxData, IntPtr sec, out long lastWrite);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    static extern uint CM_Locate_DevNodeW(out uint devInst, string id, uint flags);

    // KEY_READ | KEY_WOW64_64KEY
    public static string LastWrite(string subKey) {
        IntPtr h;
        if (RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), subKey, 0, 0x20119, out h) != 0) return "";
        try {
            long ft;
            if (RegQueryInfoKey(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) != 0) return "";
            return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        } finally { RegCloseKey(h); }
    }

    // CM_Locate_DevNode only finds devnodes in the live device tree
    public static bool Present(string instanceId) {
        uint di;
        return CM_Locate_DevNodeW(out di, instanceId, 0) == 0;
    }
}
'@
}

$PikvmMaxW = 1920
$PikvmMaxH = 1200

function Get-EdidText([byte[]]$Edid, [byte]$Tag) {
    foreach ($off in 54, 72, 90, 108) {
        if ($Edid[$off] -eq 0 -and $Edid[$off + 1] -eq 0 -and $Edid[$off + 2] -eq 0 -and $Edid[$off + 3] -eq $Tag) {
            $chars = foreach ($b in $Edid[($off + 5)..($off + 17)]) {
                if ($b -eq 0x0A) { break }
                [char]$b
            }
            $text = (-join $chars).Trim()
            if ($text) { return $text }
            return $null
        }
    }
    return $null
}

function Test-PikvmCapable([string]$Res) {
    if ($Res -notmatch '^(\d+)x(\d+)$') { return $false }
    return ([int]$Matches[1] -le $PikvmMaxW -and [int]$Matches[2] -le $PikvmMaxH)
}

function ConvertTo-CsvField([string]$Value) {
    if ($Value -match '[",\r\n]') { return '"' + $Value.Replace('"', '""') + '"' }
    return $Value
}

$hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
$display = $hive.OpenSubKey('SYSTEM\CurrentControlSet\Enum\DISPLAY')

$records = @()
if ($display) {
    foreach ($hw in $display.GetSubKeyNames()) {
        $hwKey = $display.OpenSubKey($hw)
        foreach ($inst in $hwKey.GetSubKeyNames()) {
            $instKey = $hwKey.OpenSubKey($inst)
            $dp = $instKey.OpenSubKey('Device Parameters')
            $edid = if ($dp) { [byte[]]$dp.GetValue('EDID') } else { $null }
            if (-not $edid -or $edid.Length -lt 128) { continue }

            $serialStr = Get-EdidText $edid 0xFF
            $serialNum = [BitConverter]::ToUInt32($edid, 12)
            $serial = if ($serialStr) { $serialStr } elseif ($serialNum -ne 0) { [string]$serialNum } else { $null }

            $res = ''
            if (($edid[54] -bor $edid[55]) -ne 0) {
                $w = $edid[56] + (($edid[58] -band 0xF0) -shl 4)
                $h = $edid[59] + (($edid[61] -band 0xF0) -shl 4)
                $res = "${w}x${h}"
            }
            $size = if ($edid[21] -and $edid[22]) { "$($edid[21])x$($edid[22]) cm" } else { '' }

            $instanceId = "DISPLAY\$hw\$inst"
            $connected = [MonEdid]::Present($instanceId)
            $records += [pscustomobject]@{
                InstanceId = $instanceId
                PnPId      = $hw
                Name       = Get-EdidText $edid 0xFC
                Serial     = $serial
                LastWrite  = [MonEdid]::LastWrite("SYSTEM\CurrentControlSet\Enum\DISPLAY\$hw\$inst")
                Made       = "$(1990 + $edid[17]) wk$($edid[16])"
                Resolution = $res
                Size       = $size
                Status     = if ($connected) { 'Connected' } else { 'Not connected' }
                Container  = [string]$instKey.GetValue('ContainerID')
            }
        }
    }
}

if ($All) {
    $chosen = $records | Sort-Object { "$($_.Name)" }, { "$($_.Serial)" }, LastWrite
} else {
    $chosen = @()
    $eligible = @($records | Where-Object { $_.Serial -and $_.Name -and $_.PnPId -notlike 'MS_*' -and $_.Serial.Trim() -ne '1' })
    foreach ($g in ($eligible | Group-Object { "$($_.Name)|$($_.Serial)" } | Sort-Object Name)) {
        $rows = @($g.Group)
        if (@($rows.InstanceId | Select-Object -Unique).Count -lt 2) { continue }
        if (-not @($rows | Where-Object { Test-PikvmCapable $_.Resolution })) { continue }
        $differs = (@($rows.PnPId | Select-Object -Unique).Count -gt 1) -or
                   (@($rows.Made | Select-Object -Unique).Count -gt 1) -or
                   (@($rows.Resolution | Select-Object -Unique).Count -gt 1)
        if ($differs) { $chosen += @($rows | Sort-Object LastWrite) }
    }
}

$cols = [ordered]@{
    'Display Friendly Name' = 'Name'
    'Serial Number'         = 'Serial'
    'LastWrite'             = 'LastWrite'
    'Made'                  = 'Made'
    'Resolution'            = 'Resolution'
    'Size'                  = 'Size'
    'Connection Status'     = 'Status'
    'ContainerID'           = 'Container'
}
$cols.Keys -join ','
foreach ($r in $chosen) {
    ($cols.Values | ForEach-Object { ConvertTo-CsvField ([string]$r.$_) }) -join ','
}
if (-not $records) { Write-Output '# No monitor EDID records found; an empty result is not a negative.' }

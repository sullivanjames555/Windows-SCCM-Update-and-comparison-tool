#Requires -Version 5.1
<#
.SYNOPSIS
    UpdateHealthKit collector. Gathers Windows Update, ConfigMgr (SCCM) client, .NET and
    event-log data from a PC into a portable bundle. Works with no network at all.

.DESCRIPTION
    Run this ELEVATED on the PC that is not getting updates from Software Center / SCCM.
    It never needs internet. Copy the resulting folder or .zip to an online admin PC and run
    UpdateHealthAnalyzer.exe against it to compare with Microsoft's latest Windows and .NET
    releases and with what your SCCM/WSUS server thinks about the device.

    What is collected:
      - System info, architecture, uptime, disk, pending reboot, time sync, proxy, Secure Boot
      - .NET Framework 4.x release + every .NET (Core/5+) runtime, ASP.NET Core, Desktop runtime, SDK
      - Windows Update: agent version, services, WSUS/WUfB policies, hotfixes, full WUA history,
        optional WUA scan (online against the SUP, or offline with wsusscn2.cab)
      - SCCM client: version, site, MP, SUP source, Software Center updates and apps, update store,
        maintenance windows, cache, CCMEval results, reboot state, parsed CCM logs + known failure
        signatures, raw log copies
      - Event logs: System, Application, Setup, WindowsUpdateClient, BITS, MDM, AppLocker
      - Connectivity tests to the MP and SUP (DNS / TCP / HTTP), skipped quickly when offline

.PARAMETER OutputPath
    Folder to write the bundle to. Default: a new folder next to this script (handy on a USB
    stick), falling back to %TEMP% if that location is read-only.
.PARAMETER Days
    Days of event logs, CCM logs and install history to collect. Default 30.
.PARAMETER ScanCabPath
    Path to wsusscn2.cab (Microsoft's offline scan catalog). Runs a real offline WUA scan for
    missing security updates. Download the cab on an online PC first. Takes 5-20 minutes.
.PARAMETER OnlineScan
    Run a WUA scan against the device's configured update source (normally your SUP).
    Only useful when the device can reach the SUP.
.PARAMETER RunDismCheck
    Run DISM /CheckHealth (read-only, fast) to detect component store corruption.
.PARAMETER IncludeWindowsUpdateLog
    Convert Windows Update ETL traces into WindowsUpdate.log (can take several minutes).
.PARAMETER SkipRawLogs
    Do not copy raw CCM/CBS/DISM log files into the bundle (parsed results are still included).
.PARAMETER SkipConnectivityTests
    Skip DNS/TCP/HTTP tests to the management point and SUP.
.PARAMETER NoZip
    Do not create a .zip of the bundle.

.EXAMPLE
    .\Invoke-UpdateHealthCollector.ps1

.EXAMPLE
    .\Invoke-UpdateHealthCollector.ps1 -Days 60 -ScanCabPath E:\wsusscn2.cab -RunDismCheck

.NOTES
    UpdateHealthKit 1.0.0. Requires Windows PowerShell 5.1. Read-only: it changes nothing on
    the PC except temporarily registering (and then removing) the offline scan service when
    -ScanCabPath is used.
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateRange(1, 365)][int]$Days = 30,
    [string]$ScanCabPath,
    [switch]$OnlineScan,
    [switch]$RunDismCheck,
    [switch]$IncludeWindowsUpdateLog,
    [switch]$SkipRawLogs,
    [switch]$SkipConnectivityTests,
    [switch]$NoZip
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$CollectorVersion      = '1.0.0'
$script:SectionErrors  = New-Object System.Collections.ArrayList
$Now                   = Get-Date
$WindowStart           = $Now.AddDays(-$Days)
$ComputerName          = $env:COMPUTERNAME
$Invariant             = [System.Globalization.CultureInfo]::InvariantCulture
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

#region Helpers ---------------------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message) -ForegroundColor Cyan
}

function Add-SectionError {
    param([string]$Section, $ErrorObject)
    $msg = $ErrorObject
    if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) { $msg = $ErrorObject.Exception.Message }
    elseif ($ErrorObject -is [System.Exception]) { $msg = $ErrorObject.Message }
    [void]$script:SectionErrors.Add([ordered]@{ Section = $Section; Error = [string]$msg })
    Write-Warning ("{0}: {1}" -f $Section, $msg)
}

function ConvertTo-IsoDate {
    param($Value, [switch]$AssumeUtc)
    if ($null -eq $Value) { return $null }
    try {
        $d = $null
        if ($Value -is [datetime]) { $d = $Value }
        elseif ($Value -is [string] -and $Value -match '^\d{14}\.\d{6}[+-]\d{3}$') {
            $d = [System.Management.ManagementDateTimeConverter]::ToDateTime($Value)
        }
        else { $d = [datetime]$Value }
        if ($AssumeUtc -and $d.Kind -ne [DateTimeKind]::Local) {
            $d = [DateTime]::SpecifyKind($d, [DateTimeKind]::Utc)
        }
        if ($d.Kind -eq [DateTimeKind]::Utc) { $d = $d.ToLocalTime() }
        if ($d.Year -lt 1980) { return $null }
        return $d.ToString('yyyy-MM-ddTHH:mm:sszzz', $Invariant)
    }
    catch { return $null }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function Get-RegValues {
    # Returns every value under a key as an ordered hashtable (or $null if the key is missing).
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $result = [ordered]@{}
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in $key.GetValueNames()) {
            $v = $key.GetValue($name)
            if ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }
            elseif ($v -is [string[]]) { $v = ($v -join '; ') }
            $label = $name
            if ($name -eq '') { $label = '(Default)' }
            $result[$label] = $v
        }
    }
    catch { }
    return $result
}

function ConvertFrom-CimToHash {
    # Flattens a CIM instance into an ordered hashtable that serialises cleanly to JSON.
    param($Instance, [string[]]$Include)
    if ($null -eq $Instance) { return $null }
    $h = [ordered]@{}
    foreach ($p in $Instance.CimInstanceProperties) {
        if ($Include -and ($Include -notcontains $p.Name)) { continue }
        $v = $p.Value
        if ($v -is [datetime]) { $v = ConvertTo-IsoDate $v }
        elseif ($v -is [Microsoft.Management.Infrastructure.CimInstance]) { $v = [string]$v }
        elseif ($v -is [System.Array] -and -not ($v -is [byte[]])) {
            $parts = foreach ($x in $v) {
                if ($x -is [Microsoft.Management.Infrastructure.CimInstance]) { [string]$x } else { [string]$x }
            }
            $v = ($parts -join '; ')
        }
        elseif ($v -is [byte[]]) { $v = [BitConverter]::ToString($v) }
        $h[$p.Name] = $v
    }
    return $h
}

function Get-CimSafe {
    param([string]$Namespace = 'root\cimv2', [string]$ClassName, [string]$Filter, [string]$Section)
    try {
        $p = @{ Namespace = $Namespace; ClassName = $ClassName; ErrorAction = 'Stop' }
        if ($Filter) { $p.Filter = $Filter }
        return @(Get-CimInstance @p)
    }
    catch {
        if ($Section) { Add-SectionError $Section ("{0}:{1} - {2}" -f $Namespace, $ClassName, $_.Exception.Message) }
        return @()
    }
}

function Format-HResult {
    param($Value)
    if ($null -eq $Value) { return $null }
    try { return ('0x{0:X8}' -f (([int64]$Value) -band [int64]4294967295)) } catch { return [string]$Value }
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 3000)
    $r = [ordered]@{ Host = $HostName; Port = $Port; DnsOk = $false; Addresses = $null; TcpOk = $false; Error = $null }
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostName)
        $r.DnsOk = $true
        $r.Addresses = (@($addrs | ForEach-Object { $_.IPAddressToString }) -join ', ')
    }
    catch {
        $ex = $_.Exception; if ($ex.InnerException) { $ex = $ex.InnerException }
        $r.Error = 'DNS: ' + $ex.Message
        return $r
    }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $client.EndConnect($iar); $r.TcpOk = $true }
        else { $r.Error = "TCP: no response within $TimeoutMs ms" }
    }
    catch {
        $ex = $_.Exception; if ($ex.InnerException) { $ex = $ex.InnerException }
        $r.Error = 'TCP: ' + $ex.Message
    }
    finally { $client.Close() }
    return $r
}

function Test-HttpUrl {
    param([string]$Url, [int]$TimeoutSec = 8)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Timeout = $TimeoutSec * 1000
        $req.UseDefaultCredentials = $true
        $req.Method = 'GET'
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return "HTTP $code"
    }
    catch {
        $ex = $_.Exception; if ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [System.Net.WebException] -and $ex.Response) { return 'HTTP ' + [int]$ex.Response.StatusCode }
        return 'ERR ' + $ex.Message
    }
}

function Read-SharedText {
    # Reads a file another process (CcmExec, TrustedInstaller) still has open for writing.
    param([string]$Path)
    $fs = $null; $sr = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $sr = New-Object System.IO.StreamReader($fs)
        return $sr.ReadToEnd()
    }
    catch { return $null }
    finally { if ($sr) { $sr.Close() } elseif ($fs) { $fs.Close() } }
}

$CMLogRegex = New-Object System.Text.RegularExpressions.Regex(
    '<!\[LOG\[(?<msg>[\s\S]*?)\]LOG\]!><time="(?<time>\d{1,2}:\d{2}:\d{2})[^"]*" date="(?<date>\d{1,2}-\d{1,2}-\d{4})" component="(?<comp>[^"]*)" context="[^"]*" type="(?<type>\d)"',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Read-CMLog {
    # Parses a CMTrace-format log into a list of entries.
    param([string]$Path)
    $list = New-Object System.Collections.Generic.List[object]
    $text = Read-SharedText $Path
    if (-not $text) { return ,$list }
    foreach ($m in $CMLogRegex.Matches($text)) {
        $dt = [datetime]::MinValue
        $stamp = $m.Groups['date'].Value + ' ' + $m.Groups['time'].Value
        if (-not [datetime]::TryParseExact($stamp, 'M-d-yyyy H:mm:ss', $Invariant,
                [System.Globalization.DateTimeStyles]::None, [ref]$dt)) { continue }
        $list.Add([pscustomobject]@{
                Time      = $dt
                Component = $m.Groups['comp'].Value
                Type      = [int]$m.Groups['type'].Value
                Message   = $m.Groups['msg'].Value.Trim()
            })
    }
    return ,$list
}

function Get-FriendlyNetFramework {
    param([int]$Release)
    if ($Release -ge 533320) { return '4.8.1' }
    if ($Release -ge 528040) { return '4.8' }
    if ($Release -ge 461808) { return '4.7.2' }
    if ($Release -ge 461308) { return '4.7.1' }
    if ($Release -ge 460798) { return '4.7' }
    if ($Release -ge 394802) { return '4.6.2' }
    if ($Release -ge 394254) { return '4.6.1' }
    if ($Release -ge 393295) { return '4.6' }
    if ($Release -ge 379893) { return '4.5.2' }
    if ($Release -ge 378675) { return '4.5.1' }
    if ($Release -ge 378389) { return '4.5' }
    return $null
}

#endregion

#region Output folder ---------------------------------------------------------------------

if (-not $OutputPath) {
    $base = $PSScriptRoot
    if (-not $base) { $base = (Get-Location).Path }
    $OutputPath = Join-Path $base ("UpdateHealth_{0}_{1}" -f $ComputerName, $Now.ToString('yyyyMMdd-HHmmss'))
}
try {
    New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    $probe = Join-Path $OutputPath '.write-test'
    Set-Content -LiteralPath $probe -Value 'x' -ErrorAction Stop
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
}
catch {
    $fallback = Join-Path $env:TEMP (Split-Path $OutputPath -Leaf)
    Write-Warning "Cannot write to $OutputPath ($($_.Exception.Message)). Using $fallback instead."
    $OutputPath = $fallback
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
$LogCopyDir = Join-Path $OutputPath 'Logs'
New-Item -ItemType Directory -Path $LogCopyDir -Force | Out-Null

try { Start-Transcript -Path (Join-Path $OutputPath 'collector-transcript.txt') -Force | Out-Null } catch { }

Write-Host ''
Write-Host "UpdateHealthKit collector $CollectorVersion on $ComputerName" -ForegroundColor Green
Write-Host "Output: $OutputPath"
if (-not $IsAdmin) {
    Write-Warning 'Not running elevated. SCCM, event log and Windows Update data will be incomplete. Re-run as Administrator.'
}
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Warning 'Running in 32-bit PowerShell on a 64-bit OS. Use 64-bit PowerShell for accurate registry and .NET data.'
}

#endregion

#region System ----------------------------------------------------------------------------

Write-Step 'System information'
$System = [ordered]@{ ComputerName = $ComputerName }
try {
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = @(Get-CimSafe -ClassName Win32_BIOS)[0]
    $cpu  = @(Get-CimSafe -ClassName Win32_Processor)[0]
    $cvp  = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    $buildNum = 0; [void][int]::TryParse([string]$cvp.CurrentBuildNumber, [ref]$buildNum)
    if ($buildNum -eq 0) { [void][int]::TryParse([string]$os.BuildNumber, [ref]$buildNum) }
    $ubr = 0; if ($null -ne $cvp.UBR) { $ubr = [int]$cvp.UBR }

    $nativeArch = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' 'PROCESSOR_ARCHITECTURE'
    if (-not $nativeArch) { $nativeArch = $env:PROCESSOR_ARCHITECTURE }
    switch -Regex ([string]$nativeArch) {
        'ARM64' { $updateArch = 'arm64'; break }
        'AMD64' { $updateArch = 'x64'; break }
        'x86'   { $updateArch = 'x86'; break }
        default { $updateArch = [string]$nativeArch }
    }

    $sysDrive = $env:SystemDrive
    $disk = @(Get-CimSafe -ClassName Win32_LogicalDisk -Filter "DeviceID='$sysDrive'")[0]

    $fqdn = $ComputerName
    try {
        $ipg = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if ($ipg.DomainName) { $fqdn = '{0}.{1}' -f $ipg.HostName, $ipg.DomainName }
    }
    catch { }
    if ($cs.PartOfDomain -and $fqdn -notlike '*.*') { $fqdn = "$ComputerName.$($cs.Domain)" }

    $System.Fqdn                  = $fqdn
    $System.Domain                = $cs.Domain
    $System.PartOfDomain          = [bool]$cs.PartOfDomain
    $System.Manufacturer          = $cs.Manufacturer
    $System.Model                 = $cs.Model
    $System.SerialNumber          = $(if ($bios) { $bios.SerialNumber } else { $null })
    $System.BiosVersion           = $(if ($bios) { $bios.SMBIOSBIOSVersion } else { $null })
    $System.OSCaption             = $os.Caption
    $System.EditionID             = $cvp.EditionID
    $System.InstallationType      = $cvp.InstallationType
    $System.DisplayVersion        = $cvp.DisplayVersion
    $System.ReleaseId             = $cvp.ReleaseId
    $System.CurrentBuild          = $buildNum
    $System.UBR                   = $ubr
    $System.FullBuild             = "$buildNum.$ubr"
    $System.OSVersion             = $os.Version
    $System.OSArchitecture        = $os.OSArchitecture
    $System.ProcessorArchitecture = [string]$nativeArch
    $System.UpdateArch            = $updateArch
    $System.CpuName               = $(if ($cpu) { ([string]$cpu.Name).Trim() } else { $null })
    $System.MemoryGB              = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 1)
    $System.InstallDate           = ConvertTo-IsoDate $os.InstallDate
    $System.LastBootTime          = ConvertTo-IsoDate $os.LastBootUpTime
    $System.UptimeDays            = [math]::Round((($Now - $os.LastBootUpTime).TotalDays), 1)
    $System.SystemDrive           = $sysDrive
    $System.SystemDriveFreeGB     = $(if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { $null })
    $System.SystemDriveSizeGB     = $(if ($disk) { [math]::Round($disk.Size / 1GB, 1) } else { $null })
    $System.TimeZone              = [System.TimeZoneInfo]::Local.Id
    $System.Language              = (Get-Culture).Name
}
catch { Add-SectionError 'System' $_ }

# Pending reboot
$Pending = [ordered]@{}
$reasons = New-Object System.Collections.ArrayList
$Pending.CBS = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$Pending.WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
$Pending.PendingFileRename = [bool]$pfro
$activeName  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
$pendingName = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
$Pending.ComputerRename = ($activeName -and $pendingName -and ($activeName -ne $pendingName))
$Pending.CcmClient = $null
$Pending.CcmHardReboot = $null
try {
    $rb = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -MethodName 'DetermineIfRebootPending' -ErrorAction Stop
    $Pending.CcmClient = [bool]$rb.RebootPending
    $Pending.CcmHardReboot = [bool]$rb.IsHardRebootPending
}
catch { }
foreach ($k in @('CBS', 'WindowsUpdate', 'PendingFileRename', 'ComputerRename', 'CcmClient')) {
    if ($Pending[$k] -eq $true) { [void]$reasons.Add($k) }
}
$Pending.Any = ($reasons.Count -gt 0)
$Pending.Reasons = @($reasons)

# Time sync
$TimeSync = [ordered]@{ Source = $null; Raw = $null }
try {
    $w32 = @(& w32tm.exe /query /status 2>&1 | ForEach-Object { [string]$_ })
    $TimeSync.Raw = ($w32 -join "`n")
    $srcLine = $w32 | Where-Object { $_ -match '^\s*Source\s*:' } | Select-Object -First 1
    if ($srcLine) { $TimeSync.Source = ($srcLine -replace '^\s*Source\s*:\s*', '').Trim() }
}
catch { Add-SectionError 'TimeSync' $_ }

# Secure Boot (2026 certificate rollout status is useful when updates fail on boot components)
$SecureBoot = [ordered]@{ Enabled = $null; State = $null; Servicing = $null }
try { $SecureBoot.Enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $SecureBoot.Enabled = $null }
$SecureBoot.State     = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
$SecureBoot.Servicing = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$sbRoot = Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
if ($sbRoot) { $SecureBoot.Root = $sbRoot }

#endregion

#region Network ---------------------------------------------------------------------------

Write-Step 'Network configuration'
$Network = [ordered]@{ Adapters = @(); WinHttpProxy = $null; UserProxy = $null; Connectivity = @() }
try {
    $Network.Adapters = @(Get-CimSafe -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -Section 'Network' | ForEach-Object {
            [ordered]@{
                Description = $_.Description
                IPAddress   = (@($_.IPAddress) -join ', ')
                Gateway     = (@($_.DefaultIPGateway) -join ', ')
                DnsServers  = (@($_.DNSServerSearchOrder) -join ', ')
                DnsDomain   = $_.DNSDomain
                DHCP        = [bool]$_.DHCPEnabled
            }
        })
    $Network.WinHttpProxy = (@(& netsh.exe winhttp show proxy 2>&1 | ForEach-Object { [string]$_ }) -join "`n").Trim()
    $Network.UserProxy = Get-RegValues 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($Network.UserProxy) {
        $keep = [ordered]@{}
        foreach ($n in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')) {
            if ($Network.UserProxy.Contains($n)) { $keep[$n] = $Network.UserProxy[$n] }
        }
        $Network.UserProxy = $keep
    }
}
catch { Add-SectionError 'Network' $_ }

#endregion

#region .NET ------------------------------------------------------------------------------

Write-Step '.NET Framework and .NET runtimes/SDKs'
$DotNet = [ordered]@{ Framework = $null; Installs = @() }
try {
    $ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP'
    $release = Get-RegValue "$ndp\v4\Full" 'Release'
    $fw = [ordered]@{
        Release         = $(if ($null -ne $release) { [int]$release } else { $null })
        Version         = Get-RegValue "$ndp\v4\Full" 'Version'
        FriendlyVersion = $(if ($null -ne $release) { Get-FriendlyNetFramework ([int]$release) } else { $null })
        Net35Installed  = ((Get-RegValue "$ndp\v3.5" 'Install') -eq 1)
        Legacy          = @()
    }
    if (Test-Path -LiteralPath $ndp) {
        $fw.Legacy = @(Get-ChildItem -LiteralPath $ndp -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match '^v[123]' } | ForEach-Object {
                    [ordered]@{ Key = $_.PSChildName; Version = (Get-RegValue $_.PSPath 'Version'); Install = (Get-RegValue $_.PSPath 'Install') }
                })
    }
    $DotNet.Framework = $fw

    $installs = New-Object System.Collections.ArrayList
    $pf64 = $env:ProgramW6432; if (-not $pf64) { $pf64 = $env:ProgramFiles }
    $pf86 = ${env:ProgramFiles(x86)}
    $nativeLabel = $System.UpdateArch
    $roots = New-Object System.Collections.ArrayList
    [void]$roots.Add(@{ Path = (Join-Path $pf64 'dotnet'); Arch = $nativeLabel })
    [void]$roots.Add(@{ Path = (Join-Path $pf64 'dotnet\x64'); Arch = 'x64' })
    if ($pf86) { [void]$roots.Add(@{ Path = (Join-Path $pf86 'dotnet'); Arch = 'x86' }) }
    if ($env:DOTNET_ROOT) { [void]$roots.Add(@{ Path = $env:DOTNET_ROOT; Arch = 'DOTNET_ROOT' }) }
    $kindMap = @{
        'Microsoft.NETCore.App'        = 'Runtime'
        'Microsoft.AspNetCore.App'     = 'AspNetCore'
        'Microsoft.WindowsDesktop.App' = 'WindowsDesktop'
    }
    $seenRoots = @{}
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.Path)) { continue }
        $full = (Resolve-Path -LiteralPath $r.Path).ProviderPath.TrimEnd('\')
        if ($seenRoots.ContainsKey($full)) { continue }
        $seenRoots[$full] = $true
        $shared = Join-Path $full 'shared'
        if (Test-Path -LiteralPath $shared) {
            foreach ($fwDir in Get-ChildItem -LiteralPath $shared -Directory -ErrorAction SilentlyContinue) {
                $kind = $kindMap[$fwDir.Name]; if (-not $kind) { $kind = $fwDir.Name }
                foreach ($vDir in Get-ChildItem -LiteralPath $fwDir.FullName -Directory -ErrorAction SilentlyContinue) {
                    if ($vDir.Name -notmatch '^\d+\.\d+\.\d+') { continue }
                    [void]$installs.Add([ordered]@{ Kind = $kind; Name = $fwDir.Name; Version = $vDir.Name; Architecture = $r.Arch; Path = $vDir.FullName })
                }
            }
        }
        $sdkDir = Join-Path $full 'sdk'
        if (Test-Path -LiteralPath $sdkDir) {
            foreach ($vDir in Get-ChildItem -LiteralPath $sdkDir -Directory -ErrorAction SilentlyContinue) {
                if ($vDir.Name -notmatch '^\d+\.\d+\.\d+') { continue }
                [void]$installs.Add([ordered]@{ Kind = 'SDK'; Name = 'Microsoft.NET.Sdk'; Version = $vDir.Name; Architecture = $r.Arch; Path = $vDir.FullName })
            }
        }
    }
    $DotNet.Installs = @($installs)
}
catch { Add-SectionError 'DotNet' $_ }

#endregion

#region Windows Update --------------------------------------------------------------------

Write-Step 'Windows Update agent, policy and history'
$WU = [ordered]@{}
$ResultCodeMap = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
try {
    $wua = Join-Path $env:windir 'System32\wuaueng.dll'
    if (Test-Path -LiteralPath $wua) { $WU.AgentVersion = (Get-Item -LiteralPath $wua).VersionInfo.ProductVersion }

    $svcNames = @('wuauserv', 'BITS', 'CryptSvc', 'TrustedInstaller', 'UsoSvc', 'DoSvc', 'WaaSMedicSvc', 'msiserver', 'CcmExec', 'Winmgmt', 'AppIDSvc')
    $WU.Services = @(Get-CimSafe -ClassName Win32_Service -Section 'Services' | Where-Object { $svcNames -contains $_.Name } | ForEach-Object {
            [ordered]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode; StartName = $_.StartName }
        })

    $WU.Policy          = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $WU.PolicyAU        = Get-RegValues 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $WU.MdmUpdatePolicy = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $WU.UxSettings      = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $regPol = Join-Path $env:windir 'System32\GroupPolicy\Machine\Registry.pol'
    if (Test-Path -LiteralPath $regPol) {
        $rp = Get-Item -LiteralPath $regPol
        $header = $null
        try {
            $bytes = New-Object byte[] 4
            $fs = [System.IO.File]::Open($regPol, 'Open', 'Read', 'ReadWrite')
            [void]$fs.Read($bytes, 0, 4); $fs.Close()
            $header = [BitConverter]::ToString($bytes)
        }
        catch { }
        # A healthy Registry.pol starts with "PReg" (50-52-65-67). A corrupt file breaks SCCM's WUA policy.
        $WU.RegistryPol = [ordered]@{ SizeBytes = $rp.Length; LastWrite = ConvertTo-IsoDate $rp.LastWriteTime; Header = $header; HeaderOk = ($header -eq '50-52-65-67') }
    }
}
catch { Add-SectionError 'WindowsUpdate.Config' $_ }

try {
    $WU.HotFixes = @(Get-HotFix -ErrorAction Stop | ForEach-Object {
            [ordered]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = (ConvertTo-IsoDate $_.InstalledOn); InstalledBy = $_.InstalledBy }
        })
}
catch { Add-SectionError 'WindowsUpdate.HotFixes' $_ }

$session = $null
try { $session = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop }
catch { Add-SectionError 'WindowsUpdate.COM' $_ }

if ($session) {
    try {
        $sm = New-Object -ComObject 'Microsoft.Update.ServiceManager'
        $WU.RegisteredServices = @(foreach ($s in $sm.Services) {
                [ordered]@{
                    Name = $s.Name; ServiceID = [string]$s.ServiceID; IsDefaultAUService = [bool]$s.IsDefaultAUService
                    IsManaged = [bool]$s.IsManaged; IsRegisteredWithAU = [bool]$s.IsRegisteredWithAU
                }
            })
    }
    catch { Add-SectionError 'WindowsUpdate.Services' $_ }

    try {
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        $WU.HistoryTotal = $total
        $hist = New-Object System.Collections.ArrayList
        $take = [Math]::Min($total, 1000)
        if ($take -gt 0) {
            foreach ($e in $searcher.QueryHistory(0, $take)) {
                $title = [string]$e.Title
                $kb = $null
                if ($title -match 'KB(\d{6,8})') { $kb = 'KB' + $Matches[1] }
                $op = [string]$e.Operation
                if ($op -eq '1') { $op = 'Install' } elseif ($op -eq '2') { $op = 'Uninstall' }
                $res = $ResultCodeMap[[int]$e.ResultCode]
                $updId = $null
                try { $updId = [string]$e.UpdateIdentity.UpdateID } catch { }
                [void]$hist.Add([ordered]@{
                        Date                = ConvertTo-IsoDate $e.Date -AssumeUtc
                        Title               = $title
                        KB                  = $kb
                        Operation           = $op
                        Result              = $res
                        HResult             = Format-HResult $e.HResult
                        ClientApplicationID = [string]$e.ClientApplicationID
                        ServerSelection     = [int]$e.ServerSelection
                        ServiceID           = [string]$e.ServiceID
                        UpdateID            = $updId
                    })
            }
        }
        $WU.History = @($hist)
    }
    catch { Add-SectionError 'WindowsUpdate.History' $_ }
}

# Optional WUA scan (online against the SUP, or offline with wsusscn2.cab)
$Scan = [ordered]@{ Mode = $null; Ran = $false; Error = $null; ResultCode = $null; Started = $null; Finished = $null; Missing = @() }
if ($session -and ($ScanCabPath -or $OnlineScan)) {
    $svcMgr = $null; $offlineSvc = $null
    try {
        $searcher2 = $session.CreateUpdateSearcher()
        if ($ScanCabPath) {
            $Scan.Mode = 'OfflineCab'
            $cab = (Resolve-Path -LiteralPath $ScanCabPath -ErrorAction Stop).ProviderPath
            $Scan.CabFile = $cab
            $Scan.CabDate = ConvertTo-IsoDate (Get-Item -LiteralPath $cab).LastWriteTime
            Write-Step "Offline WUA scan using $cab (this can take 5-20 minutes)"
            $svcMgr = New-Object -ComObject 'Microsoft.Update.ServiceManager'
            $offlineSvc = $svcMgr.AddScanPackageService('UpdateHealthKit Offline Scan', $cab, 1)
            $searcher2.ServerSelection = 3
            $searcher2.ServiceID = [string]$offlineSvc.ServiceID
        }
        else {
            $Scan.Mode = 'Online'
            Write-Step 'Online WUA scan against the configured update source (can take several minutes)'
        }
        $Scan.Started = ConvertTo-IsoDate (Get-Date)
        $result = $searcher2.Search("IsInstalled=0 and Type='Software'")
        $Scan.Finished = ConvertTo-IsoDate (Get-Date)
        $Scan.ResultCode = $ResultCodeMap[[int]$result.ResultCode]
        $missing = New-Object System.Collections.ArrayList
        foreach ($u in $result.Updates) {
            $kbs = @(foreach ($k in $u.KBArticleIDs) { 'KB' + $k }) -join ', '
            $cats = @(foreach ($cat in $u.Categories) { $cat.Name }) -join ', '
            [void]$missing.Add([ordered]@{
                    Title                    = [string]$u.Title
                    KB                       = $kbs
                    Severity                 = [string]$u.MsrcSeverity
                    Categories               = $cats
                    IsDownloaded             = [bool]$u.IsDownloaded
                    LastDeploymentChangeTime = ConvertTo-IsoDate $u.LastDeploymentChangeTime
                    MaxDownloadSizeMB        = [math]::Round(([double]$u.MaxDownloadSize / 1MB), 1)
                })
        }
        $Scan.Missing = @($missing)
        $Scan.Ran = $true
    }
    catch {
        $Scan.Error = $_.Exception.Message
        if ($_.Exception.HResult) { $Scan.ErrorCode = Format-HResult $_.Exception.HResult }
        Add-SectionError 'WindowsUpdate.Scan' $_
    }
    finally {
        if ($offlineSvc -and $svcMgr) { try { $svcMgr.RemoveService([string]$offlineSvc.ServiceID) } catch { } }
    }
}
$WU.Scan = $Scan

try {
    $sd = Join-Path $env:windir 'SoftwareDistribution'
    $sum = (Get-ChildItem -LiteralPath $sd -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    $WU.SoftwareDistributionSizeMB = [math]::Round(([double]$sum / 1MB), 0)
}
catch { }

$WU.Dism = [ordered]@{ Ran = $false; ExitCode = $null; Output = $null }
if ($RunDismCheck) {
    Write-Step 'DISM /CheckHealth'
    try {
        $out = @(& dism.exe /English /Online /Cleanup-Image /CheckHealth 2>&1 | ForEach-Object { [string]$_ })
        $WU.Dism.Ran = $true
        $WU.Dism.ExitCode = $LASTEXITCODE
        $WU.Dism.Output = ($out -join "`n").Trim()
    }
    catch { Add-SectionError 'DISM' $_ }
}

if ($IncludeWindowsUpdateLog) {
    Write-Step 'Converting Windows Update ETL logs (Get-WindowsUpdateLog)'
    try {
        $wuLog = Join-Path $LogCopyDir 'WindowsUpdate.log'
        Get-WindowsUpdateLog -LogPath $wuLog -ErrorAction Stop | Out-Null
        $WU.WindowsUpdateLogPath = 'Logs\WindowsUpdate.log'
    }
    catch { Add-SectionError 'WindowsUpdateLog' $_ }
}

#endregion

#region SCCM client -----------------------------------------------------------------------

Write-Step 'ConfigMgr (SCCM) client'
$Sccm = [ordered]@{ Installed = $false }
$ccmSvc = @(Get-CimSafe -ClassName Win32_Service -Filter "Name='CcmExec'")[0]
if ($ccmSvc) {
    $Sccm.Installed = $true
    $Sccm.ServiceState = $ccmSvc.State
    $Sccm.ServiceStartMode = $ccmSvc.StartMode
    $Sccm.ServicePath = $ccmSvc.PathName
}

if ($Sccm.Installed) {
    # Namespace health
    try {
        $smsClient = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
        $Sccm.NamespaceOk = $true
        $Sccm.ClientVersion = $smsClient.ClientVersion
    }
    catch {
        $Sccm.NamespaceOk = $false
        $Sccm.NamespaceError = $_.Exception.Message
        Add-SectionError 'Sccm.Namespace' $_
    }

    $ccmClient = @(Get-CimSafe -Namespace 'root\ccm' -ClassName 'CCM_Client' -Section 'Sccm.ClientId')[0]
    if ($ccmClient) { $Sccm.ClientId = $ccmClient.ClientId; $Sccm.PreviousClientId = $ccmClient.PreviousClientId }

    $Sccm.SiteCode = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' 'AssignedSiteCode'
    if (-not $Sccm.SiteCode) {
        try { $Sccm.SiteCode = (New-Object -ComObject 'Microsoft.SMS.Client').GetAssignedSite() } catch { }
    }
    $Sccm.ProductVersionRegistry = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' 'ProductVersion'

    $auth = @(Get-CimSafe -Namespace 'root\ccm' -ClassName 'SMS_Authority' -Section 'Sccm.Authority')[0]
    if ($auth) { $Sccm.ManagementPoint = $auth.CurrentManagementPoint; $Sccm.Authority = $auth.Name }
    $Sccm.MPCandidates = @(Get-CimSafe -Namespace 'root\ccm\LocationServices' -ClassName 'SMS_ActiveMPCandidate' | ForEach-Object {
            [ordered]@{ MP = $_.MP; Type = $_.Type; State = $_.State }
        })
    $Sccm.ClientCertificateInfo = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\CCM\Security'
    $Sccm.HttpsState = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\CCM' 'HttpsState'

    # Software update source and client settings
    $src = @(Get-CimSafe -Namespace 'root\ccm\SoftwareUpdates\WUAHandler' -ClassName 'CCM_UpdateSource' -Section 'Sccm.UpdateSource')[0]
    if ($src) { $Sccm.UpdateSource = ConvertFrom-CimToHash $src }
    $sumCfg = @(Get-CimSafe -Namespace 'root\ccm\Policy\Machine\ActualConfig' -ClassName 'CCM_SoftwareUpdatesClientConfig' -Section 'Sccm.SumConfig')[0]
    if ($sumCfg) { $Sccm.SumConfig = ConvertFrom-CimToHash $sumCfg }

    # Cache
    $cacheCfg = @(Get-CimSafe -Namespace 'root\ccm\SoftMgmtAgent' -ClassName 'CacheConfig' -Section 'Sccm.Cache')[0]
    if ($cacheCfg) {
        $items = @(Get-CimSafe -Namespace 'root\ccm\SoftMgmtAgent' -ClassName 'CacheInfoEx')
        $usedKB = ($items | Measure-Object -Property ContentSize -Sum).Sum
        $Sccm.Cache = [ordered]@{
            Location = $cacheCfg.Location
            SizeMB   = $cacheCfg.Size
            UsedMB   = [math]::Round(([double]$usedKB / 1024), 0)
            Items    = $items.Count
        }
    }

    # What the client's own scan says (Installed / Missing for every update it evaluated)
    $Sccm.UpdateStatus = @(Get-CimSafe -Namespace 'root\ccm\SoftwareUpdates\UpdatesStore' -ClassName 'CCM_UpdateStatus' -Section 'Sccm.UpdateStatus' | ForEach-Object {
            ConvertFrom-CimToHash $_ -Include @('Article', 'Bulletin', 'Title', 'Status', 'UniqueId', 'ScanTime', 'ProductID', 'RevisionNumber')
        })

    # Software Center: deployed updates and their state
    $Sccm.SoftwareCenterUpdates = @(Get-CimSafe -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -Section 'Sccm.SoftwareCenterUpdates' | ForEach-Object {
            ConvertFrom-CimToHash $_
        })

    # Software Center: applications (lazy properties need a per-instance Get)
    $apps = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-CimSafe -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_Application' -Section 'Sccm.Applications' | Select-Object -First 300)) {
        $fullApp = $a
        try { $fullApp = Get-CimInstance -InputObject $a -ErrorAction Stop } catch { }
        [void]$apps.Add((ConvertFrom-CimToHash $fullApp -Include @('Name', 'FullName', 'Publisher', 'SoftwareVersion', 'InstallState',
                    'ApplicabilityState', 'EvaluationState', 'ErrorCode', 'LastInstallTime', 'LastEvalTime', 'ResolvedState',
                    'IsMachineTarget', 'Deadline', 'StartTime', 'PercentComplete', 'Id', 'Revision')))
    }
    $Sccm.Applications = @($apps)

    $Sccm.ServiceWindows = @(Get-CimSafe -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ServiceWindow' -Section 'Sccm.ServiceWindows' | ForEach-Object {
            ConvertFrom-CimToHash $_
        })

    # CCMEval
    $evalPath = Join-Path $env:windir 'CCM\CcmEvalReport.xml'
    if (Test-Path -LiteralPath $evalPath) {
        try {
            [xml]$evalXml = Read-SharedText $evalPath
            $summaryNode = $evalXml.SelectSingleNode('//*[local-name()="Summary"]')
            $checks = @(foreach ($n in $evalXml.SelectNodes('//*[local-name()="HealthCheck"]')) {
                    [ordered]@{
                        Description = $n.GetAttribute('Description')
                        Result      = ([string]$n.InnerText).Trim()
                        ResultCode  = $n.GetAttribute('ResultCode')
                        ResultType  = $n.GetAttribute('ResultType')
                    }
                })
            $Sccm.CcmEval = [ordered]@{
                Summary        = $(if ($summaryNode) { ([string]$summaryNode.InnerText).Trim() } else { $null })
                EvaluationTime = $(if ($summaryNode) { $summaryNode.GetAttribute('EvaluationTime') } else { $null })
                FileTime       = ConvertTo-IsoDate (Get-Item -LiteralPath $evalPath).LastWriteTime
                Checks         = $checks
            }
        }
        catch { Add-SectionError 'Sccm.CcmEval' $_ }
    }
    $Sccm.CcmEvalRegistry = Get-RegValues 'HKLM:\SOFTWARE\Microsoft\CCM\CcmEval'

    # Co-management / Intune enrolment
    $co = [ordered]@{ IntuneEnrolled = $false; EnrollmentUPN = $null; CoManagementFlags = (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\CCM' 'CoManagementFlags') }
    foreach ($en in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue)) {
        if ((Get-RegValue $en.PSPath 'ProviderID') -eq 'MS DM Server') {
            $co.IntuneEnrolled = $true
            $co.EnrollmentUPN = Get-RegValue $en.PSPath 'UPN'
        }
    }
    $Sccm.CoManagement = $co
}

# CCM log parsing (runs even if the service is missing, in case logs remain)
$ccmLogDir = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' 'LogDirectory'
if (-not $ccmLogDir) { $ccmLogDir = Join-Path $env:windir 'CCM\Logs' }
$Sccm.LogDirectory = $ccmLogDir

$CcmLogNames = @('WUAHandler', 'ScanAgent', 'UpdatesDeployment', 'UpdatesHandler', 'UpdatesStore', 'CAS',
    'ContentTransferManager', 'DataTransferService', 'LocationServices', 'ClientLocation', 'PolicyAgent',
    'PolicyEvaluator', 'CcmExec', 'CcmMessaging', 'ClientIDManagerStartup', 'CertificateMaintenance',
    'StateMessage', 'ServiceWindowManager', 'RebootCoordinator', 'AppEnforce', 'AppDiscovery', 'AppIntentEval',
    'CIAgent', 'CcmEval', 'CoManagementHandler', 'InventoryAgent', 'execmgr')

$IgnoreCase = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$Signatures = @(
    @{ Id = 'SCAN_OK'; Severity = 'Info'; Title = 'Successful software update scan'; Logs = @('WUAHandler', 'ScanAgent')
        Pattern = 'Successfully completed scan|Scan completed successfully' }
    @{ Id = 'SCAN_FAILED'; Severity = 'High'; Title = 'Software update scan failures'; Logs = @('WUAHandler', 'ScanAgent')
        Pattern = 'Scan failed with error|Scan Failed with Error|OnSearchComplete - Failed to end search job|Failed to (start|complete) scan' }
    @{ Id = 'GPO_CONFLICT'; Severity = 'High'; Title = 'Group Policy is overriding the SCCM Windows Update source'; Logs = @('WUAHandler')
        Pattern = 'Group policy settings were overwritten by a higher authority' }
    @{ Id = 'WUA_SOURCE'; Severity = 'High'; Title = 'Client could not set the WSUS/SUP update source'; Logs = @('WUAHandler')
        Pattern = 'Failed to Add Update Source|Unable to read existing WUA Group Policy object|Failed to set WUA managed server policy|Failed to Add Update Source for WUAgent' }
    @{ Id = 'INSTALL_FAIL'; Severity = 'High'; Title = 'Update installation failures'; Logs = @('UpdatesHandler', 'UpdatesDeployment', 'WUAHandler')
        Pattern = 'Failed to install update|Installation job encountered some failures|failed to install|Job error \(0x[0-9a-f]+\)|Update \(.{0,120}\) failed' }
    @{ Id = 'NO_SERVICE_WINDOW'; Severity = 'Medium'; Title = 'Installs waiting on or blocked by maintenance windows'; Logs = @('UpdatesDeployment', 'ServiceWindowManager', 'UpdatesHandler')
        Pattern = 'No current service window|Not enough time left|service window.{0,40}(not available|insufficient)|Waiting for (a )?service window|No service windows? (is )?available' }
    @{ Id = 'CONTENT'; Severity = 'High'; Title = 'Content download or distribution point lookup problems'; Logs = @('CAS', 'ContentTransferManager', 'DataTransferService', 'LocationServices')
        Pattern = 'Content location request.{0,60}fail|Failed to get DP locations|No DP locations|returned 0 locations|Download failed|Failed to download|CTM job.{0,80}(failed|error)|DTS job.{0,80}(failed|error)' }
    @{ Id = 'MP_COMM'; Severity = 'High'; Title = 'Communication failures with the management point'; Logs = @('CcmMessaging', 'LocationServices', 'ClientLocation', 'PolicyAgent', 'StateMessage')
        Pattern = 'Failed to receive ccm message response|Post to http.{0,200}failed|Failed to send (http )?request|status code (40[0-9]|50[0-9])|MP .{0,40}(unreachable|not available)' }
    @{ Id = 'CERT'; Severity = 'High'; Title = 'Client certificate or PKI problems'; Logs = @('CertificateMaintenance', 'ClientIDManagerStartup', 'CcmMessaging', 'LocationServices')
        Pattern = 'Failed to (find|get|read|create|load|retrieve) .{0,60}certificate|certificate.{0,60}(expired|not valid|invalid|revoked)|0x87d00215|0x800b0109' }
    @{ Id = 'REGISTRATION'; Severity = 'High'; Title = 'Client registration or site assignment problems'; Logs = @('ClientIDManagerStartup', 'ClientLocation', 'LocationServices')
        Pattern = 'RegTask: Failed|Client is not (yet )?registered|registration .{0,30}(failed|rejected|pending)|Failed to get (the )?assigned site|Unable to find a valid site' }
    @{ Id = 'POLICY'; Severity = 'Medium'; Title = 'Machine policy download or evaluation errors'; Logs = @('PolicyAgent', 'PolicyEvaluator')
        Pattern = 'Failed to (download|apply|evaluate|compile) policy|Policy .{0,40}(failed|error)' }
    @{ Id = 'REBOOT'; Severity = 'Medium'; Title = 'Updates waiting on a restart'; Logs = @('UpdatesDeployment', 'RebootCoordinator', 'UpdatesHandler')
        Pattern = 'reboot (is )?pending|pending (a )?reboot|restart is required|Reboot required' }
    @{ Id = 'APPLOCKER'; Severity = 'High'; Title = 'Installer blocked by policy (AppLocker / WDAC / SRP)'; Logs = @('AppEnforce', 'UpdatesHandler', 'execmgr', 'CcmExec')
        Pattern = 'blocked by (group policy|AppLocker|your system administrator)|0x800704ec|0x800711c7' }
    @{ Id = 'WMI'; Severity = 'High'; Title = 'WMI errors reported by the client'; Logs = @('*')
        Pattern = '0x8004100[0-9a-fA-F]|0x80041013|WMI .{0,40}(corrupt|repository)' }
    @{ Id = 'APP_FAIL'; Severity = 'Medium'; Title = 'Software Center application install failures'; Logs = @('AppEnforce', 'AppDiscovery')
        Pattern = 'Unmatched exit code|Enforcement failed|Application .{0,120} failed' }
)
foreach ($s in $Signatures) { $s.Regex = New-Object System.Text.RegularExpressions.Regex($s.Pattern, $IgnoreCase) }

$sigState = @{}
$errorCodeCounts = @{}
$logEntriesOut = New-Object System.Collections.ArrayList
$logsParsed = New-Object System.Collections.ArrayList
$lastScanOk = $null; $lastScanFail = $null; $wsusFromLog = $null
$codeRegex = New-Object System.Text.RegularExpressions.Regex('0x[0-9A-Fa-f]{8}')
$urlRegex = New-Object System.Text.RegularExpressions.Regex('(https?://[^\s\)\]''"]+)')

if (Test-Path -LiteralPath $ccmLogDir) {
    Write-Step "Parsing CCM logs in $ccmLogDir"
    foreach ($name in $CcmLogNames) {
        $files = @(Get-ChildItem -LiteralPath $ccmLogDir -File -ErrorAction SilentlyContinue | Where-Object {
                ($_.Extension -eq '.log' -or $_.Extension -eq '.lo_') -and
                ($_.BaseName -eq $name -or $_.BaseName -like "$name-*") -and
                ($_.LastWriteTime -ge $WindowStart)
            } | Sort-Object LastWriteTime)
        if ($files.Count -eq 0) { continue }
        $sigsForLog = @($Signatures | Where-Object { $_.Logs -contains '*' -or $_.Logs -contains $name })
        $errs = New-Object System.Collections.Generic.List[object]
        $warns = New-Object System.Collections.Generic.List[object]
        $entryCount = 0
        foreach ($f in $files) {
            $entries = Read-CMLog $f.FullName
            foreach ($e in $entries) {
                if ($e.Time -lt $WindowStart) { continue }
                $entryCount++
                foreach ($s in $sigsForLog) {
                    if ($s.Regex.IsMatch($e.Message)) {
                        $st = $sigState[$s.Id]
                        if (-not $st) {
                            $st = [ordered]@{ Id = $s.Id; Severity = $s.Severity; Title = $s.Title; Hits = 0; FirstSeen = $e.Time; LastSeen = $e.Time; LastLog = $name; Sample = $null }
                            $sigState[$s.Id] = $st
                        }
                        $st['Hits'] = [int]$st['Hits'] + 1
                        if ($e.Time -ge $st['LastSeen']) {
                            $st['LastSeen'] = $e.Time
                            $st['LastLog'] = $name
                            $msg = $e.Message; if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) }
                            $st['Sample'] = $msg
                        }
                        if ($e.Time -lt $st['FirstSeen']) { $st['FirstSeen'] = $e.Time }
                        if ($s.Id -eq 'SCAN_OK' -and (-not $lastScanOk -or $e.Time -gt $lastScanOk)) { $lastScanOk = $e.Time }
                        if ($s.Id -eq 'SCAN_FAILED' -and (-not $lastScanFail -or $e.Time -gt $lastScanFail)) { $lastScanFail = $e.Time }
                    }
                }
                if ($name -eq 'WUAHandler' -and $e.Message -match 'Managed server|WSUS Path|update source') {
                    $um = $urlRegex.Match($e.Message)
                    if ($um.Success) { $wsusFromLog = $um.Groups[1].Value.TrimEnd('.', ',') }
                }
                if ($e.Type -ge 2) {
                    foreach ($cm in $codeRegex.Matches($e.Message)) {
                        $code = $cm.Value.ToUpperInvariant().Replace('0X', '0x')
                        if ($code -eq '0x00000000') { continue }
                        if ($errorCodeCounts.ContainsKey($code)) { $errorCodeCounts[$code]++ } else { $errorCodeCounts[$code] = 1 }
                    }
                    $msg = $e.Message; if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) }
                    $obj = [ordered]@{ Log = $name; Time = (ConvertTo-IsoDate $e.Time); Component = $e.Component; Type = $e.Type; Message = $msg }
                    if ($e.Type -eq 3) { $errs.Add($obj) } else { $warns.Add($obj) }
                }
            }
        }
        # Keep the newest 40 errors and 15 warnings per log
        $errSkip = [Math]::Max(0, $errs.Count - 40); $warnSkip = [Math]::Max(0, $warns.Count - 15)
        for ($i = $errSkip; $i -lt $errs.Count; $i++) { [void]$logEntriesOut.Add($errs[$i]) }
        for ($i = $warnSkip; $i -lt $warns.Count; $i++) { [void]$logEntriesOut.Add($warns[$i]) }
        [void]$logsParsed.Add([ordered]@{ Log = $name; Files = $files.Count; Entries = $entryCount; Errors = $errs.Count; Warnings = $warns.Count })
    }
}
else {
    Add-SectionError 'Sccm.Logs' "CCM log folder not found: $ccmLogDir"
}

$Sccm.LogsParsed = @($logsParsed)
$Sccm.LogSignatures = @(foreach ($st in @($sigState.Values)) {
        $st['FirstSeen'] = ConvertTo-IsoDate $st['FirstSeen']
        $st['LastSeen'] = ConvertTo-IsoDate $st['LastSeen']
        $st
    })
$codesOrdered = [ordered]@{}
foreach ($k in ($errorCodeCounts.Keys | Sort-Object { $errorCodeCounts[$_] } -Descending | Select-Object -First 40)) { $codesOrdered[$k] = $errorCodeCounts[$k] }
$Sccm.LogErrorCodes = $codesOrdered
$Sccm.LogEntries = @($logEntriesOut)
$Sccm.LastSuccessfulScan = ConvertTo-IsoDate $lastScanOk
$Sccm.LastScanFailure = ConvertTo-IsoDate $lastScanFail
$Sccm.WsusUrlFromLog = $wsusFromLog

#endregion

#region Event logs ------------------------------------------------------------------------

Write-Step "Event logs (last $Days days)"
$EventQueries = @(
    @{ Tag = 'System';        Max = 600; Filter = @{ LogName = 'System'; Level = 1, 2, 3 } }
    @{ Tag = 'Restarts';      Max = 100; Filter = @{ LogName = 'System'; Id = 41, 1074, 6008 } }
    @{ Tag = 'Application';   Max = 400; Filter = @{ LogName = 'Application'; Level = 1, 2 } }
    @{ Tag = 'MSI';           Max = 300; Filter = @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1022, 1033, 1035, 11707, 11708, 11724 } }
    @{ Tag = 'Setup';         Max = 400; Filter = @{ LogName = 'Setup' } }
    @{ Tag = 'WindowsUpdate'; Max = 1000; Filter = @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational' } }
    @{ Tag = 'BITS';          Max = 300; Filter = @{ LogName = 'Microsoft-Windows-Bits-Client/Operational'; Level = 1, 2, 3 } }
    @{ Tag = 'MDM';           Max = 200; Filter = @{ LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'; Level = 1, 2 } }
    @{ Tag = 'AppLocker';     Max = 300; Filter = @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8003, 8004 } }
    @{ Tag = 'AppLocker';     Max = 300; Filter = @{ LogName = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8006, 8007 } }
    @{ Tag = 'CodeIntegrity'; Max = 100; Filter = @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Level = 1, 2 } }
)
$events = New-Object System.Collections.ArrayList
$eventStatus = New-Object System.Collections.ArrayList
$seen = @{}
foreach ($q in $EventQueries) {
    $flt = $q.Filter.Clone()
    $flt.StartTime = $WindowStart
    $count = 0; $err = $null
    try {
        $found = @(Get-WinEvent -FilterHashtable $flt -MaxEvents $q.Max -ErrorAction Stop)
        foreach ($ev in $found) {
            $key = '{0}|{1}' -f $ev.LogName, $ev.RecordId
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $msg = $null
            try { $msg = $ev.Message } catch { }
            if (-not $msg) { $msg = (@($ev.Properties | ForEach-Object { [string]$_.Value }) -join ' | ') }
            if ($msg -and $msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) }
            [void]$events.Add([ordered]@{
                    Tag      = $q.Tag
                    Log      = $ev.LogName
                    Time     = ConvertTo-IsoDate $ev.TimeCreated
                    Provider = $ev.ProviderName
                    Id       = $ev.Id
                    Level    = [int]$ev.Level
                    LevelName = $ev.LevelDisplayName
                    RecordId = $ev.RecordId
                    Message  = $msg
                })
            $count++
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'No events were found') { $err = $_.Exception.Message }
    }
    [void]$eventStatus.Add([ordered]@{ Tag = $q.Tag; Log = $q.Filter.LogName; Count = $count; Error = $err })
}

#endregion

#region Connectivity ----------------------------------------------------------------------

$Connectivity = New-Object System.Collections.ArrayList
$likelyOffline = $null
if (-not $SkipConnectivityTests) {
    Write-Step 'Connectivity tests (MP / SUP)'
    $targets = New-Object System.Collections.ArrayList
    $wuServer = $null
    if ($WU.Policy -and $WU.Policy.Contains('WUServer')) { $wuServer = [string]$WU.Policy['WUServer'] }
    if ($wuServer) { [void]$targets.Add(@{ Purpose = 'WSUS/SUP (policy WUServer)'; Url = $wuServer; HttpPath = '/ClientWebService/client.asmx' }) }
    if ($Sccm.UpdateSource -and $Sccm.UpdateSource.ContentLocation -and ($Sccm.UpdateSource.ContentLocation -ne $wuServer)) {
        [void]$targets.Add(@{ Purpose = 'SUP (CCM_UpdateSource)'; Url = [string]$Sccm.UpdateSource.ContentLocation; HttpPath = '/ClientWebService/client.asmx' })
    }
    if ($Sccm.ManagementPoint) {
        [void]$targets.Add(@{ Purpose = 'Management point (HTTP)'; Url = ('http://' + $Sccm.ManagementPoint); HttpPath = '/sms_mp/.sms_aut?mplist' })
        [void]$targets.Add(@{ Purpose = 'Management point (HTTPS)'; Url = ('https://' + $Sccm.ManagementPoint); HttpPath = $null })
    }
    [void]$targets.Add(@{ Purpose = 'Microsoft Update (internet, informational)'; Url = 'https://www.catalog.update.microsoft.com'; HttpPath = $null })

    foreach ($t in $targets) {
        try {
            $u = [Uri]$t.Url
            $r = Test-TcpPort -HostName $u.Host -Port $u.Port
            $r.Purpose = $t.Purpose
            $r.Target = $t.Url
            $r.Http = $null
            if ($r.TcpOk -and $t.HttpPath) { $r.Http = Test-HttpUrl ($t.Url.TrimEnd('/') + $t.HttpPath) }
            [void]$Connectivity.Add($r)
        }
        catch { Add-SectionError 'Connectivity' ("{0}: {1}" -f $t.Url, $_.Exception.Message) }
    }
    $likelyOffline = (@($Connectivity | Where-Object { $_.DnsOk }).Count -eq 0)
}
$Network.Connectivity = @($Connectivity)

#endregion

#region Raw log copies --------------------------------------------------------------------

if (-not $SkipRawLogs) {
    Write-Step 'Copying raw logs'
    $budget = 300MB
    $copied = 0
    $copyList = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath $ccmLogDir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $ccmLogDir -File -ErrorAction SilentlyContinue | Where-Object {
                    $bn = $_.BaseName
                    ($_.LastWriteTime -ge $WindowStart) -and (@($CcmLogNames | Where-Object { $bn -eq $_ -or $bn -like "$_-*" }).Count -gt 0)
                })) { [void]$copyList.Add(@{ File = $f; Dest = 'CCM' }) }
    }
    foreach ($p in @((Join-Path $env:windir 'ccmsetup\Logs\ccmsetup.log'), (Join-Path $env:windir 'ccmsetup\Logs\client.msi.log'))) {
        if (Test-Path -LiteralPath $p) { [void]$copyList.Add(@{ File = (Get-Item -LiteralPath $p); Dest = 'ccmsetup' }) }
    }
    foreach ($p in @((Join-Path $env:windir 'Logs\CBS\CBS.log'), (Join-Path $env:windir 'Logs\DISM\dism.log'), (Join-Path $env:windir 'CCM\CcmEvalReport.xml'))) {
        if (Test-Path -LiteralPath $p) { [void]$copyList.Add(@{ File = (Get-Item -LiteralPath $p); Dest = 'Windows' }) }
    }
    foreach ($item in $copyList) {
        $f = $item.File
        if (($copied + $f.Length) -gt $budget) { Write-Warning "Log copy budget reached; skipping $($f.Name)"; continue }
        $destDir = Join-Path $LogCopyDir $item.Dest
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        try {
            $text = Read-SharedText $f.FullName
            if ($null -ne $text) {
                [System.IO.File]::WriteAllText((Join-Path $destDir $f.Name), $text)
                $copied += $f.Length
            }
        }
        catch { Add-SectionError 'RawLogs' ("{0}: {1}" -f $f.Name, $_.Exception.Message) }
    }
}

#endregion

#region Write bundle ----------------------------------------------------------------------

Write-Step 'Writing collection.json'
$Meta = [ordered]@{
    CollectorVersion = $CollectorVersion
    CollectedAtLocal = ConvertTo-IsoDate $Now
    CollectedAtUtc   = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $Invariant)
    ComputerName     = $ComputerName
    RunAsAdmin       = $IsAdmin
    RunAsUser        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    PSVersion        = $PSVersionTable.PSVersion.ToString()
    Is64BitProcess   = [Environment]::Is64BitProcess
    DaysBack         = $Days
    LikelyOffline    = $likelyOffline
    Options          = [ordered]@{
        ScanCabPath = $ScanCabPath; OnlineScan = [bool]$OnlineScan; RunDismCheck = [bool]$RunDismCheck
        IncludeWindowsUpdateLog = [bool]$IncludeWindowsUpdateLog; SkipRawLogs = [bool]$SkipRawLogs
        SkipConnectivityTests = [bool]$SkipConnectivityTests
    }
    SectionErrors    = @($script:SectionErrors)
}

$Bundle = [ordered]@{
    Meta           = $Meta
    System         = $System
    PendingReboot  = $Pending
    TimeSync       = $TimeSync
    SecureBoot     = $SecureBoot
    Network        = $Network
    DotNet         = $DotNet
    WindowsUpdate  = $WU
    Sccm           = $Sccm
    Events         = @($events)
    EventLogStatus = @($eventStatus)
}

$jsonPath = Join-Path $OutputPath 'collection.json'
$json = $Bundle | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))

try { Stop-Transcript | Out-Null } catch { }

$zipPath = $null
if (-not $NoZip) {
    $zipPath = "$OutputPath.zip"
    try {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        Compress-Archive -Path (Join-Path $OutputPath '*') -DestinationPath $zipPath -CompressionLevel Optimal -ErrorAction Stop
    }
    catch { Write-Warning "Could not create zip: $($_.Exception.Message)"; $zipPath = $null }
}

Write-Host ''
Write-Host 'Collection complete.' -ForegroundColor Green
Write-Host ("  Build            : {0} ({1}, {2})" -f $System.FullBuild, $System.DisplayVersion, $System.UpdateArch)
Write-Host ("  SCCM client      : {0}" -f $(if ($Sccm.Installed) { "$($Sccm.ClientVersion) site $($Sccm.SiteCode), MP $($Sccm.ManagementPoint)" } else { 'not installed' }))
Write-Host ("  Last good scan   : {0}" -f $(if ($Sccm.LastSuccessfulScan) { $Sccm.LastSuccessfulScan } else { 'none found in CCM logs' }))
Write-Host ("  Pending reboot   : {0}" -f $(if ($Pending.Any) { ($Pending.Reasons -join ', ') } else { 'no' }))
Write-Host ("  Events collected : {0}" -f $events.Count)
Write-Host ("  Section errors   : {0}" -f $script:SectionErrors.Count)
Write-Host "  Bundle folder    : $OutputPath"
if ($zipPath) { Write-Host "  Bundle zip       : $zipPath" }
Write-Host ''
Write-Host 'Next: copy the zip to an online admin PC and run:' -ForegroundColor Yellow
Write-Host '  UpdateHealthAnalyzer.exe -Input <zip or folder> -SiteServer <SMS Provider server>' -ForegroundColor Yellow

#endregion

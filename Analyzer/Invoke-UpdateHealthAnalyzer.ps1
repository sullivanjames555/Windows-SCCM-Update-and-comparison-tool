#Requires -Version 5.1
<#
.SYNOPSIS
    UpdateHealthKit analyzer (PowerShell edition). Compares collector bundles with Microsoft's
    latest Windows/.NET releases and with your SCCM site (and optionally WSUS), then writes an
    HTML + JSON report explaining what needs updating and why the device isn't updating.

.DESCRIPTION
    Pure Windows PowerShell 5.1: no compiled code, so it runs anywhere signed scripts are allowed.
    Run it on an admin PC with internet access (Microsoft data is cached so later runs can use
    -Offline). SCCM is queried over WMI/DCOM as the current user.

.PARAMETER InputPath
    One or more collector outputs: the .zip, the bundle folder, collection.json, or a folder that
    contains many bundles.
.PARAMETER OutputPath
    Where reports go. Default: .\UpdateHealthReports
.PARAMETER SiteServer
    SMS Provider (usually the primary site server) to compare against.
.PARAMETER SiteCode
    Site code. Auto-detected from the SMS Provider if omitted.
.PARAMETER WsusServer
    Optional WSUS/SUP server to look the device up in (needs the WSUS console / RSAT
    'Windows Server Update Services Tools' on this PC).
.PARAMETER WsusPort
    WSUS port. Default 8530 (8531 for SSL).
.PARAMETER WsusSsl
    Connect to WSUS over SSL.
.PARAMETER Offline
    Don't download; use cached Microsoft data only.
.PARAMETER CacheDir
    Cache folder for Microsoft data. Default: .\cache next to this script.
.PARAMETER CacheHours
    Re-download Microsoft data older than this many hours. Default 12.
.PARAMETER Open
    Open the report when finished.

.EXAMPLE
    .\Invoke-UpdateHealthAnalyzer.ps1 -InputPath E:\UpdateHealth_PC123_20261119-101500.zip -SiteServer CM01 -Open
.EXAMPLE
    .\Invoke-UpdateHealthAnalyzer.ps1 -InputPath \\share\bundles -SiteServer CM01
.EXAMPLE
    .\Invoke-UpdateHealthAnalyzer.ps1 -InputPath .\bundle.zip -Offline

.NOTES
    UpdateHealthKit 1.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string[]]$InputPath,
    [string]$OutputPath,
    [string]$SiteServer,
    [string]$SiteCode,
    [string]$WsusServer,
    [int]$WsusPort = 8530,
    [switch]$WsusSsl,
    [switch]$Offline,
    [string]$CacheDir,
    [ValidateRange(0, 8760)][int]$CacheHours = 12,
    [switch]$Open
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$AnalyzerVersion = '1.1.0'
$Inv = [System.Globalization.CultureInfo]::InvariantCulture
$Win11Url = 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
$Win10Url = 'https://learn.microsoft.com/en-us/windows/release-health/release-information'
$DotNetIndexUrls = @('https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json',
                     'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json')

Add-Type -AssemblyName System.Web.Extensions
Add-Type -AssemblyName System.IO.Compression.FileSystem
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }
try { if ([System.Net.WebRequest]::DefaultWebProxy) { [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials } } catch { }

#region JSON helpers ------------------------------------------------------------------------
# Data is parsed with JavaScriptSerializer (Dictionary[string,object] / object[]), which has no
# 2 MB limit and keeps every value type. Functions return arrays with a leading comma so
# PowerShell doesn't unroll them.

function ConvertFrom-JsonText([string]$Text) {
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    $ser.RecursionLimit = 512
    return ,($ser.DeserializeObject($Text))
}

function jkey($o, [string]$k) {
    if ($null -eq $o -or -not ($o -is [System.Collections.IDictionary])) { return $null }
    $val = $o[$k]
    if ($null -ne $val) { return ,$val }
    foreach ($key in @($o.Keys)) { if ($key -eq $k) { return ,($o[$key]) } }
    return $null
}

function jget($o, [string]$p) {
    if (-not $p) { return ,$o }
    $cur = $o
    foreach ($part in $p.Split('.')) {
        $cur = jkey $cur $part
        if ($null -eq $cur) { return $null }
    }
    return ,$cur
}

function js($o, [string]$p) {
    $v = jget $o $p
    if ($null -eq $v) { return $null }
    if ($v -is [bool]) { if ($v) { return 'True' } else { return 'False' } }
    if ($v -is [datetime]) { return $v.ToLocalTime().ToString('yyyy-MM-dd HH:mm', $Inv) }
    if ($v -is [System.Collections.IDictionary]) { return $null }
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { return $null }
    return [Convert]::ToString($v, $Inv)
}

function jl($o, [string]$p) {
    $v = jget $o $p
    if ($null -eq $v) { return $null }
    if ($v -is [int] -or $v -is [long]) { return [long]$v }
    if ($v -is [decimal] -or $v -is [double]) { return [long][math]::Truncate([double]$v) }
    $s = [Convert]::ToString($v, $Inv)
    $r = [long]0
    if ([long]::TryParse($s, [System.Globalization.NumberStyles]::Integer, $Inv, [ref]$r)) { return $r }
    $d = [double]0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, $Inv, [ref]$d)) { return [long][math]::Truncate($d) }
    return $null
}

function ji($o, [string]$p) {
    $l = jl $o $p
    if ($null -eq $l) { return $null }
    if ($l -gt [int]::MaxValue -or $l -lt [int]::MinValue) { return $null }
    return [int]$l
}

function jd($o, [string]$p) {
    $v = jget $o $p
    if ($null -eq $v) { return $null }
    $d = [double]0
    if ([double]::TryParse([Convert]::ToString($v, $Inv), [System.Globalization.NumberStyles]::Float, $Inv, [ref]$d)) { return $d }
    return $null
}

function jbn($o, [string]$p) {
    $v = jget $o $p
    if ($null -eq $v) { return $null }
    if ($v -is [bool]) { return $v }
    $s = ([Convert]::ToString($v, $Inv)).Trim()
    if ($s -eq '1' -or $s -eq 'true') { return $true }
    if ($s -eq '0' -or $s -eq 'false') { return $false }
    return $null
}

function jb($o, [string]$p) { return ((jbn $o $p) -eq $true) }

function ja($o, [string]$p) {
    $v = jget $o $p
    $list = New-Object System.Collections.Generic.List[object]
    if ($null -eq $v) { return ,$list }
    if ($v -is [string] -or $v -is [System.Collections.IDictionary]) { $list.Add($v); return ,$list }
    if ($v -is [System.Collections.IEnumerable]) { foreach ($x in $v) { if ($null -ne $x) { $list.Add($x) } }; return ,$list }
    $list.Add($v)
    return ,$list
}

function jdict($o, [string]$p) {
    $v = jget $o $p
    if ($v -is [System.Collections.IDictionary]) { return ,$v }
    return $null
}

function ConvertTo-DateValue([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $m = [regex]::Match($s, 'Date\((-?\d+)')
    if ($m.Success) { return ([datetime]'1970-01-01Z').ToUniversalTime().AddMilliseconds([long]$m.Groups[1].Value).ToLocalTime() }
    $dto = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($s, $Inv, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$dto)) { return $dto.LocalDateTime }
    $dt = [datetime]::MinValue
    if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
    return $null
}

function jt($o, [string]$p) {
    $v = jget $o $p
    if ($null -eq $v) { return $null }
    if ($v -is [datetime]) { return $v.ToLocalTime() }
    return (ConvertTo-DateValue ([Convert]::ToString($v, $Inv)))
}

function Fmt($d) { if ($null -eq $d) { return $null }; return ([datetime]$d).ToString('yyyy-MM-dd HH:mm', $Inv) }
function FmtDay($d) { if ($null -eq $d) { return $null }; return ([datetime]$d).ToString('yyyy-MM-dd', $Inv) }

function Short([string]$s, [int]$max) {
    if ($null -eq $s) { return $null }
    $s = ([regex]::Replace($s, '\s+', ' ')).Trim()
    if ($s.Length -le $max) { return $s }
    return $s.Substring(0, $max) + '...'
}

function Plural([int]$n, [string]$word) { if ($n -eq 1) { return "$n $word" } else { return "$n ${word}s" } }

#endregion

#region Versions, severities, error codes ---------------------------------------------------

function ConvertTo-Ver([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $m = [regex]::Match($s, '^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?')
    if (-not $m.Success) { return $null }
    try {
        $c = 0; $d = 0
        if ($m.Groups[3].Success) { $c = [int]$m.Groups[3].Value }
        if ($m.Groups[4].Success) { $d = [int]$m.Groups[4].Value }
        return New-Object System.Version([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, $c, $d)
    }
    catch { return $null }
}

function Test-Preview([string]$s) { return ($null -ne $s -and $s.Contains('-')) }

function Compare-Ver([string]$x, [string]$y) {
    $a = ConvertTo-Ver $x; $b = ConvertTo-Ver $y
    if ($null -eq $a -and $null -eq $b) { return 0 }
    if ($null -eq $a) { return -1 }
    if ($null -eq $b) { return 1 }
    $c = $a.CompareTo($b)
    if ($c -ne 0) { return $c }
    $pa = Test-Preview $x; $pb = Test-Preview $y
    if ($pa -and -not $pb) { return -1 }
    if (-not $pa -and $pb) { return 1 }
    return 0
}

function Get-MaxVer($versions) {
    $best = $null
    foreach ($v in $versions) {
        if ([string]::IsNullOrEmpty($v)) { continue }
        if ($null -eq $best -or (Compare-Ver $v $best) -gt 0) { $best = $v }
    }
    return $best
}

function Get-Channel([string]$v) { $p = ConvertTo-Ver $v; if ($null -eq $p) { return $null }; return "$($p.Major).$($p.Minor)" }

$SevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4; OK = 5 }
function Get-SevRank([string]$s) { if ($s -and $SevRank.ContainsKey($s)) { return $SevRank[$s] }; return 5 }
function Get-SevName([string]$s) {
    foreach ($k in @('Critical', 'High', 'Medium', 'Low', 'Info', 'OK')) { if ($s -eq $k) { return $k } }
    return 'Info'
}

$KnownErrors = @{
    '80240022' = 'WU_E_ALL_UPDATES_FAILED: every update in the operation failed'
    '8024000B' = 'WU_E_CALL_CANCELLED: operation cancelled (often a restart or service stop mid-job)'
    '80240017' = 'WU_E_NOT_APPLICABLE: update not applicable to this device'
    '8024001E' = 'WU_E_SERVICE_STOP: the Windows Update service stopped'
    '8024002E' = 'WU_E_WU_DISABLED: access to an unmanaged server is not allowed (policy)'
    '80240FFF' = 'WU_E_UNEXPECTED: unexpected WUA error'
    '80244007' = 'WU_E_PT_SOAPCLIENT_SOAPFAULT: SOAP fault from WSUS (often needs WSUS cleanup/reindex or client re-sync)'
    '80244010' = 'WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS: too many round trips to WSUS (large metadata / superseded updates)'
    '80244017' = 'WU_E_PT_HTTP_STATUS_DENIED: HTTP 401 from WSUS (authentication)'
    '80244018' = 'WU_E_PT_HTTP_STATUS_FORBIDDEN: HTTP 403 from WSUS (proxy or permissions)'
    '80244019' = 'WU_E_PT_HTTP_STATUS_NOT_FOUND: HTTP 404 from WSUS (wrong URL/port or IIS site down)'
    '8024401C' = 'WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT: WSUS request timed out'
    '8024401F' = 'WU_E_PT_HTTP_STATUS_SERVER_ERROR: HTTP 500 from WSUS'
    '80244021' = 'WU_E_PT_HTTP_STATUS_BAD_GATEWAY: HTTP 502 (proxy/gateway)'
    '80244022' = 'WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL: HTTP 503 - WSUS app pool on the SUP stopped/overloaded'
    '8024402C' = 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED: cannot resolve the WSUS/proxy name (DNS or proxy settings)'
    '8024402F' = 'WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS: external cab processing had errors'
    '80246007' = 'WU_E_DM_NOTDOWNLOADED: update not downloaded'
    '80246008' = 'WU_E_DM_FAILTOCONNECTTOBITS: could not connect to BITS'
    '8024200B' = 'WU_E_UH_INSTALLERFAILURE: the update installer failed'
    '80242016' = 'WU_E_UH_POSTREBOOTUNEXPECTEDSTATE: unexpected state after reboot'
    '8024500C' = 'WU_E_REDIRECTOR_CONNECT_POLICY: connection to Windows Update blocked by policy'
    '80072EE2' = 'ERROR_INTERNET_TIMEOUT: connection timed out (firewall/proxy/server down)'
    '80072EE7' = 'ERROR_INTERNET_NAME_NOT_RESOLVED: server name could not be resolved'
    '80072EFD' = 'ERROR_INTERNET_CANNOT_CONNECT: cannot connect to the server'
    '80072EFE' = 'ERROR_INTERNET_CONNECTION_ABORTED: connection aborted'
    '80072F8F' = 'ERROR_INTERNET_SECURE_FAILURE: TLS/certificate failure (check clock, TLS settings, cert chain)'
    '80070005' = 'E_ACCESSDENIED: access denied'
    '8007000E' = 'E_OUTOFMEMORY: out of memory'
    '80070070' = 'ERROR_DISK_FULL: not enough disk space'
    '80070422' = 'ERROR_SERVICE_DISABLED: a required service is disabled'
    '80070643' = 'ERROR_INSTALL_FAILURE: fatal error during installation'
    '80070652' = 'ERROR_INSTALL_ALREADY_RUNNING: another installation is in progress'
    '800704EC' = 'ERROR_ACCESS_DISABLED_BY_POLICY: program blocked by group policy (AppLocker/SRP)'
    '800711C7' = 'ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION: blocked by Windows Defender Application Control'
    '80073712' = 'ERROR_SXS_COMPONENT_STORE_CORRUPT: component store corrupt (run DISM /RestoreHealth)'
    '800F081F' = 'CBS_E_SOURCE_MISSING: source files not found (DISM needs a /Source)'
    '800F0922' = 'CBS_E_INSTALLERS_FAILED: servicing failed (often EFI/recovery partition space or VPN)'
    '800F0831' = 'CBS_E_STORE_CORRUPTION: a prerequisite package is missing (store corruption)'
    '800B0109' = 'CERT_E_UNTRUSTEDROOT: certificate chain ends in an untrusted root'
    '80004005' = 'E_FAIL: unspecified error (for WUA source errors check Registry.pol corruption)'
    '8004100E' = 'WBEM_E_INVALID_NAMESPACE: WMI namespace missing (CCM namespace broken)'
    '80041010' = 'WBEM_E_INVALID_CLASS: WMI class missing'
    '80041013' = 'WBEM_E_PROVIDER_LOAD_FAILURE: WMI provider failed to load'
    '87D00215' = 'Item not found / client certificate missing (ConfigMgr)'
    '87D00324' = 'The application was not detected after installation completed'
    '87D00607' = 'Content not found (no DP has the content for this boundary)'
    '87D00664' = 'Updates handler job was cancelled'
    '87D00668' = 'Software update still detected as actionable after apply'
    '87D00692' = 'Group policy conflict: a GPO overrides the SCCM WSUS server setting'
    '87D01106' = 'Failed to verify the executable or build its command line (missing file)'
}

function ConvertTo-ErrorCode($v) {
    # Returns the code as 8 upper-case hex digits, or $null.
    if ($null -eq $v) { return $null }
    $s = ([Convert]::ToString($v, $Inv)).Trim()
    if ($s.Length -eq 0) { return $null }
    try {
        if ($s -match '^0x([0-9A-Fa-f]{1,8})$') { return ([Convert]::ToUInt32($Matches[1], 16)).ToString('X8') }
        $l = [long]0
        if ([long]::TryParse($s, [ref]$l)) { return ([uint32]($l -band [long]4294967295)).ToString('X8') }
    }
    catch { }
    return $null
}

function Get-ErrorText($v) {
    $hex = ConvertTo-ErrorCode $v
    if ($null -eq $hex -or $hex -eq '00000000') { return $null }
    if ($KnownErrors.ContainsKey($hex)) { return "0x$hex $($KnownErrors[$hex])" }
    if ($hex.StartsWith('8007')) {
        try { return "0x$hex " + (New-Object System.ComponentModel.Win32Exception([Convert]::ToInt32($hex.Substring(4), 16))).Message } catch { }
    }
    return "0x$hex"
}

function Find-ErrorCodes([string]$text) {
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $text) { return ,$out }
    foreach ($m in [regex]::Matches($text, '0x[0-9A-Fa-f]{8}')) { $out.Add('0x' + $m.Value.Substring(2).ToUpperInvariant()) }
    return ,$out
}

function Get-FixForCodes($codes) {
    $set = @{}
    foreach ($s in $codes) { $h = ConvertTo-ErrorCode $s; if ($h) { $set[$h] = $true } }
    $tips = New-Object System.Collections.Generic.List[string]
    if ($set['80244022'] -or $set['8024401C'] -or $set['8024401F'] -or $set['80244010']) { $tips.Add('SUP/WSUS is overloaded or its IIS app pool is stopping: raise WsusPool private memory limit (0 or 8 GB+) and queue length, run WSUS cleanup/decline superseded updates') }
    if ($set['8024402C'] -or $set['80072EE2'] -or $set['80072EFD'] -or $set['80072EE7']) { $tips.Add("Device can't reach the SUP: check DNS, proxy (netsh winhttp show proxy), firewall to port 8530/8531, VPN split tunnel") }
    if ($set['80072F8F'] -or $set['800B0109']) { $tips.Add('TLS/certificate failure: check the clock, TLS 1.2 settings, and the SUP certificate chain') }
    if ($set['80073712'] -or $set['800F081F'] -or $set['800F0831']) { $tips.Add('Component store corruption: DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow') }
    if ($set['800F0922']) { $tips.Add('Check free space on the EFI/recovery partitions and disconnect VPN during install') }
    if ($set['80070070']) { $tips.Add('Free disk space') }
    if ($set['800704EC'] -or $set['800711C7']) { $tips.Add('Installer blocked by AppLocker/WDAC: allow ccmcache, CCM and SoftwareDistribution paths or Microsoft-signed publishers') }
    if ($set['80070643'] -or $set['8024200B']) { $tips.Add("Installer failure: check CBS.log / the update's MSI log; retry after a restart") }
    if ($set['80240022']) { $tips.Add('All updates failed: look at the individual update errors in WUAHandler.log/UpdatesHandler.log') }
    if ($set['80244007']) { $tips.Add('SOAP fault from WSUS: run WSUS cleanup/reindex; on the client reset SoftwareDistribution') }
    if ($tips.Count -eq 0) { $tips.Add('Look up the error in WUAHandler.log/UpdatesHandler.log and CBS.log; a reset of SoftwareDistribution and catroot2 followed by a scan cycle fixes many transient failures') }
    return (($tips -join '. ') + '.')
}

$EvalStates = @('None', 'Available', 'Submitted', 'Detecting', 'PreDownload', 'Downloading', 'WaitInstall', 'Installing',
    'PendingSoftReboot', 'PendingHardReboot', 'WaitReboot', 'Verifying', 'InstallComplete', 'Error',
    'WaitServiceWindow', 'WaitUserLogon', 'WaitUserLogoff', 'WaitJobUserLogon', 'WaitUserReconnect',
    'PendingUserLogoff', 'PendingUpdate', 'WaitingRetry', 'WaitPresModeOff', 'WaitForOrchestration')
function Get-EvalStateName($s) {
    if ($null -eq $s) { return $null }
    $i = [int]$s
    if ($i -ge 0 -and $i -lt $EvalStates.Count) { return $EvalStates[$i] }
    return [string]$i
}

function Get-WindowTypeName([string]$id) {
    switch ($id) {
        '1' { return 'All deployments' }
        '2' { return 'Programs' }
        '3' { return 'Reboot required' }
        '4' { return 'Software updates' }
        '5' { return 'Task sequences' }
        '6' { return 'Non-working hours' }
        default { return $id }
    }
}

$SignatureFixes = @{
    SCAN_FAILED       = 'Decode the error code in WUAHandler.log/ScanAgent.log. 0x80244022/0x8024401C = SUP WSUS app pool problems; 0x8024402C/0x80072EE2 = name resolution, proxy or firewall to the SUP (8530/8531).'
    GPO_CONFLICT      = "Find the GPO that sets 'Specify intranet Microsoft update service location' (gpresult /h) and remove it from SCCM-managed devices, or make it match the SUP. Then gpupdate /force and run the Software Updates Scan Cycle."
    WUA_SOURCE        = 'Usually a corrupt Registry.pol or broken WUA: rename C:\Windows\System32\GroupPolicy\Machine\Registry.pol, gpupdate /force, reset SoftwareDistribution/catroot2, restart CcmExec, trigger a scan.'
    INSTALL_FAIL      = 'Check the error code in UpdatesHandler.log/WUAHandler.log and CBS.log. Common fixes: free disk space, DISM /RestoreHealth, restart and retry, check AppLocker blocks.'
    NO_SERVICE_WINDOW = "Check maintenance windows on the device's collections (see SCCM server view). Make sure an 'All deployments' or 'Software updates' window exists and is long enough, or allow installs outside maintenance windows."
    CONTENT           = "Confirm the device's boundary group has a DP holding the update deployment package; check CAS.log, LocationServices.log and DataTransferService.log for the content ID."
    MP_COMM           = 'Check MP health (mpcontrol.log on the MP), client certificate/PKI, proxy and firewall from the client to the MP; test http(s)://<MP>/sms_mp/.sms_aut?mplist.'
    CERT              = 'Check the client certificate in the LocalMachine\SMS store (self-signed) or the PKI client auth cert; verify the clock and CRL access. Re-key: stop CcmExec, delete the SMS certificates, start CcmExec.'
    REGISTRATION      = "The client isn't registered/approved: approve it in the console, verify boundary/site assignment, review ClientIDManagerStartup.log; reinstall if the identity is corrupt."
    POLICY            = 'Trigger Machine Policy Retrieval & Evaluation; if it keeps failing, reset policy (SMS_Client ResetPolicy) and check PolicyAgent.log.'
    REBOOT            = 'Restart the device so pending updates can finish.'
    APPLOCKER         = 'Installers are blocked by AppLocker/WDAC (0x800704EC/0x800711C7). Add allow rules for C:\Windows\ccmcache\*, C:\Windows\CCM\* and C:\Windows\SoftwareDistribution\Download\* or Microsoft publisher rules for MSI/EXE/script.'
    WMI               = 'Check WMI: winmgmt /verifyrepository (salvage if inconsistent), then repair the client (ccmsetup /forceinstall or ccmrepair.exe).'
    APP_FAIL          = 'Review AppEnforce.log for the exit code and the detection method of the failing application.'
}

#endregion

#region Microsoft data (cached downloads) ---------------------------------------------------

if (-not $CacheDir) { $CacheDir = Join-Path $PSScriptRoot 'cache' }
try { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null } catch { }
$script:CacheNotes = New-Object System.Collections.Generic.List[string]
$script:CacheSources = @{}

function Get-WebText([string]$Url) {
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.UserAgent = "UpdateHealthKit/$AnalyzerVersion"
    $req.Timeout = 30000
    $req.ReadWriteTimeout = 60000
    $req.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
    $req.UseDefaultCredentials = $true
    if ($req.Proxy) { $req.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials }
    $resp = $req.GetResponse()
    try {
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        return $sr.ReadToEnd()
    }
    finally { $resp.Close() }
}

function Get-CachedText([string]$Name, [string[]]$Urls) {
    $file = Join-Path $CacheDir $Name
    if (-not $Offline) {
        if ((Test-Path -LiteralPath $file) -and ((Get-Date) - (Get-Item -LiteralPath $file).LastWriteTime).TotalHours -lt $CacheHours) {
            $script:CacheSources[$Name] = 'cache (downloaded ' + (Get-Item -LiteralPath $file).LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ')'
            return [System.IO.File]::ReadAllText($file)
        }
        foreach ($u in $Urls) {
            if (-not $u) { continue }
            try {
                $text = Get-WebText $u
                try { [System.IO.File]::WriteAllText($file, $text, (New-Object System.Text.UTF8Encoding($false))) } catch { }
                $script:CacheSources[$Name] = 'live download ' + (Get-Date).ToString('yyyy-MM-dd HH:mm') + " from $u"
                return $text
            }
            catch {
                $ex = $_.Exception; if ($ex.InnerException) { $ex = $ex.InnerException }
                $script:CacheNotes.Add("Download failed for ${u}: $($ex.Message)")
            }
        }
    }
    if (Test-Path -LiteralPath $file) {
        $stamp = (Get-Item -LiteralPath $file).LastWriteTime.ToString('yyyy-MM-dd HH:mm')
        $script:CacheSources[$Name] = "cached copy from $stamp (live download not used)"
        $script:CacheNotes.Add("Using cached copy of $Name from $stamp")
        return [System.IO.File]::ReadAllText($file)
    }
    $script:CacheSources[$Name] = 'unavailable'
    return $null
}

function Get-SourceText([string]$Name) { if ($script:CacheSources.ContainsKey($Name)) { return $script:CacheSources[$Name] }; return 'not loaded' }

function ConvertFrom-HtmlCell([string]$html) {
    $s = [regex]::Replace([string]$html, '<[^>]+>', ' ')
    $s = [System.Net.WebUtility]::HtmlDecode($s)
    return ([regex]::Replace($s, '\s+', ' ')).Trim()
}

function Find-HeaderIndex($header, [string]$name) {
    for ($i = 0; $i -lt $header.Count; $i++) { if ($header[$i] -eq $name) { return $i } }
    for ($i = 0; $i -lt $header.Count; $i++) { if ($header[$i].IndexOf($name, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $i } }
    return -1
}

function Get-Cell($row, [int]$i) { if ($i -ge 0 -and $i -lt $row.Count) { return $row[$i] }; return $null }

$script:WinVersions = New-Object System.Collections.Generic.List[object]
$script:WinReleases = @{}

function ConvertTo-UpdateType([string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw)) { return 'Unknown' }
    $s = $raw.Trim()
    if ($s -match 'OOB') { return 'OOB' }
    if ($s -match '(^|\s)B$') { return 'B' }
    if ($s -match '(^|\s)[CD]$') { return 'Preview' }
    return 'Unknown'
}

function Read-WindowsReleaseHtml([string]$Html) {
    if (-not $Html) { return }
    $opt = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $headings = @(foreach ($m in [regex]::Matches($Html, '<h2[^>]*>([\s\S]*?)</h2>', $opt)) { [pscustomobject]@{ Index = $m.Index; Text = (ConvertFrom-HtmlCell $m.Groups[1].Value) } })
    $marks = @(foreach ($m in [regex]::Matches($Html, 'Version\s+([0-9]{2}H[0-9]|[0-9]{4}|LTSC\s?\d{4})\s*\(OS build (\d{5})\)', $opt)) { [pscustomobject]@{ Index = $m.Index; Name = $m.Groups[1].Value } })

    foreach ($t in [regex]::Matches($Html, '<table[\s\S]*?</table>', $opt)) {
        $section = ''
        foreach ($h in $headings) { if ($h.Index -lt $t.Index) { $section = $h.Text } else { break } }
        $versionName = $null
        foreach ($mk in $marks) { if ($mk.Index -lt $t.Index) { $versionName = $mk.Name } else { break } }

        $header = $null
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($tr in [regex]::Matches($t.Value, '<tr[\s\S]*?</tr>', $opt)) {
            $cells = New-Object System.Collections.Generic.List[string]
            $isHeader = $false
            foreach ($cm in [regex]::Matches($tr.Value, '<t([hd])[^>]*>([\s\S]*?)</t[hd]>', $opt)) {
                if ($cm.Groups[1].Value -eq 'h') { $isHeader = $true }
                $cells.Add((ConvertFrom-HtmlCell $cm.Groups[2].Value))
            }
            if ($cells.Count -eq 0) { continue }
            if ($null -eq $header -and $isHeader) { $header = $cells; continue }
            $rows.Add($cells)
        }
        if ($null -eq $header) { continue }
        $hotpatch = ($section -match 'hotpatch') -or (@($header | Where-Object { $_ -match 'hotpatch' }).Count -gt 0)

        if ((Find-HeaderIndex $header 'Latest build') -ge 0) {
            # Summary table: version, servicing option, end-of-servicing dates, latest build
            $iVer = Find-HeaderIndex $header 'Version'
            $iSvc = Find-HeaderIndex $header 'Servicing option'
            $iAvail = Find-HeaderIndex $header 'Availability date'
            $iHome = -1; $iEnt = -1; $iExt = -1
            for ($i = 0; $i -lt $header.Count; $i++) {
                $hh = $header[$i]
                if ($iHome -lt 0 -and $hh -match 'Home') { $iHome = $i }
                elseif ($iEnt -lt 0 -and $hh -match 'Enterprise' -and ($hh -match 'End' -or $hh -match 'support')) { $iEnt = $i }
                if ($iExt -lt 0 -and $hh -match 'Extended') { $iExt = $i }
            }
            if ($iExt -ge 0) { $iEnt = $iExt }
            if ($iEnt -lt 0) { for ($i = 0; $i -lt $header.Count; $i++) { if ($i -ne $iHome -and $header[$i] -match 'End of') { $iEnt = $i; break } } }
            $iLatestUpd = Find-HeaderIndex $header 'Latest update'
            $iLatestRev = Find-HeaderIndex $header 'Latest revision date'
            $iLatestBuild = Find-HeaderIndex $header 'Latest build'
            foreach ($row in $rows) {
                $lb = Get-Cell $row $iLatestBuild
                if (-not $lb) { continue }
                $bm = [regex]::Match($lb, '(\d{5})\.(\d+)')
                if (-not $bm.Success) { continue }
                $channel = Get-Cell $row $iSvc
                $script:WinVersions.Add([pscustomobject]@{
                        Version = (Get-Cell $row $iVer); Channel = $channel; Availability = (Get-Cell $row $iAvail)
                        EosHomePro = (Get-Cell $row $iHome); EosEnterprise = (Get-Cell $row $iEnt)
                        LatestUpdate = (Get-Cell $row $iLatestUpd); LatestRevisionDate = (Get-Cell $row $iLatestRev)
                        Major = [int]$bm.Groups[1].Value; LatestUbr = [int]$bm.Groups[2].Value
                        IsLtsc = ([string]$channel -match 'Long|LTSC')
                    })
            }
            continue
        }
        if ($hotpatch) { continue }

        $iBuild = Find-HeaderIndex $header 'Build'
        $iKb = Find-HeaderIndex $header 'KB article'
        if ($iKb -lt 0) { $iKb = Find-HeaderIndex $header 'KB' }
        if ($iBuild -lt 0 -or $iKb -lt 0) { continue }
        $iType = Find-HeaderIndex $header 'Update type'
        $iDate = Find-HeaderIndex $header 'Availability date'
        if ($iDate -lt 0) { $iDate = Find-HeaderIndex $header 'date' }
        foreach ($row in $rows) {
            if ($row.Count -le [math]::Max($iBuild, $iKb)) { continue }
            if (@($row | Where-Object { $_ -match 'hotpatch' }).Count -gt 0) { continue }
            $bm = [regex]::Match($row[$iBuild], '^(\d{5})\.(\d+)')
            if (-not $bm.Success) { continue }
            $km = [regex]::Match($row[$iKb], 'KB\s?(\d{6,8})', $opt)
            if (-not $km.Success) { continue }
            $major = [int]$bm.Groups[1].Value
            $ubrVal = [int]$bm.Groups[2].Value
            if (-not $script:WinReleases.ContainsKey($major)) { $script:WinReleases[$major] = New-Object System.Collections.Generic.List[object] }
            if (@($script:WinReleases[$major] | Where-Object { $_.Ubr -eq $ubrVal }).Count -gt 0) { continue }
            $rawType = Get-Cell $row $iType
            $dateText = Get-Cell $row $iDate
            $dv = $null; $tmp = [datetime]::MinValue
            if ([datetime]::TryParse([string]$dateText, $Inv, [System.Globalization.DateTimeStyles]::None, [ref]$tmp)) { $dv = $tmp }
            $script:WinReleases[$major].Add([pscustomobject]@{
                    Major = $major; Ubr = $ubrVal; Kb = 'KB' + $km.Groups[1].Value; Date = $dateText; DateValue = $dv
                    RawType = $rawType; Type = (ConvertTo-UpdateType $rawType); VersionName = $versionName; BuildText = "$major.$ubrVal"
                })
        }
    }
}

function Find-WinVersion([int]$Major, [bool]$Ltsc) {
    $cands = @($script:WinVersions | Where-Object { $_.Major -eq $Major })
    if ($cands.Count -eq 0) { return $null }
    $pick = @($cands | Where-Object { $_.IsLtsc -eq $Ltsc }) | Select-Object -First 1
    if ($pick) { return $pick }
    return $cands[0]
}

function Get-WinReleases([int]$Major) {
    if (-not $script:WinReleases.ContainsKey($Major)) { return ,(New-Object System.Collections.Generic.List[object]) }
    $l = New-Object System.Collections.Generic.List[object]
    foreach ($x in ($script:WinReleases[$Major] | Sort-Object Ubr -Descending)) { $l.Add($x) }
    return ,$l
}

function Get-NewestWinVersion([bool]$Windows11) {
    return ($script:WinVersions | Where-Object { (($_.Major -ge 22000) -eq $Windows11) -and -not $_.IsLtsc } |
        Sort-Object { [string]$_.Availability } -Descending | Select-Object -First 1)
}

$script:DotNetChannels = @{}

function Read-DotNetIndex {
    $text = Get-CachedText 'dotnet-releases-index.json' $DotNetIndexUrls
    if (-not $text) { return }
    try {
        $root = ConvertFrom-JsonText $text
        foreach ($item in (ja $root 'releases-index')) {
            $ch = js $item 'channel-version'
            if (-not $ch) { continue }
            $script:DotNetChannels[$ch] = [pscustomobject]@{
                Channel = $ch; LatestRelease = (js $item 'latest-release'); LatestRuntime = (js $item 'latest-runtime')
                LatestSdk = (js $item 'latest-sdk'); SupportPhase = (js $item 'support-phase'); EolDate = (js $item 'eol-date')
                ReleaseType = (js $item 'release-type'); ReleasesUrl = [string](jkey $item 'releases.json')
                ReleasesLoaded = $false; Releases = (New-Object System.Collections.Generic.List[object])
            }
        }
    }
    catch { $script:CacheNotes.Add(".NET releases index could not be parsed: $($_.Exception.Message)") }
}

function Test-ChannelEol($ch) {
    if ($ch.SupportPhase -eq 'eol') { return $true }
    $d = [datetime]::MinValue
    return ([datetime]::TryParse([string]$ch.EolDate, $Inv, [System.Globalization.DateTimeStyles]::None, [ref]$d) -and $d.Date -lt (Get-Date).Date)
}

function Get-DotNetChannel([string]$Channel) {
    if (-not $Channel -or -not $script:DotNetChannels.ContainsKey($Channel)) { return $null }
    $ch = $script:DotNetChannels[$Channel]
    if ($ch.ReleasesLoaded) { return $ch }
    $ch.ReleasesLoaded = $true
    if (-not $ch.ReleasesUrl) { return $ch }
    $alt = $ch.ReleasesUrl.Replace('https://builds.dotnet.microsoft.com', 'https://dotnetcli.blob.core.windows.net')
    $text = Get-CachedText "dotnet-$Channel-releases.json" @($ch.ReleasesUrl, $(if ($alt -ne $ch.ReleasesUrl) { $alt } else { $null }))
    if (-not $text) { return $ch }
    try {
        $root = ConvertFrom-JsonText $text
        foreach ($r in (ja $root 'releases')) {
            $sdks = New-Object System.Collections.Generic.List[string]
            foreach ($s in (ja $r 'sdks')) { $v = js $s 'version'; if ($v -and -not $sdks.Contains($v)) { $sdks.Add($v) } }
            $one = js $r 'sdk.version'; if ($one -and -not $sdks.Contains($one)) { $sdks.Add($one) }
            $ch.Releases.Add([pscustomobject]@{
                    Version = (js $r 'release-version'); Date = (js $r 'release-date'); Security = (jb $r 'security')
                    CveCount = (ja $r 'cve-list').Count; Runtime = (js $r 'runtime.version')
                    AspNetCore = (js $r 'aspnetcore-runtime.version'); WindowsDesktop = (js $r 'windowsdesktop.version'); Sdks = $sdks
                })
        }
    }
    catch { $script:CacheNotes.Add(".NET $Channel releases.json could not be parsed: $($_.Exception.Message)") }
    return $ch
}

function Get-ReleaseComponent($rel, [string]$Kind) {
    switch ($Kind) {
        'Runtime' { return $rel.Runtime }
        'AspNetCore' { return $rel.AspNetCore }
        'WindowsDesktop' { return $rel.WindowsDesktop }
        default { return $null }
    }
}

function Get-NewestLts {
    return (Get-MaxVer @($script:DotNetChannels.Values | Where-Object {
                $_.ReleaseType -eq 'lts' -and -not (Test-ChannelEol $_) -and $_.SupportPhase -ne 'preview' -and $_.SupportPhase -ne 'go-live'
            } | ForEach-Object { $_.Channel }))
}

#endregion

#region SCCM SMS Provider (WMI over DCOM) and WSUS -----------------------------------------

$script:Sms = $null   # @{ Server; SiteCode; SiteVersion; Namespace; Error; Connected }

function Invoke-SmsQuery([string]$Wql) {
    $p = @{ ComputerName = $script:Sms.Server; Namespace = $script:Sms.Namespace; Query = $Wql; ErrorAction = 'Stop'
            Authentication = 'PacketPrivacy'; Impersonation = 'Impersonate'; EnableAllPrivileges = $true }
    return ,@(Get-WmiObject @p)
}

function Get-SmsProp($o, [string]$Name) {
    if ($null -eq $o) { return $null }
    try { $v = $o.Properties[$Name].Value; return ,$v } catch { return $null }
}

function Get-SmsStr($o, [string]$Name) { $v = Get-SmsProp $o $Name; if ($null -eq $v) { return $null }; return [Convert]::ToString($v, $Inv) }

function ConvertFrom-WmiDate([string]$s, [bool]$AssumeUtc) {
    if (-not $s -or $s.Length -lt 14) { return $null }
    try {
        if ($s.Contains('***')) {
            $d = [datetime]::ParseExact($s.Substring(0, 14), 'yyyyMMddHHmmss', $Inv)
            if ($d.Year -lt 1980) { return $null }
            if ($AssumeUtc) { return [datetime]::SpecifyKind($d, [DateTimeKind]::Utc).ToLocalTime() }
            return $d
        }
        $r = [System.Management.ManagementDateTimeConverter]::ToDateTime($s)
        if ($r.Year -lt 1980) { return $null }
        return $r
    }
    catch { return $null }
}

function Get-SmsDate($o, [string]$Name, [bool]$AssumeUtc) { return (ConvertFrom-WmiDate (Get-SmsStr $o $Name) $AssumeUtc) }

function Protect-Wql([string]$s) { return ([string]$s).Replace('\', '\\').Replace("'", "\'") }

function Split-Batch($Items, [int]$Size) {
    $all = @($Items)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $all.Count; $i += $Size) { $out.Add(@($all[$i..([math]::Min($i + $Size, $all.Count) - 1)])) }
    return ,$out
}

function Connect-SmsProvider([string]$Server, [string]$Code) {
    $script:Sms = @{ Server = $Server; SiteCode = $Code; SiteVersion = $null; Namespace = $null; Error = $null; Connected = $false }
    try {
        if (-not $Code) {
            $loc = @(Get-WmiObject -ComputerName $Server -Namespace 'root\SMS' -Class 'SMS_ProviderLocation' -Filter 'ProviderForLocalSite = true' -ErrorAction Stop -Authentication PacketPrivacy -Impersonation Impersonate)
            if ($loc.Count -gt 0) { $script:Sms.SiteCode = [string]$loc[0].SiteCode }
            if (-not $script:Sms.SiteCode) { $script:Sms.Error = 'Could not determine the site code from SMS_ProviderLocation. Pass -SiteCode.'; return }
        }
        $script:Sms.Namespace = 'root\SMS\site_' + $script:Sms.SiteCode
        $site = @(Invoke-SmsQuery ("SELECT Version FROM SMS_Site WHERE SiteCode = '" + (Protect-Wql $script:Sms.SiteCode) + "'"))
        if ($site.Count -gt 0) { $script:Sms.SiteVersion = [string]$site[0].Version }
        $script:Sms.Connected = $true
    }
    catch { $script:Sms.Error = $_.Exception.Message }
}

function ConvertTo-ServerUpdate($u, $Deployed) {
    $id = [uint32](Get-SmsProp $u 'CI_ID')
    return [pscustomobject]@{
        CiId = $id; Article = (Get-SmsStr $u 'ArticleID'); Title = (Get-SmsStr $u 'LocalizedDisplayName')
        IsDeployed = ((Get-SmsStr $u 'IsDeployed') -eq 'True'); IsSuperseded = ((Get-SmsStr $u 'IsSuperseded') -eq 'True')
        IsExpired = ((Get-SmsStr $u 'IsExpired') -eq 'True'); DatePosted = (Get-SmsDate $u 'DatePosted' $true)
        DeployedToDevice = $Deployed.ContainsKey($id); LastError = $null; LastCheck = $null
    }
}

function Get-SmsDeviceView([string]$Name, [string]$CuPattern, [string]$LatestKb) {
    $v = @{
        Error = $null; Records = (New-Object System.Collections.Generic.List[object]); ResourceId = 0; SmsGuid = $null; Combined = $null
        Collections = (New-Object System.Collections.Generic.List[object]); Deployments = (New-Object System.Collections.Generic.List[object])
        MaintenanceWindows = (New-Object System.Collections.Generic.List[object]); DeployedCIs = @{}; ComplianceRows = 0; InstalledCount = 0
        LastStatusCheck = $null; Required = (New-Object System.Collections.Generic.List[object]); CuSearchPattern = $CuPattern
        LatestCuInCatalog = $null; LatestMicrosoftKbInCatalog = $null
    }
    $cols = @('ResourceId', 'Name', 'SMSUniqueIdentifier', 'Client', 'ClientVersion', 'Active', 'Obsolete', 'Decommissioned', 'OperatingSystemNameandVersion', 'LastLogonTimestamp', 'CreationDate')
    try {
        $recs = @(Invoke-SmsQuery ("SELECT * FROM SMS_R_System WHERE Name = '" + (Protect-Wql $Name) + "'"))
        foreach ($r in $recs) {
            $build = Get-SmsStr $r 'BuildExt'; if (-not $build) { $build = Get-SmsStr $r 'Build' }
            $v.Records.Add([ordered]@{
                    ResourceId = (Get-SmsStr $r 'ResourceId'); SMSUniqueIdentifier = (Get-SmsStr $r 'SMSUniqueIdentifier'); Client = (Get-SmsStr $r 'Client')
                    ClientVersion = (Get-SmsStr $r 'ClientVersion'); Active = (Get-SmsStr $r 'Active'); Obsolete = (Get-SmsStr $r 'Obsolete')
                    Decommissioned = (Get-SmsStr $r 'Decommissioned'); OS = (Get-SmsStr $r 'OperatingSystemNameandVersion'); Build = $build
                    LastLogon = (Fmt (Get-SmsDate $r 'LastLogonTimestamp' $true)); CreationDate = (Fmt (Get-SmsDate $r 'CreationDate' $true))
                })
        }
        $primary = $recs | Sort-Object @{ Expression = { if ((Get-SmsStr $_ 'Client') -eq '1') { 1 } else { 0 } }; Descending = $true },
                                       @{ Expression = { if ((Get-SmsStr $_ 'Obsolete') -eq '1') { 0 } else { 1 } }; Descending = $true },
                                       @{ Expression = { [long](Get-SmsStr $_ 'ResourceId') }; Descending = $true } | Select-Object -First 1
        if (-not $primary) { return $v }
        $v.ResourceId = [long](Get-SmsStr $primary 'ResourceId')
        $v.SmsGuid = Get-SmsStr $primary 'SMSUniqueIdentifier'
        $rid = $v.ResourceId

        $cdr = @(Invoke-SmsQuery "SELECT * FROM SMS_CombinedDeviceResources WHERE ResourceID = $rid") | Select-Object -First 1
        if ($cdr) {
            $v.Combined = [ordered]@{}
            foreach ($pn in @('ClientActiveStatus', 'ClientVersion', 'IsActive', 'IsObsolete', 'IsBlocked', 'IsApproved', 'IsClient', 'LastActiveTime',
                    'LastPolicyRequest', 'LastDDR', 'LastHardwareScan', 'LastSoftwareScan', 'LastMPServerName', 'LastClientCheckTime', 'ClientCheckPass',
                    'CNIsOnline', 'CNLastOnlineTime', 'CoManaged', 'SiteCode', 'DeviceOS', 'DeviceOSBuild')) {
                $val = Get-SmsStr $cdr $pn
                if ($val -and $val -match '^\d{14}\.') { $val = Fmt (ConvertFrom-WmiDate $val $true) }
                $v.Combined[$pn] = $val
            }
        }

        $colIds = @(Invoke-SmsQuery "SELECT CollectionID FROM SMS_FullCollectionMembership WHERE ResourceID = $rid" |
                ForEach-Object { Get-SmsStr $_ 'CollectionID' } | Where-Object { $_ } | Select-Object -Unique)
        $names = @{}
        foreach ($batch in (Split-Batch $colIds 20)) {
            $filter = (@($batch | ForEach-Object { "CollectionID = '" + (Protect-Wql $_) + "'" }) -join ' OR ')
            foreach ($cRow in (Invoke-SmsQuery "SELECT CollectionID, Name FROM SMS_Collection WHERE $filter")) { $names[(Get-SmsStr $cRow 'CollectionID')] = Get-SmsStr $cRow 'Name' }
        }
        foreach ($id in $colIds) { $n = $names[$id]; if (-not $n) { $n = $id }; $v.Collections.Add([pscustomobject]@{ Id = $id; Name = $n }) }

        foreach ($batch in (Split-Batch $colIds 20)) {
            $filter = (@($batch | ForEach-Object { "TargetCollectionID = '" + (Protect-Wql $_) + "'" }) -join ' OR ')
            foreach ($a in (Invoke-SmsQuery "SELECT * FROM SMS_UpdatesAssignment WHERE $filter")) {
                try { $a.Get() } catch { }
                $count = 0
                foreach ($x in @(Get-SmsProp $a 'AssignedCIs')) { if ($null -ne $x) { $v.DeployedCIs[[uint32]$x] = $true; $count++ } }
                $gmt = ((Get-SmsStr $a 'UseGMTTimes') -eq 'True')
                $deadline = Fmt (Get-SmsDate $a 'EnforcementDeadline' $gmt)
                $col = Get-SmsStr $a 'TargetCollectionID'
                $colText = $col; if ($col -and $names.ContainsKey($col)) { $colText = "$($names[$col]) ($col)" }
                $v.Deployments.Add([ordered]@{
                        Name = (Get-SmsStr $a 'AssignmentName'); Collection = $colText; Purpose = $(if ($deadline) { 'Required' } else { 'Available' })
                        Enabled = (Get-SmsStr $a 'Enabled'); Start = (Fmt (Get-SmsDate $a 'StartTime' $gmt)); Deadline = $deadline; Updates = [string]$count
                        OverrideMaintenanceWindow = (Get-SmsStr $a 'OverrideServiceWindows'); RebootOutsideMaintenanceWindow = (Get-SmsStr $a 'RebootOutsideOfServiceWindows')
                        SuppressReboot = (Get-SmsStr $a 'SuppressReboot')
                    })
            }
        }

        foreach ($batch in (Split-Batch $colIds 20)) {
            $filter = (@($batch | ForEach-Object { "CollectionID = '" + (Protect-Wql $_) + "'" }) -join ' OR ')
            foreach ($cs in (Invoke-SmsQuery "SELECT * FROM SMS_CollectionSettings WHERE $filter")) {
                try { $cs.Get() } catch { }
                $col = Get-SmsStr $cs 'CollectionID'
                foreach ($sw in @(Get-SmsProp $cs 'ServiceWindows')) {
                    if ($null -eq $sw) { continue }
                    $gmt = ((Get-SmsStr $sw 'IsGMT') -eq 'True')
                    $colName = $col; if ($col -and $names.ContainsKey($col)) { $colName = $names[$col] }
                    $v.MaintenanceWindows.Add([ordered]@{
                            Collection = $colName; Name = (Get-SmsStr $sw 'Name'); Type = (Get-WindowTypeName (Get-SmsStr $sw 'ServiceWindowType'))
                            TypeId = (Get-SmsStr $sw 'ServiceWindowType'); Enabled = (Get-SmsStr $sw 'IsEnabled'); Start = (Fmt (Get-SmsDate $sw 'StartTime' $gmt))
                            DurationMin = (Get-SmsStr $sw 'Duration'); Recurrence = (Get-SmsStr $sw 'RecurrenceType'); Description = (Get-SmsStr $sw 'Description')
                        })
                }
            }
        }

        $comp = @(Invoke-SmsQuery "SELECT CI_ID, Status, LastStatusCheckTime, LastErrorCode, LastEnforcementMessageID FROM SMS_UpdateComplianceStatus WHERE MachineID = $rid")
        $v.ComplianceRows = $comp.Count
        $required = @{}
        foreach ($cRow in $comp) {
            $chk = Get-SmsDate $cRow 'LastStatusCheckTime' $true
            if ($chk -and (-not $v.LastStatusCheck -or $chk -gt $v.LastStatusCheck)) { $v.LastStatusCheck = $chk }
            $st = Get-SmsStr $cRow 'Status'
            if ($st -eq '2') { $required[[uint32](Get-SmsProp $cRow 'CI_ID')] = $cRow }
            elseif ($st -eq '3') { $v.InstalledCount++ }
        }
        foreach ($batch in (Split-Batch @($required.Keys) 25)) {
            $filter = (@($batch | ForEach-Object { "CI_ID = $_" }) -join ' OR ')
            foreach ($u in (Invoke-SmsQuery "SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE $filter")) {
                $su = ConvertTo-ServerUpdate $u $v.DeployedCIs
                if ($required.ContainsKey($su.CiId)) {
                    $cr = $required[$su.CiId]
                    $le = ConvertTo-ErrorCode (Get-SmsProp $cr 'LastErrorCode')
                    if ($le -and $le -ne '00000000') { $su.LastError = "0x$le" }
                    $su.LastCheck = Get-SmsDate $cr 'LastStatusCheckTime' $true
                }
                $v.Required.Add($su)
            }
        }

        if ($CuPattern) {
            $v.LatestCuInCatalog = @(Invoke-SmsQuery ("SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE LocalizedDisplayName LIKE '%" + (Protect-Wql $CuPattern) + "%' AND IsExpired = 0") |
                    ForEach-Object { ConvertTo-ServerUpdate $_ $v.DeployedCIs }) | Sort-Object { if ($_.DatePosted) { $_.DatePosted } else { [datetime]::MinValue } } -Descending | Select-Object -First 1
        }
        if ($LatestKb) {
            $digits = $LatestKb.ToUpperInvariant().Replace('KB', '')
            $v.LatestMicrosoftKbInCatalog = @(Invoke-SmsQuery ("SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE ArticleID = '" + (Protect-Wql $digits) + "'") |
                    ForEach-Object { ConvertTo-ServerUpdate $_ $v.DeployedCIs } | Where-Object { -not $CuPattern -or ([string]$_.Title).IndexOf($CuPattern, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
        }
    }
    catch { $v.Error = $_.Exception.Message }
    return $v
}

function Get-WsusDevice([string]$Server, [int]$Port, [bool]$Ssl, [string]$Fqdn, [string]$ShortName) {
    $res = @{ Data = $null; Error = $null }
    $loaded = $false
    try { [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration'); $loaded = ($null -ne ('Microsoft.UpdateServices.Administration.AdminProxy' -as [type])) } catch { }
    if (-not $loaded) {
        $p = Join-Path $env:ProgramFiles 'Update Services\Api\Microsoft.UpdateServices.Administration.dll'
        if (Test-Path -LiteralPath $p) { try { Add-Type -Path $p; $loaded = $true } catch { } }
    }
    if (-not $loaded) { $res.Error = "WSUS administration API not found on this PC. Install RSAT 'Windows Server Update Services Tools' (or run on the SUP) to enable the WSUS check."; return $res }
    try {
        $srv = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($Server, $Ssl, $Port)
        $target = $null
        foreach ($n in @($Fqdn, $ShortName)) {
            if (-not $n) { continue }
            try { $target = $srv.GetComputerTargetByName($n) } catch { $target = $null }
            if ($target) { break }
        }
        $d = [ordered]@{ Server = "${Server}:$Port" + $(if ($Ssl) { ' (SSL)' } else { '' }) }
        if (-not $target) { $d.Found = 'False'; $res.Data = $d; return $res }
        $d.Found = 'True'
        foreach ($prop in @('FullDomainName', 'IPAddress', 'LastReportedStatusTime', 'LastSyncTime', 'LastSyncResult', 'LastReportedInventoryTime', 'ClientVersion', 'OSDescription', 'RequestedTargetGroupName')) {
            $val = $null
            try { $val = $target.$prop } catch { }
            if ($val -is [datetime]) { if ($val.Year -lt 1980) { $val = $null } else { $val = Fmt ([datetime]::SpecifyKind($val, [DateTimeKind]::Utc).ToLocalTime()) } }
            $d[$prop] = $(if ($null -ne $val) { [string]$val } else { $null })
        }
        try {
            $sum = $target.GetUpdateInstallationSummary()
            foreach ($prop in @('InstalledCount', 'InstalledPendingRebootCount', 'NotInstalledCount', 'DownloadedCount', 'FailedCount', 'UnknownCount', 'NotApplicableCount')) { $d[$prop] = [string]$sum.$prop }
        }
        catch { }
        $res.Data = $d
    }
    catch {
        $ex = $_.Exception; if ($ex.InnerException) { $ex = $ex.InnerException }
        $res.Error = "WSUS query failed: $($ex.Message)"
    }
    return $res
}

#endregion

#region Findings engine ---------------------------------------------------------------------

function Add-Finding([string]$Severity, [string]$Area, [string]$Title, [string]$Detail, [string]$Fix) {
    [void]$script:R.Findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Title = $Title; Detail = $Detail; Fix = $Fix })
}

function Add-UpdateRow([string]$Component, [string]$Installed, [string]$Latest, [string]$Status, [string]$Action, [string]$Severity) {
    [void]$script:R.Updates.Add([pscustomobject]@{ Component = $Component; Installed = $Installed; Latest = $Latest; Status = $Status; Action = $Action; Severity = $Severity })
}

function Add-Note([string]$Text) { [void]$script:R.Notes.Add($Text) }

function Invoke-Step([string]$Name, [scriptblock]$Block) {
    try { & $Block }
    catch {
        $pos = ''
        if ($_.InvocationInfo) { $pos = " (line $($_.InvocationInfo.ScriptLineNumber))" }
        Add-Finding 'Info' 'Analyzer' "Analysis step '$Name' failed" ($_.Exception.GetType().Name + ': ' + $_.Exception.Message + $pos) 'Report this with the bundle; other sections are unaffected.'
    }
}

function Test-SameServer([string]$a, [string]$b) {
    try {
        $ua = [Uri]$a.Trim(); $ub = [Uri]$b.Trim()
        return (($ua.Host.Split('.')[0] -eq $ub.Host.Split('.')[0]) -and $ua.Port -eq $ub.Port)
    }
    catch { return ($a -eq $b) }
}

function Test-DefinitionUpdate([string]$Title) {
    if (-not $Title) { return $false }
    return ($Title -match 'Security Intelligence Update|Definition Update|KB2267602')
}

function Invoke-AnalyzeMeta {
    $C = $script:C
    if ((jbn $C 'Meta.RunAsAdmin') -eq $false) {
        Add-Finding 'Medium' 'Collection' 'Collector was not run as administrator' 'SCCM WMI, some event logs and Windows Update data may be missing, so some checks below are incomplete.' 'Re-run Invoke-UpdateHealthCollector.ps1 from an elevated PowerShell.'
    }
    $errs = ja $C 'Meta.SectionErrors'
    if ($errs.Count -gt 0) {
        Add-Finding 'Info' 'Collection' ((Plural $errs.Count 'collector section') + ' reported errors') ((@($errs | Select-Object -First 10 | ForEach-Object { (js $_ 'Section') + ': ' + (Short (js $_ 'Error') 160) }) -join '; ')) 'Usually harmless (component not installed). Repeated WMI errors point to a broken WMI repository.'
    }
    if ($script:R.CollectedAt -and ((Get-Date) - $script:R.CollectedAt).TotalDays -gt 14) {
        Add-Note ("This bundle was collected " + [int]((Get-Date) - $script:R.CollectedAt).TotalDays + " days ago. Ages (last scan, uptime, etc.) are measured from the collection time; 'latest version' comparisons use today's Microsoft data.")
    }
    if ($script:Ctx.LikelyOffline) { Add-Note 'The device could not resolve its MP/SUP or the internet when collected (likely offline), so connectivity results reflect that.' }
}

function Invoke-AnalyzeWindows {
    $C = $script:C; $X = $script:Ctx
    $build = $X.Build; $ubr = $X.Ubr; $disp = $X.Disp; $edition = $X.Edition
    $win11 = $build -ge 22000
    $product = $(if ($win11) { 'Windows 11' } else { 'Windows 10' })
    $ltsc = $edition -match 'Enterprise(S|SN)$'
    $entClass = $edition -match 'Enterprise|Education|ServerRdsh'
    $installedBuild = "$build.$ubr"
    $instType = [string](js $C 'System.InstallationType')

    if ($instType -match 'Server' -or $edition -match '^Server') {
        Add-UpdateRow 'Windows Server cumulative update' $installedBuild 'not compared' 'Not checked' "Windows Server isn't covered by the Microsoft comparison; use the SCCM server view" 'Info'
        Add-Note "This is Windows Server ($edition). The Microsoft client release comparison was skipped; SCCM, log and event checks still apply."
        return
    }
    if ($disp) { $script:R.CuPattern = "Cumulative Update for $product Version $disp for $($X.Arch)-based" }
    if ($build -eq 0) { Add-Finding 'Info' 'Windows' 'OS build not present in the bundle' $null 'Check the collector transcript for System errors.'; return }
    if ($script:WinVersions.Count -eq 0 -and $script:WinReleases.Count -eq 0) {
        Add-UpdateRow "$product cumulative update" $installedBuild 'unknown' 'Not checked' 'Microsoft release data unavailable (offline and no cache).' 'Info'
        Add-Finding 'Info' 'Windows' 'Microsoft Windows release data unavailable' 'Run the analyzer once with internet access to build the cache.' $null
        return
    }

    $ver = Find-WinVersion $build $ltsc
    $rels = Get-WinReleases $build
    $bRels = @($rels | Where-Object { $_.Type -eq 'B' })
    if ($bRels.Count -eq 0) { $bRels = @($rels | Where-Object { $_.Type -ne 'Preview' }) }
    $latestB = $bRels | Select-Object -First 1
    $latestAny = $rels | Select-Object -First 1

    if ($ver) {
        $eos = $(if ($entClass) { $ver.EosEnterprise } else { $ver.EosHomePro })
        if (-not $eos) { $eos = $(if ($ver.EosEnterprise) { $ver.EosEnterprise } else { $ver.EosHomePro }) }
        $ended = $false; $eosText = $eos
        $eosDate = [datetime]::MinValue
        if ($eos -and $eos -match 'End of') { $ended = $true }
        elseif ($eos -and [datetime]::TryParse($eos, $Inv, [System.Globalization.DateTimeStyles]::None, [ref]$eosDate)) {
            if ($eosDate.Date -lt (Get-Date).Date) { $ended = $true }
            elseif (($eosDate - (Get-Date).Date).TotalDays -le 120) {
                Add-Finding 'Medium' 'Windows' ("$product $disp reaches end of servicing on " + $eosDate.ToString('yyyy-MM-dd', $Inv)) "Edition $edition. After this date it receives no security updates." 'Plan the feature update (SCCM servicing plan, feature update deployment, or in-place upgrade task sequence).'
            }
            $eosText = 'supported until ' + $eosDate.ToString('yyyy-MM-dd', $Inv)
        }
        $newest = Get-NewestWinVersion $win11
        $newestText = $(if ($newest) { "$($newest.Version) ($($newest.Major))" } else { '?' })
        if ($ended) {
            Add-Finding 'Critical' 'Windows' "$product $disp is out of servicing for the $edition edition" "Microsoft no longer ships security updates for this version/edition (unless the device is enrolled in Extended Security Updates). Microsoft lists: $eos" "Upgrade to a supported feature update (newest: $newestText). Until then the device will never show as compliant."
            Add-UpdateRow "$product feature version" "$disp ($edition)" $newestText 'Out of servicing' 'Feature update required' 'Critical'
        }
        else {
            $behindFeature = ($newest -and $newest.Major -ne $build -and -not $ltsc)
            $statusText = $(if ($eosText) { $eosText } else { 'Supported' })
            Add-UpdateRow "$product feature version" "$disp ($edition)" $(if ($ltsc) { 'LTSC' } else { $newestText }) $statusText $(if ($behindFeature) { 'Optional: newer feature update available' } else { 'None' }) $(if ($behindFeature) { 'Info' } else { 'OK' })
        }
    }
    else {
        Add-Finding 'Info' 'Windows' "Build $build is not listed on Microsoft's release information pages" 'Insider, Server, or a version newer than the cached data.' 'Run without -Offline to refresh Microsoft data.'
    }

    if (-not $latestB) { Add-UpdateRow "$product cumulative update" $installedBuild 'unknown' 'Not checked' "No release history found for build $build" 'Info'; return }
    $script:R.LatestKb = $latestB.Kb
    $latestText = "$($latestB.BuildText) ($($latestB.Kb), $($latestB.Date))"
    $installedRel = $rels | Where-Object { $_.Ubr -eq $ubr } | Select-Object -First 1
    $installedText = $installedBuild + $(if ($installedRel) { " ($($installedRel.Kb), $($installedRel.Date))" } else { '' })

    if ($ubr -ge $latestB.Ubr) {
        Add-UpdateRow "$product cumulative update" $installedText $latestText 'Current' 'None' 'OK'
    }
    else {
        $behind = @($bRels | Where-Object { $_.Ubr -gt $ubr }).Count
        $ageDays = $(if ($latestB.DateValue) { ((Get-Date).Date - $latestB.DateValue).TotalDays } else { 99 })
        $sev = $(if ($behind -ge 3) { 'Critical' } elseif ($behind -eq 2) { 'High' } elseif ($ageDays -lt 14) { 'Low' } else { 'Medium' })
        $monthsText = Plural $behind 'monthly security update'
        Add-UpdateRow "$product cumulative update" $installedText $latestText "$monthsText behind" "Install $($latestB.Kb)" $sev
        Add-Finding $sev 'Windows' "Windows is $monthsText behind" "Installed build $installedText. Latest security update for $product $disp is $($latestB.Kb) (build $($latestB.BuildText), released $($latestB.Date))." "Deploy $($latestB.Kb) from SCCM. The SCCM server checks and client findings below explain why it hasn't installed."
    }
    if ($latestAny -and $latestAny.Ubr -gt $latestB.Ubr -and $ubr -lt $latestAny.Ubr -and $latestAny.Type -eq 'OOB') {
        Add-Finding 'Medium' 'Windows' "Out-of-band update $($latestAny.Kb) is available" "Build $($latestAny.BuildText) released $($latestAny.Date) (out-of-band fixes are usually for urgent issues)." 'Check the KB article; import/deploy it in SCCM if it applies to you.'
    }
}

function Get-KindLabel([string]$Kind) {
    switch ($Kind) {
        'Runtime' { return '.NET Runtime' }
        'AspNetCore' { return 'ASP.NET Core Runtime' }
        'WindowsDesktop' { return '.NET Desktop Runtime' }
        'SDK' { return '.NET SDK' }
        default { return $Kind }
    }
}

function Get-SdkBand([string]$v) { $p = ConvertTo-Ver $v; if ($null -eq $p) { return $null }; return "$($p.Major).$($p.Minor).$([math]::Floor($p.Build / 100))xx" }

function Invoke-AnalyzeDotNet {
    $C = $script:C; $X = $script:Ctx
    $release = ji $C 'DotNet.Framework.Release'
    $fv = js $C 'DotNet.Framework.FriendlyVersion'
    if ($null -eq $release) {
        Add-Finding 'Medium' '.NET' 'No .NET Framework 4.x detected' 'The NDP\v4\Full registry key is missing (unusual on Windows 10/11).' 'Repair .NET Framework through Windows Features or an in-place repair.'
    }
    elseif ($release -lt 528040) {
        Add-UpdateRow '.NET Framework' "$fv (release $release)" '4.8.1' 'Outdated' 'Deploy .NET Framework 4.8.1 (or 4.8)' 'Medium'
        Add-Finding 'Medium' '.NET' ".NET Framework $fv is older than 4.8" 'Older Framework versions miss current security fixes and some app requirements.' 'Deploy .NET Framework 4.8.1 from SCCM.'
    }
    elseif ($release -lt 533320 -and $X.Build -ge 19044) {
        Add-UpdateRow '.NET Framework' "$fv (release $release)" '4.8.1' 'Supported' 'Optional: 4.8.1 available for this OS' 'Info'
    }
    else {
        Add-UpdateRow '.NET Framework' "$fv (release $release)" '4.8.1' 'Current' 'Monthly Framework security fixes ship in the .NET Framework cumulative update (see missing updates)' 'OK'
    }

    $installs = ja $C 'DotNet.Installs'
    if ($installs.Count -eq 0) { return }
    if ($script:DotNetChannels.Count -eq 0) {
        Add-Finding 'Info' '.NET' '.NET release metadata unavailable' ("Couldn't download or find cached releases-index.json, so " + (Plural $installs.Count 'install') + ' were not compared.') 'Run with internet access once to build the cache.'
        return
    }
    $newestLts = Get-NewestLts
    $ltsText = $(if ($newestLts) { $newestLts } else { 'the current LTS' })
    $seen = @{}
    foreach ($inst in $installs) {
        $kind = js $inst 'Kind'; $version = js $inst 'Version'; $archLabel = js $inst 'Architecture'
        if (-not $kind -or -not $version) { continue }
        if (@('Runtime', 'AspNetCore', 'WindowsDesktop', 'SDK') -notcontains $kind) { continue }
        $key = "$kind|$version|$archLabel"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $label = (Get-KindLabel $kind) + " $version" + $(if ($archLabel) { " ($archLabel)" } else { '' })
        $channel = Get-Channel $version
        if (Test-Preview $version) { Add-UpdateRow $label $version '-' 'Preview build' 'Remove preview builds from production devices' 'Low'; continue }
        $ch = Get-DotNetChannel $channel
        if (-not $ch) { Add-UpdateRow $label $version '?' 'Unknown channel' "Not in Microsoft's release index" 'Info'; continue }

        $installedRelease = $null
        if ($kind -eq 'SDK') {
            $band = Get-SdkBand $version
            $latest = Get-MaxVer @($ch.Releases | ForEach-Object { $_.Sdks } | Where-Object { (Get-SdkBand $_) -eq $band -and -not (Test-Preview $_) })
            if (-not $latest) { $latest = $ch.LatestSdk }
            $withSdk = $ch.Releases | Where-Object { $_.Sdks.Contains($version) } | Select-Object -First 1
            if ($withSdk) { $installedRelease = $withSdk.Version }
        }
        else {
            $latest = Get-MaxVer @($ch.Releases | ForEach-Object { Get-ReleaseComponent $_ $kind } | Where-Object { $_ -and -not (Test-Preview $_) })
            if (-not $latest) { $latest = $ch.LatestRuntime }
        }

        $missedSec = 0; $cves = 0
        foreach ($rel in $ch.Releases) {
            if (-not $rel.Security) { continue }
            if ($kind -eq 'SDK') { $newer = ($installedRelease -and (Compare-Ver $rel.Version $installedRelease) -gt 0) }
            else { $comp = Get-ReleaseComponent $rel $kind; $newer = ($comp -and (Compare-Ver $comp $version) -gt 0) }
            if ($newer) { $missedSec++; $cves += $rel.CveCount }
        }

        $outdated = ($latest -and (Compare-Ver $version $latest) -lt 0)
        $phase = $(if ($ch.SupportPhase) { $ch.SupportPhase } else { '?' })
        $latestShown = $(if ($latest) { $latest } else { '?' })
        if (Test-ChannelEol $ch) {
            $eolText = $(if ($ch.EolDate) { " on $($ch.EolDate)" } else { '' })
            Add-UpdateRow $label $version $latestShown "Out of support (.NET $channel ended$eolText)" "Upgrade apps to .NET $ltsText or remove this runtime" 'High'
            $extra = $(if ($missedSec -gt 0) { " It is also missing $(Plural $missedSec 'security release') ($cves CVEs) from before end of support." } else { '' })
            Add-Finding 'High' '.NET' "$(Get-KindLabel $kind) $version is out of support" ".NET $channel reached end of support$eolText and receives no more security fixes.$extra" "Move the apps that need it to .NET $ltsText, then uninstall it (or deploy the final $channel patch as a stopgap)."
        }
        elseif ($outdated) {
            $sev = $(if ($missedSec -gt 0) { 'High' } else { 'Medium' })
            $status = $(if ($missedSec -gt 0) { "$(Plural $missedSec 'security release') behind ($cves CVEs)" } else { 'Patch available' })
            Add-UpdateRow $label $version $latest $status "Update to $latest" $sev
            $extra = $(if ($missedSec -gt 0) { " Missed $(Plural $missedSec 'security release') covering $cves CVEs." } else { '' })
            Add-Finding $sev '.NET' "$(Get-KindLabel $kind) $version should be updated to $latest" ".NET $channel ($phase, $($ch.ReleaseType)) latest is $latest.$extra" "Deploy the $latest $(Get-KindLabel $kind) (SCCM application or Microsoft Update 'Developer Tools, Runtimes and Redistributables' / .NET product category), then remove the old version if the installer doesn't."
        }
        else {
            Add-UpdateRow $label $version $latestShown "Current ($phase)" 'None' 'OK'
        }
    }
}

function Invoke-AnalyzeWindowsUpdate {
    $C = $script:C; $X = $script:Ctx
    $critical = @('wuauserv', 'CcmExec', 'Winmgmt')
    $important = @('BITS', 'CryptSvc', 'TrustedInstaller', 'msiserver')
    foreach ($s in (ja $C 'WindowsUpdate.Services')) {
        $name = js $s 'Name'; $start = js $s 'StartMode'; $state = js $s 'State'; $display = js $s 'DisplayName'
        if (-not $name) { continue }
        if ($start -eq 'Disabled') {
            $sev = $(if ($critical -contains $name) { 'Critical' } elseif ($important -contains $name) { 'High' } else { 'Medium' })
            $mode = $(if (@('CcmExec', 'Winmgmt', 'CryptSvc') -contains $name) { 'Automatic' } else { 'Manual' })
            Add-Finding $sev 'Services' "$display ($name) is disabled" 'Windows Update / SCCM depend on this service.' "Set-Service $name -StartupType $mode; then find what disabled it (security baseline GPO, hardening script, or third-party tool)."
        }
        elseif ((@('CcmExec', 'Winmgmt', 'CryptSvc') -contains $name) -and $state -ne 'Running') {
            $st = $(if ($state) { $state } else { 'not running' })
            Add-Finding 'High' 'Services' "$display ($name) is $st" 'This service should always be running.' "Start-Service $name; check the System log for Service Control Manager errors (7000/7031/7034)."
        }
    }

    $pol = jdict $C 'WindowsUpdate.Policy'
    $au = jdict $C 'WindowsUpdate.PolicyAU'
    $wuServer = js $pol 'WUServer'
    $useWu = ((ji $au 'UseWUServer') -eq 1)
    $ccmSource = js $C 'Sccm.UpdateSource.ContentLocation'
    if ($X.SccmInstalled) {
        if (-not $wuServer -or -not $useWu) {
            $extra = $(if ($ccmSource) { " CCM_UpdateSource points to $ccmSource." } else { '' })
            Add-Finding 'High' 'Windows Update policy' 'WSUS policy (WUServer / UseWUServer) is not set' ("SCCM writes these as local policy when the client is assigned a software update point. Missing values mean the SUP was never assigned, or a GPO/MDM policy removed them.$extra") "Check boundary groups include a SUP, that WUAHandler.log shows 'Enabling WUA Managed server policy', and that no GPO sets 'Specify intranet Microsoft update service location' to Disabled."
        }
        elseif ($ccmSource -and -not (Test-SameServer $wuServer $ccmSource)) {
            Add-Finding 'High' 'Windows Update policy' 'WSUS server in policy differs from the SCCM software update point' "Policy WUServer = $wuServer, but the SCCM client expects $ccmSource. A domain GPO is overriding SCCM (WUAHandler logs 'Group policy settings were overwritten by a higher authority')." "Remove 'Specify intranet Microsoft update service location' from GPOs that apply to SCCM clients (gpresult /h on the device shows which GPO), then gpupdate /force and run the Software Updates Scan Cycle."
        }
    }
    if ((jbn $C 'WindowsUpdate.RegistryPol.HeaderOk') -eq $false) {
        Add-Finding 'High' 'Windows Update policy' 'Local Group Policy file Registry.pol looks corrupt' "C:\Windows\System32\GroupPolicy\Machine\Registry.pol does not start with the 'PReg' signature. SCCM can't write its WUA policy into a corrupt file (WUAHandler: 'Failed to Add Update Source', 0x80004005)." 'Rename Registry.pol to Registry.pol.old, run gpupdate /force, restart CcmExec, then trigger a Software Updates Scan Cycle.'
    }
    $wufb = New-Object System.Collections.Generic.List[string]
    foreach ($k in @('SetPolicyDrivenUpdateSourceForQualityUpdates', 'SetPolicyDrivenUpdateSourceForFeatureUpdates', 'SetPolicyDrivenUpdateSourceForDriverUpdates', 'SetPolicyDrivenUpdateSourceForOtherUpdates')) {
        if ((ji $pol $k) -eq 0 -and $null -ne (ji $pol $k)) { $wufb.Add($k.Replace('SetPolicyDrivenUpdateSourceFor', '') + ' = Windows Update (cloud)') }
    }
    if ($X.SccmInstalled -and $wufb.Count -gt 0) {
        Add-Finding 'High' 'Windows Update policy' 'Some update types are set to come from Windows Update instead of WSUS/SCCM' (($wufb -join '; ') + ". Those update types won't come from your SUP.") "If SCCM should own updates, set 'Specify source service for specific classes of Windows Updates' to WSUS for each class (or remove the setting), or check the co-management Windows Update policies workload."
    }
    $defer = $false
    if ($pol) { foreach ($k in $pol.Keys) { if ($k -match '^(DeferQualityUpdates|DeferFeatureUpdates|PauseQualityUpdates)') { $defer = $true } } }
    if ($X.SccmInstalled -and $defer -and (ji $pol 'DisableDualScan') -ne 1 -and $wufb.Count -eq 0) {
        Add-Finding 'Medium' 'Windows Update policy' 'Windows Update for Business deferral policies are set alongside WSUS' "Deferral/pause policies with a WSUS server can trigger 'dual scan', where the device scans Microsoft Update instead of your SUP." "Remove WUfB deferral policies for SCCM-managed devices or enable 'Do not allow update deferral policies to cause scans against Windows Update'."
    }
    if ((ji $pol 'TargetReleaseVersion') -eq 1) { Add-Note ("Feature version is pinned by policy: TargetReleaseVersionInfo = " + (js $pol 'TargetReleaseVersionInfo') + " (ProductVersion " + (js $pol 'ProductVersion') + ").") }
    $mdm = jdict $C 'WindowsUpdate.MdmUpdatePolicy'
    if ($mdm -and $mdm.Count -gt 0) {
        $keys = @($mdm.Keys | Where-Object { $_ -notmatch '_(ProviderSet|WinningProvider)$' } | Select-Object -First 8) -join ', '
        Add-Note "MDM (Intune) Windows Update policies are present on the device ($keys). If co-managed, check who owns the Windows Update policies workload."
    }

    # History
    $hist = @(foreach ($h in (ja $C 'WindowsUpdate.History')) {
            $title = js $h 'Title'; if (-not $title) { $title = '' }
            [pscustomobject]@{ Date = (jt $h 'Date'); Title = $title; KB = (js $h 'KB'); Result = (js $h 'Result'); HResult = (js $h 'HResult'); Client = (js $h 'ClientApplicationID') }
        })
    $windowStart = $X.RefNow.AddDays(-$X.Days)
    $fails = @($hist | Where-Object { $_.Date -and $_.Date -ge $windowStart -and ($_.Result -eq 'Failed' -or $_.Result -eq 'Aborted') -and -not (Test-DefinitionUpdate $_.Title) })
    if ($fails.Count -gt 0) {
        $groups = $fails | Group-Object { $(if ($_.KB) { $_.KB } else { Short $_.Title 60 }) + '|' + $_.HResult } | Sort-Object Count -Descending | Select-Object -First 10
        $lines = foreach ($g in $groups) {
            $first = $g.Group[0]
            $lastDate = ($g.Group | Sort-Object Date -Descending | Select-Object -First 1).Date
            $err = Get-ErrorText $first.HResult; if (-not $err) { $err = $first.HResult }
            $nm = $(if ($first.KB) { $first.KB } else { Short $first.Title 60 })
            "${nm}: $err x$($g.Count), last $(Fmt $lastDate)"
        }
        Add-Finding 'High' 'Windows Update' ((Plural $fails.Count 'update install failure') + " in the last $($X.Days) days") (@($lines) -join ' | ') (Get-FixForCodes @($fails | ForEach-Object { $_.HResult }))
    }
    $oks = @($hist | Where-Object { ($_.Result -eq 'Succeeded' -or $_.Result -eq 'SucceededWithErrors') -and $_.Date -and -not (Test-DefinitionUpdate $_.Title) })
    $lastOk = $null
    if ($oks.Count -gt 0) { $lastOk = ($oks | Sort-Object Date -Descending | Select-Object -First 1).Date }
    if ($hist.Count -gt 0) {
        if (-not $lastOk) {
            Add-Finding 'High' 'Windows Update' 'No successful update installs in Windows Update history' ("Only definition updates or failures were found in " + (Plural $hist.Count 'history entry') + '.') 'Work through the SCCM scan/deployment findings; if the client scans fine, check content download (CAS.log) and install errors (WUAHandler.log).'
        }
        elseif (($X.RefNow - $lastOk).TotalDays -gt 45) {
            Add-Finding 'High' 'Windows Update' ("Last successful update install was " + [int]($X.RefNow - $lastOk).TotalDays + ' days ago') ("Last success: " + (Fmt $lastOk)) 'See SCCM scan and deployment findings.'
        }
    }
    $lastCu = $hist | Where-Object { $_.Title -match 'Cumulative Update for Windows' -and $_.Result -eq 'Succeeded' } | Sort-Object Date -Descending | Select-Object -First 1
    if ($lastCu) { Add-Note "Last cumulative update installed: $($lastCu.Title) on $(Fmt $lastCu.Date) via $($lastCu.Client)." }

    # Reboot, uptime, disk, clock
    $up = jd $C 'System.UptimeDays'
    if (jb $C 'PendingReboot.Any') {
        $u = $(if ($null -ne $up) { $up } else { 0 })
        $reasons = @(ja $C 'PendingReboot.Reasons') -join ', '
        Add-Finding $(if ($u -gt 7) { 'High' } else { 'Medium' }) 'Restart' "Restart pending ($reasons)" ("Uptime " + $u.ToString('0.#', $Inv) + " days. Windows and SCCM won't install further updates until the pending restart completes.") "Restart the device. If it keeps coming back, check deployments with 'Suppress restart' and the RebootCoordinator.log."
    }
    elseif ($null -ne $up -and $up -gt 30) {
        Add-Finding 'Medium' 'Restart' ("Device hasn't restarted in " + [int]$up + ' days') 'Long uptime often hides a stuck servicing operation.' 'Restart and re-run the scan cycle.'
    }
    $free = jd $C 'System.SystemDriveFreeGB'
    if ($null -ne $free -and $free -lt 20) {
        $drv = js $C 'System.SystemDrive'; if (-not $drv) { $drv = 'C:' }
        Add-Finding $(if ($free -lt 10) { 'High' } else { 'Medium' }) 'Disk' ("Only " + $free.ToString('0.#', $Inv) + " GB free on $drv") 'Cumulative updates need roughly 10-20 GB free to download, stage and install (plus the SCCM cache).' 'Free space: Disk Cleanup (Windows Update Cleanup), clear old ccmcache content, DISM /Online /Cleanup-Image /StartComponentCleanup.'
    }
    $sd = jd $C 'WindowsUpdate.SoftwareDistributionSizeMB'
    if ($null -ne $sd -and $sd -gt 10240) {
        Add-Finding 'Low' 'Disk' ("SoftwareDistribution folder is " + ($sd / 1024).ToString('0.#', $Inv) + ' GB') 'Large stale download/datastore content.' 'Stop wuauserv and bits, rename C:\Windows\SoftwareDistribution, restart services, run a scan.'
    }
    $tsrc = js $C 'TimeSync.Source'
    if ($tsrc -and $tsrc -match 'Local CMOS|Free-running') {
        Add-Finding 'Medium' 'Time' "Clock is not syncing from a time source ($tsrc)" 'Clock drift breaks Kerberos and TLS/certificate validation to the MP and SUP.' 'w32tm /resync /rediscover; check domain hierarchy time sync and UDP 123.'
    }
    if (jb $C 'WindowsUpdate.Dism.Ran') {
        $dism = [string](js $C 'WindowsUpdate.Dism.Output')
        if ($dism -match 'repairable' -or ($dism -match 'corrupt' -and $dism -notmatch 'No component store corruption')) {
            Add-Finding 'High' 'Servicing' 'Component store corruption detected (DISM)' (Short $dism 400) "DISM /Online /Cleanup-Image /RestoreHealth (add /Source:wim:<install.wim>:1 /LimitAccess if the device can't reach Windows Update), then sfc /scannow."
        }
        elseif ($dism -match 'No component store corruption') { Add-Note 'DISM CheckHealth: no component store corruption detected.' }
    }
    $scanErr = js $C 'WindowsUpdate.Scan.Error'
    if ($scanErr) {
        $code = js $C 'WindowsUpdate.Scan.ErrorCode'
        Add-Finding 'Medium' 'Windows Update' ("Windows Update scan during collection failed (" + (js $C 'WindowsUpdate.Scan.Mode') + ')') ((Get-ErrorText $code) + ' ' + (Short $scanErr 300)) (Get-FixForCodes @($code))
    }
    if (jb $C 'WindowsUpdate.Scan.Ran') {
        $missing = ja $C 'WindowsUpdate.Scan.Missing'
        $crit = @($missing | Where-Object { (js $_ 'Severity') -eq 'Critical' }).Count
        if ($missing.Count -gt 0) {
            Add-Finding $(if ($crit -gt 0) { 'High' } else { 'Medium' }) 'Windows Update' ((Plural $missing.Count 'missing update') + ' found by the ' + (js $C 'WindowsUpdate.Scan.Mode') + ' scan' + $(if ($crit -gt 0) { " ($crit critical)" } else { '' })) (@($missing | Select-Object -First 8 | ForEach-Object { (js $_ 'KB') + ' ' + (Short (js $_ 'Title') 80) }) -join '; ') "See 'Missing updates' below; compare with the SCCM server view to see if they are deployed."
        }
    }
    if ((jbn $C 'SecureBoot.Enabled') -eq $true) {
        $sbStatus = js $C 'SecureBoot.Servicing.UEFICA2023Status'
        if ($sbStatus -and $sbStatus -ne 'Updated') {
            Add-Finding 'Medium' 'Secure Boot' "Secure Boot 2023 certificate update not complete (status: $sbStatus)" "Microsoft's original Secure Boot certificates began expiring in 2026; devices need the 2023 CA certificates to keep receiving boot-component updates." "Make sure the latest cumulative update is installed and the device has restarted; follow Microsoft's Secure Boot certificate update guidance for your hardware."
        }
    }
}

function Invoke-AnalyzeSccmClient {
    $C = $script:C; $X = $script:Ctx
    if (-not $X.SccmInstalled) {
        Add-Finding 'Critical' 'SCCM client' 'ConfigMgr client is not installed (no CcmExec service)' 'Without the client the device never receives Software Center updates.' 'Install the client: ccmsetup.exe /mp:<MP FQDN> SMSSITECODE=<code> (or client push).'
        return
    }
    if ((jbn $C 'Sccm.NamespaceOk') -eq $false) {
        Add-Finding 'Critical' 'SCCM client' 'CCM WMI namespace is missing or broken' (Short (js $C 'Sccm.NamespaceError') 300) 'winmgmt /verifyrepository; if inconsistent winmgmt /salvagerepository; then ccmsetup.exe /forceinstall to rebuild the client.'
    }
    $state = js $C 'Sccm.ServiceState'
    if ($state -and $state -ne 'Running') { Add-Finding 'Critical' 'SCCM client' "SMS Agent Host (CcmExec) is $state" 'The client does nothing while this service is stopped.' 'Start-Service CcmExec; check System log events 7031/7034 for crashes.' }
    if (-not (js $C 'Sccm.SiteCode')) { Add-Finding 'Critical' 'SCCM client' 'Client is not assigned to a site' 'No AssignedSiteCode in the registry.' 'Check boundary groups for site assignment, or reinstall with SMSSITECODE=<code>.' }
    if (-not (js $C 'Sccm.ManagementPoint')) { Add-Finding 'High' 'SCCM client' 'Client has no current management point' 'SMS_Authority.CurrentManagementPoint is empty.' 'Check LocationServices.log and boundary groups; confirm the MP is healthy.' }

    $nsChecked = ($null -ne (js $C 'Sccm.NamespaceOk'))
    $sum = jdict $C 'Sccm.SumConfig'
    if ($nsChecked -and -not $sum) {
        Add-Finding 'High' 'SCCM client' 'Software Updates client settings policy not found' 'CCM_SoftwareUpdatesClientConfig is missing from ActualConfig; the client may not have received machine policy.' 'Trigger Machine Policy Retrieval; check PolicyAgent.log and client settings deployment.'
    }
    elseif ($sum) {
        $enabled = jbn $sum 'ComponentEnabled'; if ($null -eq $enabled) { $enabled = jbn $sum 'Enabled' }
        if ($enabled -eq $false) { Add-Finding 'Critical' 'SCCM client' 'Software Updates are disabled in client settings' 'CCM_SoftwareUpdatesClientConfig.ComponentEnabled = False.' "Enable 'Software Updates' in the client settings deployed to this device's collections." }
    }
    $source = js $C 'Sccm.UpdateSource.ContentLocation'
    if ($nsChecked -and -not $source) {
        Add-Finding 'High' 'SCCM client' 'Client has no software update point (CCM_UpdateSource empty)' "The client hasn't been told which SUP to scan against." 'Check boundary groups include a SUP, the SUP role is healthy (WCM.log/WSUSCtrl.log), and LocationServices.log on the client.'
    }

    $lastScan = jt $C 'Sccm.LastSuccessfulScan'
    $lastFail = jt $C 'Sccm.LastScanFailure'
    if (-not $lastScan) {
        $d = $(if ($lastFail) { "Last scan failure: $(Fmt $lastFail)." } else { 'WUAHandler.log/ScanAgent.log show no completed scan.' })
        Add-Finding 'High' 'SCCM client' "No successful software update scan in the last $($X.Days) days of CCM logs" $d "Run the 'Software Updates Scan Cycle' action and read WUAHandler.log; see scan failure details below."
    }
    elseif (($X.RefNow - $lastScan).TotalDays -gt 7) {
        $d = "Last success $(Fmt $lastScan)" + $(if ($lastFail) { ", last failure $(Fmt $lastFail)" } else { '' })
        Add-Finding 'High' 'SCCM client' ("Last successful update scan was " + [int]($X.RefNow - $lastScan).TotalDays + ' days ago') $d 'Trigger a scan cycle and check WUAHandler.log.'
    }
    else { Add-Note "Last successful SCCM update scan: $(Fmt $lastScan)." }

    foreach ($s in (ja $C 'Sccm.LogSignatures')) {
        $id = js $s 'Id'
        if (-not $id -or $id -eq 'SCAN_OK') { continue }
        $hits = ji $s 'Hits'; if ($null -eq $hits) { $hits = ji $s 'Count' }; if ($null -eq $hits) { $hits = 0 }
        Add-Finding (Get-SevName (js $s 'Severity')) 'SCCM logs' ((js $s 'Title') + " (${hits}x, last " + (Fmt (jt $s 'LastSeen')) + ' in ' + (js $s 'LastLog') + '.log)') (Short (js $s 'Sample') 400) $SignatureFixes[$id]
    }
    $codes = jdict $C 'Sccm.LogErrorCodes'
    if ($codes -and $codes.Count -gt 0) {
        $decoded = @($codes.Keys | Sort-Object { [long](jl $codes.$_ $null) } -Descending | Select-Object -First 8 | ForEach-Object {
                $t = Get-ErrorText $_; if (-not $t) { $t = $_ }
                "$t x$($codes[$_])"
            })
        Add-Finding 'Info' 'SCCM logs' "Error codes seen in CCM logs (top $($decoded.Count))" ($decoded -join ' | ') (Get-FixForCodes @($codes.Keys))
    }
    $wsusLog = js $C 'Sccm.WsusUrlFromLog'
    if ($wsusLog -and $source -and -not (Test-SameServer $wsusLog $source)) { Add-Note "WUAHandler.log last referenced $wsusLog while CCM_UpdateSource is $source." }

    $scu = ja $C 'Sccm.SoftwareCenterUpdates'
    $errored = @($scu | Where-Object { (ji $_ 'EvaluationState') -eq 13 -or ((jl $_ 'ErrorCode') -ne $null -and (jl $_ 'ErrorCode') -ne 0) })
    if ($errored.Count -gt 0) {
        $detail = @($errored | Select-Object -First 8 | ForEach-Object {
                $t = Get-ErrorText (js $_ 'ErrorCode'); if (-not $t) { $t = Get-EvalStateName (ji $_ 'EvaluationState') }
                'KB' + (js $_ 'ArticleID') + ' ' + (Short (js $_ 'Name') 60) + ": $t"
            }) -join ' | '
        Add-Finding 'High' 'Software Center' ((Plural $errored.Count 'deployed update') + ' in an error state in Software Center') $detail ((Get-FixForCodes @($errored | ForEach-Object { js $_ 'ErrorCode' })) + ' Retry from Software Center or run the Software Updates Deployment Evaluation Cycle.')
    }
    $waitMw = @($scu | Where-Object { (ji $_ 'EvaluationState') -eq 14 }).Count
    if ($waitMw -gt 0) { Add-Finding 'Medium' 'Software Center' ((Plural $waitMw 'update') + ' waiting for a maintenance window') 'EvaluationState = WaitServiceWindow.' $SignatureFixes['NO_SERVICE_WINDOW'] }
    $waitReboot = @($scu | Where-Object { @(8, 9, 10) -contains (ji $_ 'EvaluationState') }).Count
    if ($waitReboot -gt 0) { Add-Finding 'Medium' 'Software Center' ((Plural $waitReboot 'update') + ' installed and waiting for a restart') $null 'Restart the device to finish installation.' }
    if ($scu.Count -gt 0) {
        $summary = @($scu | Group-Object { $n = Get-EvalStateName (ji $_ 'EvaluationState'); if ($n) { $n } else { '?' } } | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '
        Add-Note ("Software Center shows " + (Plural $scu.Count 'deployed update') + ": $summary.")
    }
    $clientMissing = @(ja $C 'Sccm.UpdateStatus' | Where-Object { (js $_ 'Status') -eq 'Missing' }).Count
    if ($clientMissing -gt 0 -and $scu.Count -eq 0) {
        Add-Finding 'Medium' 'SCCM client' ("Client scan reports " + (Plural $clientMissing 'missing update') + ' but none are deployed to it') "CCM_UpdateStatus lists them as Missing, yet Software Center has no update deployments." "Deploy the needed software update groups to a collection containing this device (see SCCM server view), or check that the device is in the expected collections."
    }

    $mws = ja $C 'Sccm.ServiceWindows'
    if ($mws.Count -gt 0) {
        $applicable = @($mws | Where-Object { @(1, 4) -contains (ji $_ 'Type') }).Count -gt 0
        if (-not $applicable) { Add-Finding 'Info' 'Maintenance windows' "Device has maintenance windows, none of type 'All deployments' or 'Software updates'" ((Plural $mws.Count 'window') + ' found. Verify updates can install when you expect.') "Review the maintenance windows on the device's collections." }
        $shortOnes = @($mws | Where-Object { $t = ji $_ 'Type'; $du = jl $_ 'Duration'; (@(1, 4) -contains $t) -and $du -gt 0 -and $du -lt 3600 }).Count
        if ($shortOnes -gt 0) { Add-Finding 'Low' 'Maintenance windows' ((Plural $shortOnes 'maintenance window') + ' shorter than 60 minutes') "Cumulative updates default to a 60+ minute max run time and won't start in a shorter window." "Lengthen the windows or lower the update's maximum run time." }
    }
    $cacheMb = jd $C 'Sccm.Cache.SizeMB'
    if ($null -ne $cacheMb -and $cacheMb -gt 0 -and $cacheMb -lt 10240) {
        Add-Finding 'Low' 'SCCM client' ("ccmcache is only " + ($cacheMb / 1024).ToString('0.#', $Inv) + ' GB') 'Feature updates and large cumulative updates can exceed a small cache.' 'Raise the client cache size in client settings (10-25 GB is common).'
    }
    $evalSummary = js $C 'Sccm.CcmEval.Summary'
    $failedChecks = @(ja $C 'Sccm.CcmEval.Checks' | Where-Object { $res = [string](js $_ 'Result'); $res.Length -gt 0 -and $res -ne 'Passed' -and $res -ne 'Not Applicable' })
    if ($failedChecks.Count -gt 0 -or ($evalSummary -and $evalSummary -ne 'Passed')) {
        $t = $(if ($evalSummary) { $evalSummary } else { 'failures' })
        Add-Finding 'High' 'SCCM client' "CCMEval health check: $t" (@($failedChecks | Select-Object -First 8 | ForEach-Object { (Short (js $_ 'Description') 80) + ' = ' + (js $_ 'Result') }) -join ' | ') 'Review CcmEval.log; repair the client (ccmrepair.exe or ccmsetup /forceinstall).'
    }
    $failedApps = @(ja $C 'Sccm.Applications' | Where-Object { $e = jl $_ 'ErrorCode'; $null -ne $e -and $e -ne 0 })
    if ($failedApps.Count -gt 0) {
        Add-Finding 'Medium' 'Software Center' ((Plural $failedApps.Count 'application') + ' with install errors in Software Center') (@($failedApps | Select-Object -First 8 | ForEach-Object { $t = Get-ErrorText (js $_ 'ErrorCode'); if (-not $t) { $t = js $_ 'ErrorCode' }; (js $_ 'Name') + ": $t" }) -join ' | ') $SignatureFixes['APP_FAIL']
    }
    if (jb $C 'Sccm.CoManagement.IntuneEnrolled') {
        $flags = js $C 'Sccm.CoManagement.CoManagementFlags'
        Add-Note ("Device is MDM-enrolled (co-managed" + $(if ($flags) { ", flags $flags" } else { '' }) + "). If the 'Windows Update policies' workload is moved to Intune, SCCM software update deployments stop applying.")
    }
}

function Invoke-AnalyzeEvents {
    $C = $script:C; $X = $script:Ctx
    $evs = @(foreach ($e in (ja $C 'Events')) {
            $prov = js $e 'Provider'; if (-not $prov) { $prov = '' }
            $msg = js $e 'Message'; if (-not $msg) { $msg = '' }
            $id = ji $e 'Id'; if ($null -eq $id) { $id = 0 }
            $lvl = ji $e 'Level'; if ($null -eq $lvl) { $lvl = 4 }
            [pscustomobject]@{ Log = (js $e 'Log'); Provider = $prov; Message = $msg; Tag = (js $e 'Tag'); Id = $id; Level = $lvl; Time = (jt $e 'Time') }
        })
    if ($evs.Count -eq 0) { return }

    $wu20 = @($evs | Where-Object { $_.Provider -match 'WindowsUpdateClient' -and $_.Id -eq 20 })
    if ($wu20.Count -gt 0) {
        $allCodes = @($wu20 | ForEach-Object { Find-ErrorCodes $_.Message } | ForEach-Object { $_ })
        $codeText = @($allCodes | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { $t = Get-ErrorText $_.Name; if (-not $t) { $t = $_.Name }; "$t x$($_.Count)" }) -join ', '
        $latest = $wu20 | Sort-Object Time -Descending | Select-Object -First 1
        Add-Finding 'High' 'Event log' ((Plural $wu20.Count 'Windows Update installation failure') + ' (WindowsUpdateClient event 20)') ("Latest: " + (Short $latest.Message 250) + " | Codes: $codeText") (Get-FixForCodes $allCodes)
    }
    $wu31 = @($evs | Where-Object { $_.Provider -match 'WindowsUpdateClient' -and $_.Id -eq 31 }).Count
    if ($wu31 -gt 0) { Add-Finding 'Medium' 'Event log' ((Plural $wu31 'Windows Update download failure') + ' (event 31)') $null 'Check BITS, disk space, and DP/SUP reachability.' }

    $svcPattern = 'Windows Update|SMS Agent Host|Background Intelligent Transfer|Cryptographic Services|Windows Management Instrumentation|Windows Modules Installer|Windows Installer|Update Orchestrator'
    $scm = @($evs | Where-Object { $_.Provider -eq 'Service Control Manager' -and (@(7000, 7009, 7011, 7022, 7023, 7024, 7031, 7034) -contains $_.Id) -and $_.Message -match $svcPattern })
    if ($scm.Count -gt 0) {
        Add-Finding 'High' 'Event log' ((Plural $scm.Count 'service failure') + ' for update-related services') (@($scm | Sort-Object Time -Descending | Select-Object -First 5 | ForEach-Object { (Fmt $_.Time) + " $($_.Id): " + (Short $_.Message 140) }) -join ' | ') 'Investigate the crashing service (Application log for faulting module); repair WMI or the SCCM client if CcmExec/Winmgmt crash repeatedly.'
    }
    $disk = @($evs | Where-Object { ($_.Provider -eq 'disk' -and (@(7, 51, 153) -contains $_.Id)) -or ($_.Provider -match 'Ntfs' -and (@(55, 98, 140) -contains $_.Id)) })
    if ($disk.Count -gt 0) {
        Add-Finding 'High' 'Event log' (Plural $disk.Count 'disk or file system error') (Short ($disk | Sort-Object Time -Descending | Select-Object -First 1).Message 250) 'Check disk health (chkdsk /scan, SMART/vendor diagnostics). Failing storage causes servicing corruption.'
    }
    $crashes = @($evs | Where-Object { ($_.Id -eq 41 -and $_.Provider -match 'Kernel-Power') -or ($_.Id -eq 6008 -and $_.Provider -eq 'EventLog') }).Count
    if ($crashes -ge 3) { Add-Finding 'Medium' 'Event log' ((Plural $crashes 'unexpected shutdown') + " in $($X.Days) days") 'Power loss or crashes during servicing can leave updates half-installed.' 'Check power settings, BSOD dumps and hardware.' }
    if (@($evs | Where-Object { $_.Id -eq 5719 -and $_.Provider -match 'NETLOGON' }).Count -gt 0) { Add-Finding 'Medium' 'Event log' "Netlogon couldn't reach a domain controller (5719)" $null 'Check network, DNS and the secure channel (Test-ComputerSecureChannel).' }
    if (@($evs | Where-Object { $_.Provider -match 'Time-Service' -and $_.Level -le 3 }).Count -gt 0) { Add-Finding 'Low' 'Event log' 'Windows Time service warnings' $null 'w32tm /query /status; resync with the domain hierarchy.' }

    $blocked = @($evs | Where-Object { $_.Provider -match 'AppLocker' -and (@(8004, 8007) -contains $_.Id) })
    $audited = @($evs | Where-Object { $_.Provider -match 'AppLocker' -and (@(8003, 8006) -contains $_.Id) })
    if ($blocked.Count -gt 0) {
        $updRelated = @($blocked | Where-Object { $_.Message -match 'ccmcache|\\CCM\\|SoftwareDistribution|ccmsetup|\\Temp\\' }).Count
        $paths = @($blocked | ForEach-Object { $m = [regex]::Match($_.Message, '^(.*?) was (prevented|not allowed)'); if ($m.Success) { $m.Groups[1].Value } else { Short $_.Message 120 } } |
                Group-Object | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ' | '
        Add-Finding $(if ($updRelated -gt 0) { 'High' } else { 'Medium' }) 'AppLocker' ((Plural $blocked.Count 'file') + ' blocked by AppLocker' + $(if ($updRelated -gt 0) { " ($updRelated from SCCM/Windows Update paths)" } else { '' })) $paths $SignatureFixes['APPLOCKER']
    }
    if ($audited.Count -gt 0) { Add-Note ("AppLocker audit mode would have blocked " + (Plural $audited.Count 'file') + ' (events 8003/8006). Check these before enforcing.') }
    $msiFail = @($evs | Where-Object { $_.Provider -eq 'MsiInstaller' -and ($_.Id -eq 11708 -or ($_.Id -eq 1033 -and $_.Message -notmatch 'status:\s*0\b')) })
    if ($msiFail.Count -gt 0) { Add-Finding 'Medium' 'Event log' (Plural $msiFail.Count 'MSI install failure') (@($msiFail | Sort-Object Time -Descending | Select-Object -First 4 | ForEach-Object { Short $_.Message 160 }) -join ' | ') 'Check AppEnforce.log for the matching deployment and the MSI verbose log.' }
    $setupErr = @($evs | Where-Object { $_.Tag -eq 'Setup' -and $_.Level -le 2 })
    if ($setupErr.Count -gt 0) { Add-Finding 'Medium' 'Event log' ((Plural $setupErr.Count 'servicing error') + ' in the Setup log') (@($setupErr | Select-Object -First 4 | ForEach-Object { Short $_.Message 160 }) -join ' | ') 'Review CBS.log around these times; run DISM /RestoreHealth.' }

    foreach ($g in ($evs | Where-Object { $_.Level -ge 1 -and $_.Level -le 2 } | Group-Object { "$($_.Log)|$($_.Provider)|$($_.Id)" } | Sort-Object Count -Descending | Select-Object -First 25)) {
        $latest = $g.Group | Sort-Object Time -Descending | Select-Object -First 1
        [void]$script:R.EventGroups.Add([ordered]@{ Log = $latest.Log; Provider = $latest.Provider; Id = [string]$latest.Id; Count = [string]$g.Count; Last = (Fmt $latest.Time); Sample = (Short $latest.Message 220) })
    }
}

function Invoke-AnalyzeConnectivity {
    $C = $script:C; $X = $script:Ctx
    foreach ($t in (ja $C 'Network.Connectivity')) {
        $purpose = [string](js $t 'Purpose')
        if ($purpose -match 'informational') { continue }
        $hostName = js $t 'Host'; $port = js $t 'Port'; $http = js $t 'Http'; $err = js $t 'Error'
        $sevFail = $(if ($X.LikelyOffline) { 'Info' } else { 'High' })
        if (-not (jb $t 'DnsOk')) { Add-Finding $sevFail 'Connectivity' "Can't resolve $hostName ($purpose)" $err 'Check DNS suffix/servers, VPN, and that the name in policy is correct.' }
        elseif (-not (jb $t 'TcpOk')) { Add-Finding $sevFail 'Connectivity' "Can't connect to ${hostName}:$port ($purpose)" $err 'Check firewall rules (client and server), the IIS site on that port, and any proxy.' }
        elseif ($http -and ($http.StartsWith('ERR') -or $http -match 'HTTP [45]\d\d')) {
            $mp403 = ($purpose -match 'Management point' -and $http -match '403')
            $fix = $(if ($purpose -match 'WSUS|SUP') { 'HTTP 503 = WsusPool stopped; 404 = wrong port/vdir; 401/403 = permissions or proxy. Check IIS on the SUP.' } else { 'Check MP health (mpcontrol.log) and whether the MP requires HTTPS/client certificates.' })
            Add-Finding $(if ($mp403) { 'Info' } else { 'Medium' }) 'Connectivity' "$purpose answered $http" "${hostName}:$port" $fix
        }
    }
}

function Invoke-AnalyzeServer {
    $C = $script:C; $X = $script:Ctx
    if (-not $script:Sms) { Add-Note 'SCCM server comparison skipped (run with -SiteServer <SMS Provider> to compare with the site).'; return }
    $script:R.ServerName = $script:Sms.Server; $script:R.SiteCode = $script:Sms.SiteCode; $script:R.SiteVersion = $script:Sms.SiteVersion
    if (-not $script:Sms.Connected) {
        $script:R.ServerError = $script:Sms.Error
        Add-Finding 'Medium' 'SCCM server' "Could not query the SMS Provider $($script:Sms.Server)" $script:Sms.Error 'Run as an account with at least Read-only Analyst rights, check DCOM/WMI firewall rules to the provider, or pass -SiteCode.'
        return
    }
    $name = $script:R.ComputerName
    $v = Get-SmsDeviceView $name $script:R.CuPattern $script:R.LatestKb
    $script:R.Server = $v
    if ($v.Error) { Add-Finding 'Medium' 'SCCM server' 'Part of the SMS Provider query failed' $v.Error 'Results below may be partial.' }
    if ($v.Records.Count -eq 0) {
        Add-Finding 'Critical' 'SCCM server' "Device $name was not found in SCCM" 'No SMS_R_System record. The client has never registered, was deleted, or is reporting under another name.' 'Check ClientIDManagerStartup.log and LocationServices.log on the client; verify discovery; reinstall the client if needed.'
        return
    }
    if ($v.Records.Count -gt 1) {
        Add-Finding 'High' 'SCCM server' ((Plural $v.Records.Count 'SCCM record') + " exist for $name") (@($v.Records | ForEach-Object { "ResourceId $($_.ResourceId) client=$($_.Client) obsolete=$($_.Obsolete) GUID $($_.SMSUniqueIdentifier)" }) -join ' | ') 'Delete the obsolete/duplicate records. If several are active, the image may share an SMS GUID: run ccmsetup /forceinstall or delete SMSCFG.INI and the SMS certificates, then restart CcmExec.'
    }
    $clientGuid = js $C 'Sccm.ClientId'
    if ($clientGuid -and $v.SmsGuid -and $clientGuid -ne $v.SmsGuid) {
        Add-Finding 'High' 'SCCM server' "SCCM record GUID doesn't match the client's GUID" "Client: $clientGuid / Site: $($v.SmsGuid). The device's state messages and inventory land on another record (or nowhere)." 'Delete the stale record and trigger a Discovery Data Collection Cycle on the client; if the client GUID keeps changing, reinstall the client.'
    }
    if ($v.Combined) {
        $cv = $v.Combined
        if ($cv.IsObsolete -eq 'True' -or $cv.IsObsolete -eq '1') { Add-Finding 'High' 'SCCM server' 'Device record is marked obsolete' $null 'Delete the obsolete record; the active record should be recreated by the client.' }
        if ($cv.IsBlocked -eq 'True' -or $cv.IsBlocked -eq '1') { Add-Finding 'High' 'SCCM server' 'Device is blocked in SCCM' $null 'Unblock the device in the console.' }
        if ($cv.IsApproved -eq '0') { Add-Finding 'High' 'SCCM server' 'Client is not approved' $null "Approve the client in the console (or adjust the site's approval setting)." }
        if ($cv.ClientActiveStatus -eq '0') { Add-Finding 'High' 'SCCM server' 'Site reports the client as inactive' "Client activity: last active $($cv.LastActiveTime), last policy request $($cv.LastPolicyRequest)." "Client isn't talking to the MP: see client MP communication findings." }
        $lp = ConvertTo-DateValue $cv.LastPolicyRequest
        if ($lp -and ((Get-Date) - $lp).TotalDays -gt 7) { Add-Finding 'High' 'SCCM server' ("Site hasn't received a policy request from this device in " + [int]((Get-Date) - $lp).TotalDays + ' days') "Last policy request $(Fmt $lp) via $($cv.LastMPServerName)." 'Check client-to-MP communication (CcmMessaging.log, LocationServices.log) and whether the device is online.' }
        $hw = ConvertTo-DateValue $cv.LastHardwareScan
        if ($hw -and ((Get-Date) - $hw).TotalDays -gt 14) { Add-Finding 'Medium' 'SCCM server' ("Last hardware inventory received " + [int]((Get-Date) - $hw).TotalDays + ' days ago') $null 'Inventory and state messages share the same path to the MP; check MP communication.' }
    }
    $clientVer = js $C 'Sccm.ClientVersion'
    if ($clientVer -and $script:Sms.SiteVersion) {
        $cvv = ConvertTo-Ver $clientVer; $sv = ConvertTo-Ver $script:Sms.SiteVersion
        if ($cvv -and $sv -and $cvv.Build -lt $sv.Build) {
            Add-UpdateRow 'ConfigMgr client' $clientVer "site $($script:Sms.SiteVersion)" 'Older than site' 'Upgrade the client (automatic client upgrade or client push)' 'Medium'
            Add-Finding 'Medium' 'SCCM client' "ConfigMgr client $clientVer is older than the site ($($script:Sms.SiteVersion))" $null 'Enable automatic client upgrade in Hierarchy Settings or push the client.'
        }
        else { Add-UpdateRow 'ConfigMgr client' $clientVer "site $($script:Sms.SiteVersion)" 'Current' 'None' 'OK' }
    }
    if ($v.Deployments.Count -eq 0) { Add-Finding 'High' 'SCCM server' 'No software update deployments target any collection this device is in' ("Device is in " + (Plural $v.Collections.Count 'collection') + '.') 'Add the device to a collection that receives your monthly SUG/ADR deployment.' }
    if (-not $v.LastStatusCheck) { Add-Finding 'High' 'SCCM server' 'Site has no update compliance data for this device' 'SMS_UpdateComplianceStatus has no rows: the client has never sent scan results (state messages).' "Fix the client scan first; then run 'Software Updates Scan Cycle' and check StateMessage.log." }
    elseif (((Get-Date) - $v.LastStatusCheck).TotalDays -gt 7) { Add-Finding 'High' 'SCCM server' ("Site's latest update scan result from this device is " + [int]((Get-Date) - $v.LastStatusCheck).TotalDays + ' days old') "Last status check $(Fmt $v.LastStatusCheck)." "The client isn't scanning or isn't delivering state messages; see client scan findings." }

    $deployedMissing = @($v.Required | Where-Object { $_.DeployedToDevice -and -not $_.IsExpired })
    $notDeployed = @($v.Required | Where-Object { -not $_.DeployedToDevice -and -not $_.IsExpired -and -not $_.IsSuperseded })
    if ($deployedMissing.Count -gt 0) {
        $detail = @($deployedMissing | Select-Object -First 10 | ForEach-Object { $e = ''; if ($_.LastError) { $t = Get-ErrorText $_.LastError; if (-not $t) { $t = $_.LastError }; $e = " ($t)" }; "KB$($_.Article) " + (Short $_.Title 70) + $e }) -join ' | '
        Add-Finding 'High' 'SCCM server' ((Plural $deployedMissing.Count 'deployed update') + ' required but not installed (site view)') $detail 'These are deployed to the device, so this is a client-side install problem: work through the client findings (scan, content, maintenance window, restart, install errors).'
    }
    if ($notDeployed.Count -gt 0) {
        Add-Finding 'Medium' 'SCCM server' ((Plural $notDeployed.Count 'required update') + ' not deployed to this device') (@($notDeployed | Select-Object -First 10 | ForEach-Object { "KB$($_.Article) " + (Short $_.Title 70) }) -join ' | ') "Add them to a software update group deployed to one of this device's collections (or adjust the ADR criteria)."
    }
    if ($script:R.LatestKb) {
        $kb = $script:R.LatestKb
        $inCat = @($v.LatestMicrosoftKbInCatalog)
        if ($inCat.Count -eq 0 -or $null -eq $inCat[0]) {
            $pat = $(if ($script:R.CuPattern) { $script:R.CuPattern } else { 'this OS' })
            Add-Finding 'High' 'SCCM server' "Latest Microsoft cumulative update $kb is not in the SCCM catalog for $pat" "The SUP hasn't synchronized it, or the product/classification isn't selected." "Check SUP sync (wsyncmgr.log, WCM.log), that the OS product (e.g. 'Windows 11') and 'Security Updates' classification are selected, and run a sync."
        }
        else {
            $e = $inCat[0]
            if (-not $e.IsDeployed) { Add-Finding 'High' 'SCCM server' "$kb is in SCCM but not deployed anywhere" $e.Title 'Add it to the monthly SUG / check that the ADR ran and its criteria match.' }
            elseif (-not $e.DeployedToDevice) { Add-Finding 'High' 'SCCM server' "$kb is deployed, but not to any collection containing this device" $e.Title "Check which collection the deployment targets and the device's membership." }
            else { Add-Note "$kb is deployed to this device ($($e.Title))." }
        }
    }
    if ($v.MaintenanceWindows.Count -gt 0) {
        $applicable = @($v.MaintenanceWindows | Where-Object { ($_.TypeId -eq '1' -or $_.TypeId -eq '4') -and $_.Enabled -ne 'False' }).Count -gt 0
        if (-not $applicable) {
            Add-Finding 'Medium' 'Maintenance windows' "Device's collections have maintenance windows, but none for all deployments or software updates" (@($v.MaintenanceWindows | Select-Object -First 6 | ForEach-Object { "$($_.Collection): $($_.Name) ($($_.Type))" }) -join ' | ') "Add a 'Software updates' or 'All deployments' maintenance window, or allow the deployment to install outside maintenance windows."
        }
    }
}

function Invoke-AnalyzeWsus {
    $C = $script:C
    if (-not $WsusServer) { return }
    $res = Get-WsusDevice $WsusServer $WsusPort ([bool]$WsusSsl) (js $C 'System.Fqdn') $script:R.ComputerName
    $script:R.Wsus = $res.Data; $script:R.WsusError = $res.Error
    if ($res.Error) { Add-Finding 'Info' 'WSUS' 'WSUS check not available' $res.Error $null; return }
    $w = $res.Data
    if ($w.Found -ne 'True') { Add-Finding 'Medium' 'WSUS' "Device not found in WSUS $WsusServer" 'WSUS creates the computer object the first time the device scans successfully.' 'Fix the client scan (see SCCM client findings).'; return }
    $last = ConvertTo-DateValue $w.LastReportedStatusTime
    if ($last -and ((Get-Date) - $last).TotalDays -gt 7) { Add-Finding 'High' 'WSUS' ("Device last reported to WSUS " + [int]((Get-Date) - $last).TotalDays + ' days ago') "Last reported $(Fmt $last)." "The WUA scan isn't completing; see scan failures." }
    if ($w.FailedCount -and $w.FailedCount -ne '0') { Add-Finding 'Medium' 'WSUS' "WSUS reports $($w.FailedCount) failed update(s) for this device" $null 'Compare with the Windows Update history failures above.' }
}

function Invoke-BuildMissing {
    $C = $script:C
    $map = [ordered]@{}
    $addRow = {
        param($kb, $title, $source, $severity, $extra)
        $key = $(if ($kb) { $kb } elseif ($title) { $title } else { '?' })
        if (-not $map.Contains($key)) { $map[$key] = [ordered]@{ KB = $kb; Title = $title; Sources = $source; Severity = $severity; Notes = $extra } }
        else {
            $row = $map[$key]
            if ($row.Sources -notlike "*$source*") { $row.Sources = "$($row.Sources); $source" }
            if (-not $row.Severity) { $row.Severity = $severity }
            if ($extra) { $row.Notes = $(if ($row.Notes) { "$($row.Notes); $extra" } else { $extra }) }
        }
    }
    $mode = js $C 'WindowsUpdate.Scan.Mode'
    foreach ($m in (ja $C 'WindowsUpdate.Scan.Missing')) { & $addRow (js $m 'KB') (js $m 'Title') "WUA scan ($mode)" (js $m 'Severity') $null }
    foreach ($s in (ja $C 'Sccm.UpdateStatus')) {
        if ((js $s 'Status') -ne 'Missing') { continue }
        $art = js $s 'Article'
        & $addRow $(if ($art) { "KB$art" } else { $null }) (js $s 'Title') 'SCCM client scan' $null $null
    }
    foreach ($u in (ja $C 'Sccm.SoftwareCenterUpdates')) {
        $es = ji $u 'EvaluationState'
        if ($es -eq 12) { continue }
        $art = js $u 'ArticleID'
        $dl = jt $u 'Deadline'
        & $addRow $(if ($art) { "KB$art" } else { $null }) (js $u 'Name') 'Software Center' $null ("State " + (Get-EvalStateName $es) + $(if ($dl) { ", deadline $(Fmt $dl)" } else { '' }))
    }
    if ($script:R.Server) {
        foreach ($su in $script:R.Server.Required) { & $addRow "KB$($su.Article)" $su.Title 'SCCM site (required)' $null $(if ($su.DeployedToDevice) { 'deployed to device' } else { 'NOT deployed to device' }) }
    }
    foreach ($row in ($map.Values | Sort-Object { if ($_.KB) { $_.KB } else { 'zzz' } })) { [void]$script:R.Missing.Add($row) }
}

function Invoke-BuildRecentInstalls {
    $C = $script:C; $X = $script:Ctx
    $start = $X.RefNow.AddDays(-$X.Days)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($h in (ja $C 'WindowsUpdate.History')) {
        $d = jt $h 'Date'
        if (-not $d -or $d -lt $start) { continue }
        $client = [string](js $h 'ClientApplicationID')
        $via = $(if ($client -eq 'CcmExec') { 'SCCM / Software Center (WUA)' } else { 'Windows Update Agent (' + $(if ($client) { $client } else { '?' }) + ')' })
        $res = js $h 'Result'
        $list.Add([pscustomobject]@{ Sort = $d; Row = [ordered]@{ Time = (Fmt $d); Item = (js $h 'Title'); Result = $res; Source = $via; Error = $(if ($res -eq 'Succeeded') { $null } else { Get-ErrorText (js $h 'HResult') }) } })
    }
    foreach ($a in (ja $C 'Sccm.Applications')) {
        $d = jt $a 'LastInstallTime'
        if (-not $d -or $d -lt $start) { continue }
        $list.Add([pscustomobject]@{ Sort = $d; Row = [ordered]@{ Time = (Fmt $d); Item = ((js $a 'Name') + ' ' + (js $a 'SoftwareVersion')).Trim(); Result = (js $a 'InstallState'); Source = 'Software Center application'; Error = (Get-ErrorText (js $a 'ErrorCode')) } })
    }
    foreach ($e in (ja $C 'Events')) {
        $tag = js $e 'Tag'; $id = ji $e 'Id'; $msg = [string](js $e 'Message'); $d = jt $e 'Time'
        if (-not $d) { continue }
        if ($tag -eq 'MSI' -and (@(1033, 11707, 11708) -contains $id)) {
            $res = $(if ($id -eq 11708) { 'Failed' } elseif ($id -eq 11707) { 'Succeeded' } elseif ($msg -match 'status:\s*0\b') { 'Succeeded' } else { 'See message' })
            $list.Add([pscustomobject]@{ Sort = $d; Row = [ordered]@{ Time = (Fmt $d); Item = (Short $msg 160); Result = $res; Source = 'MSI (Application log)'; Error = $null } })
        }
        elseif ($tag -eq 'Setup') {
            $m = [regex]::Match($msg, 'Package (\S+) was successfully changed to the (\w+) state', 'IgnoreCase')
            if ($m.Success) { $list.Add([pscustomobject]@{ Sort = $d; Row = [ordered]@{ Time = (Fmt $d); Item = $m.Groups[1].Value; Result = $m.Groups[2].Value; Source = 'Servicing (Setup log)'; Error = $null } }) }
            elseif ((ji $e 'Level') -le 2) {
                $errText = @(Find-ErrorCodes $msg | ForEach-Object { Get-ErrorText $_ }) -join ', '
                $list.Add([pscustomobject]@{ Sort = $d; Row = [ordered]@{ Time = (Fmt $d); Item = (Short $msg 160); Result = 'Error'; Source = 'Servicing (Setup log)'; Error = $errText } })
            }
        }
    }
    foreach ($x in ($list | Sort-Object Sort -Descending | Select-Object -First 300)) { [void]$script:R.RecentInstalls.Add($x.Row) }
}

function Invoke-Analysis($Data) {
    $script:C = $Data
    $script:R = [pscustomobject]@{
        ComputerName = $null; BundlePath = $null; ReportPath = $null; CollectedAt = $null
        Findings = (New-Object System.Collections.ArrayList); Updates = (New-Object System.Collections.ArrayList)
        Missing = (New-Object System.Collections.ArrayList); RecentInstalls = (New-Object System.Collections.ArrayList)
        EventGroups = (New-Object System.Collections.ArrayList); Notes = (New-Object System.Collections.ArrayList)
        Server = $null; ServerName = $null; ServerError = $null; SiteCode = $null; SiteVersion = $null
        Wsus = $null; WsusError = $null; LatestKb = $null; CuPattern = $null
    }
    $name = js $Data 'System.ComputerName'; if (-not $name) { $name = js $Data 'Meta.ComputerName' }
    $script:R.ComputerName = $name
    $script:R.CollectedAt = jt $Data 'Meta.CollectedAtLocal'
    $refNow = $script:R.CollectedAt; if (-not $refNow) { $refNow = Get-Date }
    $days = ji $Data 'Meta.DaysBack'; if (-not $days) { $days = 30 }
    $build = ji $Data 'System.CurrentBuild'; if ($null -eq $build) { $build = 0 }
    $ubr = ji $Data 'System.UBR'; if ($null -eq $ubr) { $ubr = 0 }
    $disp = js $Data 'System.DisplayVersion'; if (-not $disp) { $disp = js $Data 'System.ReleaseId' }
    $edition = js $Data 'System.EditionID'; if (-not $edition) { $edition = '' }
    $arch = js $Data 'System.UpdateArch'; if (-not $arch) { $arch = 'x64' }
    $script:Ctx = [pscustomobject]@{
        RefNow = $refNow; Days = $days; Build = $build; Ubr = $ubr; Disp = $disp; Edition = $edition; Arch = $arch
        SccmInstalled = (jb $Data 'Sccm.Installed'); LikelyOffline = (jb $Data 'Meta.LikelyOffline')
    }

    Invoke-Step 'Collection' { Invoke-AnalyzeMeta }
    Invoke-Step 'Windows' { Invoke-AnalyzeWindows }
    Invoke-Step '.NET' { Invoke-AnalyzeDotNet }
    Invoke-Step 'Windows Update' { Invoke-AnalyzeWindowsUpdate }
    Invoke-Step 'SCCM client' { Invoke-AnalyzeSccmClient }
    Invoke-Step 'Event logs' { Invoke-AnalyzeEvents }
    Invoke-Step 'Connectivity' { Invoke-AnalyzeConnectivity }
    Invoke-Step 'SCCM server' { Invoke-AnalyzeServer }
    Invoke-Step 'WSUS' { Invoke-AnalyzeWsus }
    Invoke-Step 'Missing updates' { Invoke-BuildMissing }
    Invoke-Step 'Recent installs' { Invoke-BuildRecentInstalls }

    if (@($script:R.Findings | Where-Object { (Get-SevRank $_.Severity) -le 1 }).Count -eq 0) {
        Add-Finding 'OK' 'Summary' 'No critical or high-severity problems found' 'Review medium/low findings below.' $null
    }
    $sorted = @($script:R.Findings | Sort-Object @{ Expression = { Get-SevRank $_.Severity } }, @{ Expression = { $_.Area } })
    $script:R.Findings.Clear()
    foreach ($f in $sorted) { [void]$script:R.Findings.Add($f) }
    return $script:R
}

function Get-SevCount($Result, [string]$Sev) { return @($Result.Findings | Where-Object { $_.Severity -eq $Sev }).Count }

#endregion

#region HTML report -------------------------------------------------------------------------

$Css = @'
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2430;--muted:#5d6b7e;--line:#e3e7ee;--crit:#b3261e;--high:#d9480f;--med:#b7791f;--low:#2b6cb0;--info:#5d6b7e;--ok:#2f855a}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#1f2a3a;color:#fff;padding:20px 28px}header h1{margin:0 0 4px;font-size:22px;font-weight:600}header .sub{color:#c9d3e0;font-size:13px}
main{padding:20px 28px;max-width:1500px}section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin:0 0 18px}
h2{font-size:17px;margin:0 0 12px}h3{font-size:14px;margin:16px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{background:#f0f3f7;font-weight:600;position:sticky;top:0}tr:hover td{background:#fafbfc}td.k{width:260px;color:var(--muted)}
.b{display:inline-block;min-width:64px;text-align:center;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}.Info{background:var(--info)}.OK{background:var(--ok)}
.chips{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}.chip{background:rgba(255,255,255,.1);border-radius:6px;padding:6px 12px;font-size:13px}.chip b{font-size:18px;margin-right:6px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:18px}
details{margin:6px 0}summary{cursor:pointer;color:#2b5797;font-weight:600}code,.mono{font-family:Consolas,monospace;font-size:12px}
.muted{color:var(--muted)}.fix{color:#22543d}.small{font-size:12px}ul{margin:4px 0 4px 18px;padding:0}
nav{font-size:13px;margin:0 0 16px}nav a{margin-right:14px;color:#2b5797;text-decoration:none}
@media print{nav{display:none}th{position:static}section{break-inside:avoid}}
'@

function Enc($s) { if ($null -eq $s) { return '' }; return [System.Net.WebUtility]::HtmlEncode([string]$s) }
function Badge([string]$sev) { $s = Get-SevName $sev; return "<span class=`"b $s`">$s</span>" }
function W([string]$s) { [void]$script:SB.Append($s) }
function New-RowList { return ,(New-Object System.Collections.Generic.List[object]) }

function Write-Table([string[]]$Headers, $Rows, [string]$Empty) {
    if ($null -eq $Rows -or $Rows.Count -eq 0) { if ($Empty) { W ('<p class="muted">' + (Enc $Empty) + '</p>') }; return }
    W '<table><thead><tr>'
    foreach ($h in $Headers) { W ('<th>' + (Enc $h) + '</th>') }
    W '</tr></thead><tbody>'
    foreach ($row in $Rows) {
        W '<tr>'
        foreach ($cell in $row) { W ('<td>' + [string]$cell + '</td>') }
        W '</tr>'
    }
    W '</tbody></table>'
}

function Write-KV($Pairs) {
    W '<table><tbody>'
    foreach ($p in $Pairs) {
        if ($null -eq $p[1]) { continue }
        W ('<tr><td class="k">' + (Enc $p[0]) + '</td><td>' + (Enc $p[1]) + '</td></tr>')
    }
    W '</tbody></table>'
}

function Write-DictTable($Dict, [string]$Empty) {
    if ($null -eq $Dict -or $Dict.Count -eq 0) { W ('<p class="muted">' + (Enc $Empty) + '</p>'); return }
    $pairs = New-RowList
    foreach ($k in $Dict.Keys) { $pairs.Add(@($k, [Convert]::ToString($Dict[$k], $Inv))) }
    Write-KV $pairs
}

function YesNo($b) { if ($b) { return 'Yes' } else { return 'No' } }

function Build-Report($Res) {
    $C = $script:C
    $script:SB = New-Object System.Text.StringBuilder(262144)
    $title = "Update Health Report - $($Res.ComputerName)"
    W '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    W ('<title>' + (Enc $title) + '</title><style>' + $Css + '</style></head><body>')
    W ('<header><h1>' + (Enc $title) + '</h1><div class="sub">')
    W (Enc ((js $C 'System.OSCaption') + ' ' + (js $C 'System.DisplayVersion') + ' - build ' + (js $C 'System.FullBuild') + ' - ' + (js $C 'System.UpdateArch')))
    W (' &middot; Collected ' + (Enc (Fmt $Res.CollectedAt)) + ' &middot; Analyzed ' + (Enc (Fmt (Get-Date))))
    W '</div><div class="chips">'
    foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) { W ("<div class=`"chip`"><b>$(Get-SevCount $Res $s)</b>$s</div>") }
    W '</div></header><main>'
    W '<nav><a href="#updates">What needs updating</a><a href="#findings">Findings</a><a href="#missing">Missing updates</a><a href="#recent">Recent installs</a><a href="#sc">Software Center</a><a href="#client">SCCM client</a><a href="#server">SCCM server</a><a href="#wu">Windows Update</a><a href="#dotnet">.NET</a><a href="#events">Events</a><a href="#system">System</a><a href="#sources">Data sources</a></nav>'

    W '<section id="updates"><h2>What needs to be updated</h2>'
    $rows = New-RowList
    foreach ($u in ($Res.Updates | Sort-Object { Get-SevRank $_.Severity })) { $rows.Add(@((Badge $u.Severity), (Enc $u.Component), (Enc $u.Installed), (Enc $u.Latest), (Enc $u.Status), (Enc $u.Action))) }
    Write-Table @('', 'Component', 'Installed', 'Latest', 'Status', 'Action') $rows 'No version data.'
    W '</section>'

    W '<section id="findings"><h2>Findings - why it isn''t updating</h2>'
    $rows = New-RowList
    foreach ($f in $Res.Findings) {
        $detail = $(if ($f.Detail) { '<div class="small muted">' + (Enc $f.Detail) + '</div>' } else { '' })
        $rows.Add(@((Badge $f.Severity), (Enc $f.Area), ('<b>' + (Enc $f.Title) + '</b>' + $detail), ('<span class="fix">' + (Enc $f.Fix) + '</span>')))
    }
    Write-Table @('Severity', 'Area', 'Finding', 'Recommended fix') $rows 'No findings.'
    if ($Res.Notes.Count -gt 0) { W '<h3>Notes</h3><ul>'; foreach ($n in $Res.Notes) { W ('<li>' + (Enc $n) + '</li>') }; W '</ul>' }
    W '</section>'

    W '<section id="missing"><h2>Missing updates (all sources)</h2>'
    $rows = New-RowList
    foreach ($m in $Res.Missing) { $rows.Add(@((Enc $m.KB), (Enc $m.Title), (Enc $m.Severity), (Enc $m.Sources), (Enc $m.Notes))) }
    Write-Table @('KB', 'Title', 'Severity', 'Seen by', 'Notes') $rows 'No missing updates reported by the client scan, Software Center, WUA scan or the site.'
    W '</section>'

    $daysBack = ji $C 'Meta.DaysBack'; if (-not $daysBack) { $daysBack = 30 }
    W "<section id=`"recent`"><h2>Recent installs (last $daysBack days)</h2>"
    $rows = New-RowList
    foreach ($x in $Res.RecentInstalls) { $rows.Add(@((Enc $x.Time), (Enc $x.Item), (Enc $x.Result), (Enc $x.Source), (Enc $x.Error))) }
    Write-Table @('Time', 'Item', 'Result', 'Source', 'Error') $rows 'No installs recorded in the window.'
    W '</section>'

    W '<section id="sc"><h2>Software Center</h2><h3>Deployed software updates</h3>'
    $rows = New-RowList
    foreach ($u in (ja $C 'Sccm.SoftwareCenterUpdates')) {
        $pc = js $u 'PercentComplete'
        $rows.Add(@((Enc ('KB' + (js $u 'ArticleID'))), (Enc (js $u 'Name')), (Enc (Get-EvalStateName (ji $u 'EvaluationState'))), (Enc (Get-ErrorText (js $u 'ErrorCode'))), (Enc (Fmt (jt $u 'Deadline'))), (Enc $(if ($pc) { "$pc%" } else { '' }))))
    }
    Write-Table @('KB', 'Name', 'State', 'Error', 'Deadline', 'Progress') $rows 'No software updates are deployed to this device in Software Center.'
    W '<h3>Applications</h3>'
    $rows = New-RowList
    foreach ($a in (ja $C 'Sccm.Applications' | Sort-Object { [string](js $_ 'LastInstallTime') } -Descending)) {
        $rows.Add(@((Enc (js $a 'Name')), (Enc (js $a 'SoftwareVersion')), (Enc (js $a 'InstallState')), (Enc (Fmt (jt $a 'LastInstallTime'))), (Enc (Get-ErrorText (js $a 'ErrorCode'))), (Enc $(if (jb $a 'IsMachineTarget') { 'Device' } else { 'User' }))))
    }
    Write-Table @('Name', 'Version', 'Install state', 'Last install', 'Error', 'Target') $rows 'No applications.'
    W '</section>'

    W '<section id="client"><h2>SCCM client</h2><div class="grid"><div>'
    $cacheText = $null; if (js $C 'Sccm.Cache.Location') { $cacheText = (js $C 'Sccm.Cache.Location') + ' - ' + (js $C 'Sccm.Cache.UsedMB') + ' of ' + (js $C 'Sccm.Cache.SizeMB') + ' MB used' }
    $evalText = $null; if (js $C 'Sccm.CcmEval.Summary') { $evalText = (js $C 'Sccm.CcmEval.Summary') + ' (' + (js $C 'Sccm.CcmEval.FileTime') + ')' }
    Write-KV @(
        , @('Installed', (js $C 'Sccm.Installed'))
        , @('CcmExec', ((js $C 'Sccm.ServiceState') + ' / ' + (js $C 'Sccm.ServiceStartMode')))
        , @('Client version', (js $C 'Sccm.ClientVersion'))
        , @('Client GUID', (js $C 'Sccm.ClientId'))
        , @('Site code', (js $C 'Sccm.SiteCode'))
        , @('Management point', (js $C 'Sccm.ManagementPoint'))
        , @('HTTPS state', (js $C 'Sccm.HttpsState'))
        , @('SUP (CCM_UpdateSource)', (js $C 'Sccm.UpdateSource.ContentLocation'))
        , @('SUP from WUAHandler.log', (js $C 'Sccm.WsusUrlFromLog'))
        , @('Last successful scan (logs)', (Fmt (jt $C 'Sccm.LastSuccessfulScan')))
        , @('Last scan failure (logs)', (Fmt (jt $C 'Sccm.LastScanFailure')))
        , @('Cache', $cacheText)
        , @('CCMEval', $evalText)
        , @('Intune enrolled', (js $C 'Sccm.CoManagement.IntuneEnrolled'))
        , @('Co-management flags', (js $C 'Sccm.CoManagement.CoManagementFlags'))
    )
    W '</div><div><h3>Maintenance windows (client)</h3>'
    $rows = New-RowList
    foreach ($w in (ja $C 'Sccm.ServiceWindows')) {
        $du = jl $w 'Duration'
        $rows.Add(@((Enc (Get-WindowTypeName (js $w 'Type'))), (Enc (Fmt (jt $w 'StartTime'))), (Enc (Fmt (jt $w 'EndTime'))), (Enc $(if ($null -ne $du) { [string][math]::Floor($du / 60) } else { '' }))))
    }
    Write-Table @('Type', 'Start', 'End', 'Duration (min)') $rows 'No maintenance windows - deployments can install at any time.'
    W '<h3>Client update scan (CCM_UpdateStatus)</h3>'
    $us = ja $C 'Sccm.UpdateStatus'
    $usSummary = @($us | Group-Object { $st = js $_ 'Status'; if ($st) { $st } else { '?' } } | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '
    W ("<p>$($us.Count) updates evaluated: " + (Enc $usSummary) + '</p></div></div>')

    W '<h3>Known failure signatures in CCM logs</h3>'
    $rows = New-RowList
    foreach ($s in (ja $C 'Sccm.LogSignatures' | Sort-Object { Get-SevRank (js $_ 'Severity') })) {
        $hits = js $s 'Hits'; if (-not $hits) { $hits = js $s 'Count' }
        $rows.Add(@((Badge (js $s 'Severity')), (Enc (js $s 'Title')), (Enc $hits), (Enc (Fmt (jt $s 'FirstSeen'))), (Enc (Fmt (jt $s 'LastSeen'))), (Enc (js $s 'LastLog')), ('<span class="mono">' + (Enc (js $s 'Sample')) + '</span>')))
    }
    Write-Table @('Severity', 'Signature', 'Hits', 'First', 'Last', 'Log', 'Latest line') $rows 'No known failure signatures matched.'
    W '<h3>CCMEval checks</h3>'
    $rows = New-RowList
    foreach ($k in (ja $C 'Sccm.CcmEval.Checks')) { $rows.Add(@((Enc (js $k 'Description')), (Enc (js $k 'Result')), (Enc (js $k 'ResultCode')))) }
    Write-Table @('Check', 'Result', 'Code') $rows 'CcmEvalReport.xml not found.'
    W '<h3>CCM log errors and warnings</h3>'
    $rows = New-RowList
    foreach ($l in (ja $C 'Sccm.LogsParsed')) { $rows.Add(@((Enc (js $l 'Log')), (Enc (js $l 'Entries')), (Enc (js $l 'Errors')), (Enc (js $l 'Warnings')))) }
    Write-Table @('Log', 'Entries', 'Errors', 'Warnings') $rows 'No CCM logs parsed.'
    foreach ($grp in (ja $C 'Sccm.LogEntries' | Group-Object { $lg = js $_ 'Log'; if ($lg) { $lg } else { '?' } } | Sort-Object Name)) {
        W ('<details><summary>' + (Enc $grp.Name) + ".log - $($grp.Count) entries</summary>")
        $rows = New-RowList
        foreach ($e in ($grp.Group | Sort-Object { [string](js $_ 'Time') } -Descending)) {
            $rows.Add(@((Enc (Fmt (jt $e 'Time'))), (Enc $(if ((js $e 'Type') -eq '3') { 'Error' } else { 'Warning' })), (Enc (js $e 'Component')), ('<span class="mono">' + (Enc (js $e 'Message')) + '</span>')))
        }
        Write-Table @('Time', 'Type', 'Component', 'Message') $rows $null
        W '</details>'
    }
    W '</section>'

    W '<section id="server"><h2>SCCM server view</h2>'
    if (-not $Res.Server) {
        $msg = $(if ($Res.ServerError) { "Not available: $($Res.ServerError)" } else { 'Not checked. Run the analyzer with -SiteServer <SMS Provider>.' })
        W ('<p class="muted">' + (Enc $msg) + '</p>')
    }
    else {
        $v = $Res.Server
        W ('<p>SMS Provider <b>' + (Enc $Res.ServerName) + '</b>, site ' + (Enc $Res.SiteCode) + ' (' + (Enc $Res.SiteVersion) + ')</p>')
        if ($v.Error) { W ('<p class="muted">Query error: ' + (Enc $v.Error) + '</p>') }
        W '<h3>Device records</h3>'
        $rows = New-RowList
        foreach ($x in $v.Records) { $rows.Add(@((Enc $x.ResourceId), (Enc $x.SMSUniqueIdentifier), (Enc $x.Client), (Enc $x.ClientVersion), (Enc $x.Active), (Enc $x.Obsolete), (Enc $x.Build), (Enc $x.LastLogon), (Enc $x.CreationDate))) }
        Write-Table @('ResourceId', 'GUID', 'Client', 'Client version', 'Active', 'Obsolete', 'Build', 'Last logon', 'Created') $rows 'No records.'
        if ($v.Combined) { W '<details><summary>Client status (SMS_CombinedDeviceResources)</summary>'; Write-DictTable $v.Combined ''; W '</details>' }
        $lsc = Fmt $v.LastStatusCheck; if (-not $lsc) { $lsc = 'never' }
        W ('<p>Last update scan result received: <b>' + (Enc $lsc) + "</b> &middot; $($v.ComplianceRows) compliance rows, $($v.InstalledCount) installed, $($v.Required.Count) required</p>")
        W '<h3>Latest cumulative update</h3>'
        $rows = New-RowList
        foreach ($mk in @($v.LatestMicrosoftKbInCatalog)) { if ($mk) { $rows.Add(@((Enc "Microsoft latest ($($Res.LatestKb))"), (Enc $mk.Title), (Enc (YesNo $mk.IsDeployed)), (Enc (YesNo $mk.DeployedToDevice)), (Enc (YesNo $mk.IsSuperseded)), (Enc (FmtDay $mk.DatePosted)))) } }
        if ($v.LatestCuInCatalog) { $cu = $v.LatestCuInCatalog; $rows.Add(@((Enc 'Newest in SCCM catalog'), (Enc $cu.Title), (Enc (YesNo $cu.IsDeployed)), (Enc (YesNo $cu.DeployedToDevice)), (Enc (YesNo $cu.IsSuperseded)), (Enc (FmtDay $cu.DatePosted)))) }
        $patText = $(if ($v.CuSearchPattern) { $v.CuSearchPattern } else { '(unknown)' })
        Write-Table @('', 'Update', 'Deployed', 'To this device', 'Superseded', 'Posted') $rows "No matching cumulative update found in the SCCM catalog for pattern: $patText"
        W '<h3>Required updates (site view)</h3>'
        $rows = New-RowList
        foreach ($u in ($v.Required | Sort-Object { if ($_.DeployedToDevice) { 0 } else { 1 } })) { $rows.Add(@((Enc "KB$($u.Article)"), (Enc $u.Title), (Enc (YesNo $u.DeployedToDevice)), (Enc (YesNo $u.IsDeployed)), (Enc (YesNo $u.IsSuperseded)), (Enc (Get-ErrorText $u.LastError)))) }
        Write-Table @('KB', 'Title', 'Deployed to device', 'Deployed anywhere', 'Superseded', 'Last error') $rows 'The site reports no required updates for this device.'
        W '<h3>Software update deployments to this device</h3>'
        $rows = New-RowList
        foreach ($d in $v.Deployments) { $rows.Add(@((Enc $d.Name), (Enc $d.Collection), (Enc $d.Purpose), (Enc $d.Enabled), (Enc $d.Start), (Enc $d.Deadline), (Enc $d.Updates), (Enc $d.OverrideMaintenanceWindow))) }
        Write-Table @('Deployment', 'Collection', 'Purpose', 'Enabled', 'Available', 'Deadline', 'Updates', 'Ignore MW') $rows "No software update deployments target this device's collections."
        W '<h3>Maintenance windows (collections)</h3>'
        $rows = New-RowList
        foreach ($w in $v.MaintenanceWindows) { $rows.Add(@((Enc $w.Collection), (Enc $w.Name), (Enc $w.Type), (Enc $w.Enabled), (Enc $w.Start), (Enc $w.DurationMin), (Enc $w.Description))) }
        Write-Table @('Collection', 'Name', 'Type', 'Enabled', 'Start', 'Duration (min)', 'Description') $rows "No maintenance windows on this device's collections."
        W ("<details><summary>Collection membership ($($v.Collections.Count))</summary><ul>")
        foreach ($col in ($v.Collections | Sort-Object Name)) { W ('<li>' + (Enc "$($col.Name) ($($col.Id))") + '</li>') }
        W '</ul></details>'
    }
    if ($Res.Wsus -or $Res.WsusError) {
        W '<h3>WSUS</h3>'
        if ($Res.Wsus) { Write-DictTable $Res.Wsus '' } else { W ('<p class="muted">' + (Enc $Res.WsusError) + '</p>') }
    }
    W '</section>'

    W '<section id="wu"><h2>Windows Update</h2><div class="grid"><div>'
    $sdText = $null; if (js $C 'WindowsUpdate.SoftwareDistributionSizeMB') { $sdText = (js $C 'WindowsUpdate.SoftwareDistributionSizeMB') + ' MB' }
    $rpText = $null; if ($null -ne (js $C 'WindowsUpdate.RegistryPol.HeaderOk')) { $rpText = $(if (jb $C 'WindowsUpdate.RegistryPol.HeaderOk') { 'OK' } else { 'CORRUPT header ' + (js $C 'WindowsUpdate.RegistryPol.Header') }) + ', ' + (js $C 'WindowsUpdate.RegistryPol.SizeBytes') + ' bytes' }
    $scanText = 'not run'; if (js $C 'WindowsUpdate.Scan.Mode') { $rc = js $C 'WindowsUpdate.Scan.ResultCode'; if (-not $rc) { $rc = js $C 'WindowsUpdate.Scan.Error' }; $scanText = (js $C 'WindowsUpdate.Scan.Mode') + " - $rc" }
    $dismText = $(if (jb $C 'WindowsUpdate.Dism.Ran') { js $C 'WindowsUpdate.Dism.Output' } else { 'not run' })
    Write-KV @(
        , @('Agent version', (js $C 'WindowsUpdate.AgentVersion'))
        , @('History entries', (js $C 'WindowsUpdate.HistoryTotal'))
        , @('SoftwareDistribution size', $sdText)
        , @('Registry.pol', $rpText)
        , @('Scan during collection', $scanText)
        , @('DISM CheckHealth', $dismText)
    )
    W '<h3>Services</h3>'
    $rows = New-RowList
    foreach ($s in (ja $C 'WindowsUpdate.Services')) { $rows.Add(@((Enc ((js $s 'DisplayName') + ' (' + (js $s 'Name') + ')')), (Enc (js $s 'State')), (Enc (js $s 'StartMode')), (Enc (js $s 'StartName')))) }
    Write-Table @('Service', 'State', 'Start mode', 'Account') $rows 'No service data.'
    W '</div><div><h3>Policy: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate</h3>'
    Write-DictTable (jdict $C 'WindowsUpdate.Policy') 'No WindowsUpdate policy key.'
    W '<h3>Policy: ...\WindowsUpdate\AU</h3>'
    Write-DictTable (jdict $C 'WindowsUpdate.PolicyAU') 'No AU policy key.'
    W '<details><summary>MDM update policy (PolicyManager)</summary>'
    Write-DictTable (jdict $C 'WindowsUpdate.MdmUpdatePolicy') 'None.'
    W '</details><details><summary>Registered update services</summary>'
    $rows = New-RowList
    foreach ($s in (ja $C 'WindowsUpdate.RegisteredServices')) { $rows.Add(@((Enc (js $s 'Name')), ('<span class="mono">' + (Enc (js $s 'ServiceID')) + '</span>'), (Enc (js $s 'IsDefaultAUService')), (Enc (js $s 'IsManaged')))) }
    Write-Table @('Name', 'ServiceID', 'Default AU', 'Managed') $rows 'None.'
    W '</details></div></div>'
    $histAll = ja $C 'WindowsUpdate.History'
    W "<details><summary>Windows Update history ($($histAll.Count) entries)</summary>"
    $rows = New-RowList
    foreach ($h in $histAll) { $rows.Add(@((Enc (Fmt (jt $h 'Date'))), (Enc (js $h 'Title')), (Enc (js $h 'Result')), (Enc (Get-ErrorText (js $h 'HResult'))), (Enc (js $h 'ClientApplicationID')))) }
    Write-Table @('Date', 'Title', 'Result', 'HResult', 'Client') $rows 'No history.'
    $hf = ja $C 'WindowsUpdate.HotFixes'
    W "</details><details><summary>Installed hotfixes ($($hf.Count))</summary>"
    $rows = New-RowList
    foreach ($h in ($hf | Sort-Object { [string](js $_ 'InstalledOn') } -Descending)) { $rows.Add(@((Enc (js $h 'HotFixID')), (Enc (js $h 'Description')), (Enc (FmtDay (jt $h 'InstalledOn'))), (Enc (js $h 'InstalledBy')))) }
    Write-Table @('HotFix', 'Description', 'Installed on', 'By') $rows 'None.'
    W '</details></section>'

    W '<section id="dotnet"><h2>.NET</h2>'
    Write-KV @(
        , @('.NET Framework 4.x', ((js $C 'DotNet.Framework.FriendlyVersion') + ' (release ' + (js $C 'DotNet.Framework.Release') + ', ' + (js $C 'DotNet.Framework.Version') + ')'))
        , @('.NET Framework 3.5', $(if (jb $C 'DotNet.Framework.Net35Installed') { 'Installed' } else { 'Not installed' }))
    )
    $rows = New-RowList
    foreach ($i in (ja $C 'DotNet.Installs')) { $rows.Add(@((Enc (js $i 'Kind')), (Enc (js $i 'Version')), (Enc (js $i 'Architecture')), ('<span class="mono">' + (Enc (js $i 'Path')) + '</span>'))) }
    Write-Table @('Kind', 'Version', 'Architecture', 'Path') $rows 'No .NET (Core/5+) runtimes or SDKs installed.'
    W '</section>'

    W '<section id="events"><h2>Event log highlights</h2><h3>Most frequent errors</h3>'
    $rows = New-RowList
    foreach ($g in $Res.EventGroups) { $rows.Add(@((Enc $g.Log), (Enc $g.Provider), (Enc $g.Id), (Enc $g.Count), (Enc $g.Last), ('<span class="small">' + (Enc $g.Sample) + '</span>'))) }
    Write-Table @('Log', 'Source', 'ID', 'Count', 'Last', 'Sample') $rows 'No error events in the window.'
    foreach ($grp in (ja $C 'Events' | Group-Object { $tg = js $_ 'Tag'; if ($tg) { $tg } else { '?' } } | Sort-Object Name)) {
        W ('<details><summary>' + (Enc $grp.Name) + " - $($grp.Count) events</summary>")
        $rows = New-RowList
        foreach ($e in ($grp.Group | Sort-Object { [string](js $_ 'Time') } -Descending | Select-Object -First 300)) {
            $ln = js $e 'LevelName'; if (-not $ln) { $ln = js $e 'Level' }
            $rows.Add(@((Enc (Fmt (jt $e 'Time'))), (Enc $ln), (Enc (js $e 'Provider')), (Enc (js $e 'Id')), ('<span class="small">' + (Enc (js $e 'Message')) + '</span>')))
        }
        Write-Table @('Time', 'Level', 'Source', 'ID', 'Message') $rows $null
        W '</details>'
    }
    W '<h3>Event logs queried</h3>'
    $rows = New-RowList
    foreach ($s in (ja $C 'EventLogStatus')) { $rows.Add(@((Enc (js $s 'Tag')), (Enc (js $s 'Log')), (Enc (js $s 'Count')), (Enc (js $s 'Error')))) }
    Write-Table @('Query', 'Log', 'Events', 'Error') $rows 'None.'
    W '</section>'

    W '<section id="system"><h2>System</h2><div class="grid"><div>'
    $pending = $(if (jb $C 'PendingReboot.Any') { @(ja $C 'PendingReboot.Reasons') -join ', ' } else { 'No' })
    $verText = js $C 'System.DisplayVersion'; if (-not $verText) { $verText = js $C 'System.ReleaseId' }
    $collector = (js $C 'Meta.CollectorVersion') + ' as ' + (js $C 'Meta.RunAsUser') + $(if (jb $C 'Meta.RunAsAdmin') { ' (elevated)' } else { ' (NOT elevated)' })
    Write-KV @(
        , @('Computer', (js $C 'System.ComputerName'))
        , @('FQDN', (js $C 'System.Fqdn'))
        , @('Domain', (js $C 'System.Domain'))
        , @('Model', ((js $C 'System.Manufacturer') + ' ' + (js $C 'System.Model')))
        , @('Serial', (js $C 'System.SerialNumber'))
        , @('BIOS', (js $C 'System.BiosVersion'))
        , @('OS', (js $C 'System.OSCaption'))
        , @('Edition', (js $C 'System.EditionID'))
        , @('Version', $verText)
        , @('Build', (js $C 'System.FullBuild'))
        , @('Architecture', ((js $C 'System.ProcessorArchitecture') + ' / ' + (js $C 'System.OSArchitecture')))
        , @('CPU', (js $C 'System.CpuName'))
        , @('Memory', ((js $C 'System.MemoryGB') + ' GB'))
        , @('System drive', ((js $C 'System.SystemDrive') + ' ' + (js $C 'System.SystemDriveFreeGB') + ' GB free of ' + (js $C 'System.SystemDriveSizeGB') + ' GB'))
        , @('Installed', (Fmt (jt $C 'System.InstallDate')))
        , @('Last boot', (Fmt (jt $C 'System.LastBootTime')))
        , @('Uptime (days)', (js $C 'System.UptimeDays'))
        , @('Pending restart', $pending)
        , @('Time source', (js $C 'TimeSync.Source'))
        , @('Secure Boot', (js $C 'SecureBoot.Enabled'))
        , @('Secure Boot 2023 CA status', (js $C 'SecureBoot.Servicing.UEFICA2023Status'))
        , @('Collector', $collector)
    )
    W '</div><div><h3>Network</h3>'
    $rows = New-RowList
    foreach ($a in (ja $C 'Network.Adapters')) { $rows.Add(@((Enc (js $a 'Description')), (Enc (js $a 'IPAddress')), (Enc (js $a 'Gateway')), (Enc (js $a 'DnsServers')))) }
    Write-Table @('Adapter', 'IP', 'Gateway', 'DNS') $rows 'No adapters.'
    W ('<p class="small mono">' + (Enc (js $C 'Network.WinHttpProxy')) + '</p>')
    W '<h3>Connectivity tests (from the device)</h3>'
    $rows = New-RowList
    foreach ($t in (ja $C 'Network.Connectivity')) { $rows.Add(@((Enc (js $t 'Purpose')), (Enc ((js $t 'Host') + ':' + (js $t 'Port'))), (Enc $(if (jb $t 'DnsOk') { 'OK' } else { 'FAIL' })), (Enc $(if (jb $t 'TcpOk') { 'OK' } else { 'FAIL' })), (Enc (js $t 'Http')), (Enc (js $t 'Error')))) }
    Write-Table @('Purpose', 'Target', 'DNS', 'TCP', 'HTTP', 'Error') $rows 'Connectivity tests were skipped.'
    W '</div></div>'
    $secErr = ja $C 'Meta.SectionErrors'
    if ($secErr.Count -gt 0) {
        W "<details><summary>Collector section errors ($($secErr.Count))</summary>"
        $rows = New-RowList
        foreach ($e in $secErr) { $rows.Add(@((Enc (js $e 'Section')), (Enc (js $e 'Error')))) }
        Write-Table @('Section', 'Error') $rows $null
        W '</details>'
    }
    W '</section>'

    W '<section id="sources"><h2>Data sources</h2>'
    $smsText = $(if ($Res.ServerName) { "$($Res.ServerName) site $($Res.SiteCode)" } else { 'not used' })
    $wsusText = $(if ($Res.Wsus) { $Res.Wsus.Server } elseif ($Res.WsusError) { $Res.WsusError } else { 'not used' })
    Write-KV @(
        , @('Windows 11 release information', (Get-SourceText 'windows11-release-information.html'))
        , @('Windows 10 release information', (Get-SourceText 'windows10-release-information.html'))
        , @('.NET releases index', (Get-SourceText 'dotnet-releases-index.json'))
        , @('SCCM SMS Provider', $smsText)
        , @('WSUS', $wsusText)
        , @('Bundle', $Res.BundlePath)
        , @('Analyzer', "PowerShell $AnalyzerVersion")
    )
    W ('<p class="small muted">Microsoft pages: ' + (Enc $Win11Url) + ' and ' + (Enc $Win10Url) + '</p></section>')
    W '</main></body></html>'
    return $script:SB.ToString()
}

function Build-Index($Results, [string]$Root) {
    $script:SB = New-Object System.Text.StringBuilder
    W ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Update Health Summary</title><style>' + $Css + '</style></head><body>')
    W ("<header><h1>Update Health Summary</h1><div class=`"sub`">$($Results.Count) devices &middot; " + (Enc (Fmt (Get-Date))) + '</div></header><main><section>')
    $rows = New-RowList
    foreach ($x in ($Results | Sort-Object @{ Expression = { if ((Get-SevCount $_ 'Critical') -gt 0) { 0 } else { 1 } } }, @{ Expression = { Get-SevCount $_ 'High' }; Descending = $true })) {
        $top = $x.Findings | Select-Object -First 1
        $rel = $x.ReportPath
        if ($rel -and $rel.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { $rel = $rel.Substring($Root.Length).TrimStart('\', '/').Replace('\', '/') }
        $crit = Get-SevCount $x 'Critical'; $high = Get-SevCount $x 'High'
        $rows.Add(@((Enc $x.ComputerName), (Enc (Fmt $x.CollectedAt)), (Enc $x.FullBuild),
                $(if ($crit -gt 0) { (Badge 'Critical') + " $crit" } else { '0' }), $(if ($high -gt 0) { (Badge 'High') + " $high" } else { '0' }),
                [string](Get-SevCount $x 'Medium'), $(if ($top) { Enc $top.Title } else { '' }), ('<a href="' + (Enc $rel) + '">open</a>')))
    }
    Write-Table @('Computer', 'Collected', 'Build', 'Critical', 'High', 'Medium', 'Top finding', 'Report') $rows 'No results.'
    W '</section></main></body></html>'
    return $script:SB.ToString()
}

#endregion

#region JSON output -------------------------------------------------------------------------

function ConvertTo-Plain($o) {
    # Converts report objects into Dictionary/List graphs for JavaScriptSerializer.
    if ($null -eq $o) { return $null }
    if ($o -is [string] -or $o -is [ValueType]) { if ($o -is [datetime]) { return (Fmt $o) }; return $o }
    if ($o -is [System.Collections.IDictionary]) {
        $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        foreach ($k in $o.Keys) { $d[[string]$k] = ConvertTo-Plain $o[$k] }
        return ,$d
    }
    if ($o -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($x in $o) { $l.Add((ConvertTo-Plain $x)) }
        return ,$l
    }
    if ($o -is [psobject]) {
        $d = New-Object 'System.Collections.Generic.Dictionary[string,object]'
        foreach ($p in $o.PSObject.Properties) { $d[$p.Name] = ConvertTo-Plain $p.Value }
        return ,$d
    }
    return [string]$o
}

function Export-AnalysisJson($Res, [string]$Path) {
    $summary = [ordered]@{}
    foreach ($s in @('Critical', 'High', 'Medium', 'Low', 'Info')) { $summary[$s] = Get-SevCount $Res $s }
    $doc = [ordered]@{
        ComputerName = $Res.ComputerName; CollectedAt = (Fmt $Res.CollectedAt); AnalyzedAt = (Fmt (Get-Date)); AnalyzerVersion = "PowerShell $AnalyzerVersion"
        Summary = $summary; Updates = $Res.Updates; Findings = $Res.Findings; MissingUpdates = $Res.Missing; RecentInstalls = $Res.RecentInstalls; Notes = $Res.Notes
        MicrosoftData = [ordered]@{
            WindowsVersions = $script:WinVersions.Count; WindowsReleaseBuilds = @($script:WinReleases.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
            DotNetChannels = $script:DotNetChannels.Count
        }
    }
    if ($Res.Server) {
        $v = $Res.Server
        $doc.SccmServer = [ordered]@{
            Server = $Res.ServerName; SiteCode = $Res.SiteCode; ResourceId = $v.ResourceId; Records = $v.Records.Count
            Collections = @($v.Collections | ForEach-Object { $_.Name }); Deployments = $v.Deployments; MaintenanceWindows = $v.MaintenanceWindows
            LastStatusCheck = (Fmt $v.LastStatusCheck); Combined = $v.Combined
            RequiredUpdates = @($v.Required | ForEach-Object { [ordered]@{ KB = "KB$($_.Article)"; Title = $_.Title; DeployedToDevice = $_.DeployedToDevice; IsDeployed = $_.IsDeployed; LastError = $_.LastError } })
            Error = $v.Error
        }
    }
    if ($Res.Wsus) { $doc.Wsus = $Res.Wsus }
    $json = ConvertTo-Json -InputObject (ConvertTo-Plain $doc) -Depth 12
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

#endregion

#region Main --------------------------------------------------------------------------------

Write-Host "UpdateHealthKit analyzer (PowerShell) $AnalyzerVersion" -ForegroundColor Green
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).Path 'UpdateHealthReports' }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath

# Resolve bundles
$bundles = New-Object System.Collections.Generic.List[string]
function Expand-BundleZip([string]$Zip) {
    try {
        $dest = Join-Path (Join-Path $OutputPath '_extracted') ([IO.Path]::GetFileNameWithoutExtension($Zip))
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Zip, $dest)
        $found = @(Get-ChildItem -LiteralPath $dest -Filter 'collection.json' -Recurse -File)
        if ($found.Count -eq 0) { Write-Warning "No collection.json inside $Zip"; return $null }
        return $found[0].FullName
    }
    catch { Write-Warning "Could not extract ${Zip}: $($_.Exception.Message)"; return $null }
}
foreach ($raw in $InputPath) {
    $p = $null
    try { $p = (Resolve-Path -LiteralPath $raw -ErrorAction Stop).ProviderPath } catch { Write-Warning "Not found: $raw"; continue }
    if (Test-Path -LiteralPath $p -PathType Leaf) {
        if ($p -like '*.zip') { $j = Expand-BundleZip $p; if ($j) { $bundles.Add($j) } }
        elseif ((Split-Path $p -Leaf) -eq 'collection.json') { $bundles.Add($p) }
        else { Write-Warning "Unsupported file (expected .zip or collection.json): $p" }
    }
    else {
        $direct = Join-Path $p 'collection.json'
        if (Test-Path -LiteralPath $direct) { $bundles.Add($direct); continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $p -Filter 'collection.json' -Recurse -File -ErrorAction SilentlyContinue)) {
            if ($f.FullName -notlike '*\_extracted\*') { $bundles.Add($f.FullName) }
        }
        foreach ($z in @(Get-ChildItem -LiteralPath $p -Filter '*.zip' -File -ErrorAction SilentlyContinue)) {
            $sibling = Join-Path $z.DirectoryName $z.BaseName
            if (Test-Path -LiteralPath (Join-Path $sibling 'collection.json')) { continue }
            $j = Expand-BundleZip $z.FullName; if ($j) { $bundles.Add($j) }
        }
    }
}
$bundles = @($bundles | Select-Object -Unique)
if ($bundles.Count -eq 0) { Write-Error 'No collection.json found in the given input(s).'; exit 1 }
Write-Host "Bundles to analyze: $($bundles.Count)"

# Microsoft reference data
if ($Offline) { Write-Host 'Offline mode: using cached Microsoft data only.' } else { Write-Host 'Downloading Microsoft release data...' }
Read-WindowsReleaseHtml (Get-CachedText 'windows11-release-information.html' @($Win11Url))
Read-WindowsReleaseHtml (Get-CachedText 'windows10-release-information.html' @($Win10Url))
Read-DotNetIndex
Write-Host ("  Windows versions: {0}, release builds: {1}, .NET channels: {2}" -f $script:WinVersions.Count,
    (@($script:WinReleases.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum), $script:DotNetChannels.Count)

if ($SiteServer) {
    Write-Host "Connecting to SMS Provider $SiteServer..."
    Connect-SmsProvider $SiteServer $SiteCode
    if ($script:Sms.Connected) { Write-Host "  Connected to site $($script:Sms.SiteCode) (version $($script:Sms.SiteVersion))" }
    else { Write-Warning "Could not connect: $($script:Sms.Error)" }
}

$results = New-Object System.Collections.Generic.List[object]
$failures = 0
foreach ($bundle in $bundles) {
    try {
        Write-Host ''
        Write-Host "Analyzing $bundle"
        $data = ConvertFrom-JsonText ([System.IO.File]::ReadAllText($bundle))
        $res = Invoke-Analysis $data
        $res.BundlePath = $bundle
        $stamp = $(if ($res.CollectedAt) { $res.CollectedAt.ToString('yyyyMMdd-HHmmss', $Inv) } else { 'nodate' })
        $safeName = [string]$res.ComputerName; if (-not $safeName) { $safeName = 'UNKNOWN' }
        foreach ($bad in [IO.Path]::GetInvalidFileNameChars()) { $safeName = $safeName.Replace([string]$bad, '_') }
        $dir = Join-Path $OutputPath "${safeName}_$stamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $html = Join-Path $dir 'UpdateHealthReport.html'
        $json = Join-Path $dir 'analysis.json'
        [System.IO.File]::WriteAllText($html, (Build-Report $res), (New-Object System.Text.UTF8Encoding($false)))
        Export-AnalysisJson $res $json
        $res.ReportPath = $html
        $res | Add-Member -NotePropertyName FullBuild -NotePropertyValue (js $data 'System.FullBuild') -Force
        $results.Add($res)
        Write-Host ("  {0}: Critical {1}, High {2}, Medium {3}, Low {4}" -f $res.ComputerName, (Get-SevCount $res 'Critical'), (Get-SevCount $res 'High'), (Get-SevCount $res 'Medium'), (Get-SevCount $res 'Low'))
        foreach ($f in ($res.Findings | Where-Object { (Get-SevRank $_.Severity) -le 1 } | Select-Object -First 8)) { Write-Host "    [$($f.Severity)] $($f.Title)" }
        foreach ($f in ($res.Findings | Where-Object { $_.Area -eq 'Analyzer' })) { Write-Warning "$($f.Title): $($f.Detail)" }
        Write-Host "  Report: $html"
    }
    catch {
        $failures++
        Write-Warning "ERROR analyzing ${bundle}: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    }
}

if ($results.Count -gt 1) {
    $index = Join-Path $OutputPath 'index.html'
    [System.IO.File]::WriteAllText($index, (Build-Index $results $OutputPath), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ''
    Write-Host "Summary: $index"
    if ($Open) { Start-Process $index }
}
elseif ($results.Count -eq 1 -and $Open) { Start-Process $results[0].ReportPath }

foreach ($n in $script:CacheNotes) { Write-Host "NOTE: $n" }
if ($failures -gt 0) { exit 1 }

#endregion

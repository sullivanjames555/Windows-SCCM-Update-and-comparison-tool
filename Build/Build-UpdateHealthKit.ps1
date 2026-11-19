#Requires -Version 5.1
<#
.SYNOPSIS
    Compiles UpdateHealthAnalyzer.exe with the C# compiler built into .NET Framework 4.8 and
    Authenticode-signs the analyzer and the collector script.

.DESCRIPTION
    No Visual Studio or SDK needed: uses %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe.
    Signing picks the newest valid code-signing certificate (with private key) in
    Cert:\CurrentUser\My unless -Thumbprint is given. Re-run after editing any file, because
    editing a signed script invalidates its signature.

.PARAMETER Thumbprint
    Thumbprint of the code-signing certificate to use (CurrentUser\My or LocalMachine\My).
.PARAMETER TimestampServer
    RFC 3161 / Authenticode timestamp URL. Default http://timestamp.digicert.com.
    If it can't be reached the files are signed without a timestamp (signature then stops
    validating when the certificate expires).
.PARAMETER SkipSign
    Compile only.
.PARAMETER CscPath
    Use a different csc.exe (e.g. Roslyn from Visual Studio Build Tools).

.EXAMPLE
    .\Build-UpdateHealthKit.ps1
.EXAMPLE
    .\Build-UpdateHealthKit.ps1 -Thumbprint 1A2B3C... -TimestampServer http://timestamp.sectigo.com
#>
[CmdletBinding()]
param(
    [string]$Thumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$SkipSign,
    [string]$CscPath
)

$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $PSScriptRoot
$srcDir    = Join-Path $root 'Analyzer\src'
$outExe    = Join-Path $root 'Analyzer\UpdateHealthAnalyzer.exe'
$collector = Join-Path $root 'Collector\Invoke-UpdateHealthCollector.ps1'

# ---- Compile -------------------------------------------------------------------------------
$csc = $CscPath
if (-not $csc) {
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $csc)) { $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
}
if (-not (Test-Path -LiteralPath $csc)) { throw "csc.exe not found ($csc). .NET Framework 4.8 is required." }

$sources = @(Get-ChildItem -LiteralPath $srcDir -Filter '*.cs' | ForEach-Object { $_.FullName })
if ($sources.Count -eq 0) { throw "No .cs files found in $srcDir" }

$refs = @('System.dll', 'System.Core.dll', 'System.Management.dll', 'System.Web.Extensions.dll',
          'System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll')
$cscArgs = @('/nologo', '/target:exe', '/optimize+', '/platform:anycpu', '/warn:3', "/out:$outExe") +
           @($refs | ForEach-Object { "/reference:$_" }) + $sources

Write-Host "Compiling $($sources.Count) source files with $csc" -ForegroundColor Cyan
& $csc @cscArgs
if ($LASTEXITCODE -ne 0) { throw "Compilation failed (exit code $LASTEXITCODE). See the errors above." }
Write-Host "Built $outExe" -ForegroundColor Green

if ($SkipSign) { Write-Host 'Skipping signing (-SkipSign).'; return }

# ---- Sign ----------------------------------------------------------------------------------
$cert = $null
if ($Thumbprint) {
    $tp = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My' |
        Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1
}
else {
    $cert = Get-ChildItem -Path 'Cert:\CurrentUser\My' -CodeSigningCert |
        Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}
if (-not $cert) { throw 'No valid code-signing certificate found. Pass -Thumbprint, or use -SkipSign to compile only.' }
Write-Host ("Signing with {0} (thumbprint {1}, expires {2:yyyy-MM-dd})" -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter) -ForegroundColor Cyan

$toSign = @($outExe, $collector, $MyInvocation.MyCommand.Path)
foreach ($file in $toSign) {
    $sig = $null
    try {
        $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop
    }
    catch { $sig = $null }
    if (-not $sig -or $sig.Status -ne 'Valid') {
        Write-Warning "Timestamped signing failed for $(Split-Path $file -Leaf); signing without a timestamp."
        $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256
    }
    Write-Host ("  {0,-40} {1}" -f (Split-Path $file -Leaf), $sig.Status)
}

Write-Host ''
Write-Host 'Done. Copy Collector\Invoke-UpdateHealthCollector.ps1 to the problem PC (USB is fine) and keep' -ForegroundColor Green
Write-Host 'Analyzer\UpdateHealthAnalyzer.exe on your online admin PC.' -ForegroundColor Green

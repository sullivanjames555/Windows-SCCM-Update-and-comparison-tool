#Requires -Version 5.1
<#
.SYNOPSIS
    Authenticode-signs the UpdateHealthKit scripts (collector, analyzer and this script) so they
    run under AppLocker / AllSigned execution policy.

.DESCRIPTION
    Uses the newest valid code-signing certificate (with private key) in Cert:\CurrentUser\My,
    or the one given by -Thumbprint, with SHA-256 and a timestamp. Run it on a PC with internet so
    the timestamp server is reachable; a timestamped signature stays valid after the certificate
    expires. Re-run it after editing any script, because an edit invalidates the signature.

    List your code-signing certificates with:
        Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object Thumbprint, Subject, NotAfter

.PARAMETER Thumbprint
    Thumbprint of the code-signing certificate to use (CurrentUser\My or LocalMachine\My).
.PARAMETER TimestampServer
    Authenticode timestamp URL. Default http://timestamp.digicert.com. If it can't be reached the
    files are signed without a timestamp (the signature then stops validating when the
    certificate expires) and a warning is shown.
.PARAMETER SignOnly
    Accepted for compatibility with older instructions; signing is all this script does.

.EXAMPLE
    .\Build\Build-UpdateHealthKit.ps1

    Signs both scripts with your newest code-signing certificate.

.EXAMPLE
    .\Build\Build-UpdateHealthKit.ps1 -Thumbprint 1A2B3C4D5E6F...

    Signs with a specific certificate.
#>
[CmdletBinding()]
param(
    [string]$Thumbprint,
    [string]$TimestampServer = 'http://timestamp.digicert.com',
    [switch]$SignOnly
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$toSign = @(
    (Join-Path $root 'Collector\Invoke-UpdateHealthCollector.ps1'),
    (Join-Path $root 'Analyzer\Invoke-UpdateHealthAnalyzer.ps1'),
    $PSCommandPath
) | Where-Object { Test-Path -LiteralPath $_ }

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
if (-not $cert) { throw 'No valid code-signing certificate found. Pass -Thumbprint (see Get-Help .\Build\Build-UpdateHealthKit.ps1).' }
Write-Host ("Signing with {0} (thumbprint {1}, expires {2:yyyy-MM-dd})" -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter) -ForegroundColor Cyan

foreach ($file in $toSign) {
    $sig = $null
    try { $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop }
    catch { $sig = $null }
    if (-not $sig -or $sig.Status -ne 'Valid') {
        Write-Warning "Timestamped signing failed for $(Split-Path $file -Leaf); signing without a timestamp."
        $sig = Set-AuthenticodeSignature -FilePath $file -Certificate $cert -HashAlgorithm SHA256
    }
    Write-Host ("  {0,-40} {1}" -f (Split-Path $file -Leaf), $sig.Status)
}

Write-Host ''
Write-Host 'Done. Copy the folder to the problem PC (USB is fine) and run Collector\Invoke-UpdateHealthCollector.ps1 as Administrator.' -ForegroundColor Green

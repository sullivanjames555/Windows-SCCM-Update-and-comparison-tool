# UpdateHealthKit

Finds out why a Windows 10/11 PC isn't getting updates from Software Center / SCCM, and what on it needs updating.

It has two parts, both plain PowerShell 5.1 scripts, so nothing has to be compiled and AppLocker treats them like any other signed script:

| Part | Runs on | Needs network? | What it does |
|---|---|---|---|
| `Collector\Invoke-UpdateHealthCollector.ps1` | The problem PC | No | Collects system, .NET, Windows Update, SCCM client, CCM logs and event logs into a zip |
| `Analyzer\Invoke-UpdateHealthAnalyzer.ps1` | Your online admin PC | Yes (it can also use a cache) | Compares the zip with Microsoft's latest Windows/.NET releases and your SCCM site (plus WSUS if you want), then writes an HTML + JSON report |

An optional C# build of the analyzer (`UpdateHealthAnalyzer.exe`) does the same job for places where executables are allowed; skip it if they aren't.

```
Build\Build-UpdateHealthKit.ps1             sign the scripts (and optionally compile the .exe)
Collector\Invoke-UpdateHealthCollector.ps1
Analyzer\Invoke-UpdateHealthAnalyzer.ps1     the analyzer
Analyzer\src\*.cs                            optional C# analyzer source
```

Every push is tested on a Windows machine by GitHub Actions: the collector runs for real, then both analyzers process its output (plus a copy made to look like a Windows 11 client) and the build fails on any error. Sample reports from that run are attached to each Actions run as `e2e-sample-reports`.

## Download

A ready-to-use zip with both scripts, the optional .exe, the build script and this README is on the [Latest build release](../../releases/tag/latest). GitHub Actions rebuilds it on every push to `main`. The files are **unsigned**, so sign them before using them under AppLocker:

```powershell
# in the extracted folder (right-click the zip > Properties > Unblock first)
Set-ExecutionPolicy -Scope Process Bypass
.\Build\Build-UpdateHealthKit.ps1 -SignOnly        # or -SignOnly -Thumbprint <thumb>
```

Pushing a tag such as `v1.0.0` also creates a versioned release.

## 1. Sign (and optionally build)

```powershell
.\Build\Build-UpdateHealthKit.ps1 -SignOnly                     # sign the scripts only (no .exe needed)
.\Build\Build-UpdateHealthKit.ps1 -SignOnly -Thumbprint <thumb>
.\Build\Build-UpdateHealthKit.ps1                               # also compile UpdateHealthAnalyzer.exe, then sign
```

Signing uses the newest valid code-signing certificate in `CurrentUser\My` (or `-Thumbprint`), SHA-256 and a timestamp. Sign on a PC with internet so the timestamp server is reachable. **Re-sign after you edit any file**, because an edit breaks the signature.

AppLocker: a publisher rule for your signing certificate covers everything. Signed scripts that are allowed by policy run in FullLanguage mode, which both scripts need (COM for the Windows Update Agent, WMI, .NET classes).

## 2. Collect (on the problem PC; works offline)

Run it from an **elevated** Windows PowerShell:

```powershell
.\Invoke-UpdateHealthCollector.ps1                          # defaults: last 30 days
.\Invoke-UpdateHealthCollector.ps1 -Days 60 -RunDismCheck
.\Invoke-UpdateHealthCollector.ps1 -ScanCabPath E:\wsusscn2.cab   # true offline scan for missing security updates
.\Invoke-UpdateHealthCollector.ps1 -OnlineScan              # WUA scan against the SUP (if reachable)
```

Output goes to `UpdateHealth_<PC>_<timestamp>\` next to the script (or `%TEMP%` if that location is read-only), and to a `.zip` of that folder. Other options: `-OutputPath`, `-IncludeWindowsUpdateLog`, `-SkipRawLogs`, `-SkipConnectivityTests`, `-NoZip`.

The collector only reads. The one exception: with `-ScanCabPath` it registers a temporary offline scan service and removes it when the scan finishes.

**What it collects**
- **System:** OS, edition, version and build.UBR, architecture (x64/ARM64/x86), model, BIOS, disk space, uptime, pending restart (CBS, WU, file renames, CCM), time sync, proxy, Secure Boot certificate status
- **.NET:** Framework 4.x release, 3.5, plus every .NET Runtime, ASP.NET Core, Desktop Runtime and SDK (x64, x86, and x64-on-ARM64)
- **Windows Update:** agent version, related services, WSUS/WUfB/MDM policies, Registry.pol health, hotfixes, the full WUA history (including which installs came from CcmExec, i.e. Software Center), an optional WUA scan, SoftwareDistribution size, optional DISM CheckHealth
- **SCCM client:** version, GUID, site, MP, SUP (CCM_UpdateSource), Software Updates client settings, cache, the client's own scan results (CCM_UpdateStatus), Software Center updates and apps with state and errors, maintenance windows, CCMEval, co-management
- **CCM logs:** about 27 logs parsed for errors, warnings and known failure signatures (scan failures, GPO conflict, WUA source errors, content/DP problems, MP communication, certificates, registration, maintenance windows, AppLocker blocks, WMI). Raw copies are included along with ccmsetup.log, CBS.log and dism.log.
- **Event logs:** System, Application, Setup, WindowsUpdateClient, BITS, MDM, AppLocker and CodeIntegrity
- **Connectivity:** DNS/TCP/HTTP tests to the SUP (`/ClientWebService/client.asmx`) and the MP (`/sms_mp/.sms_aut?mplist`). When the PC is offline these fail fast and are labelled as such.

## 3. Analyze (on an online PC)

```powershell
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath E:\UpdateHealth_PC123_20261119-101500.zip -SiteServer CM01 -Open
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath \\share\bundles -SiteServer CM01        # many bundles -> index.html
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath bundle.zip -SiteServer CM01 -WsusServer SUP01 -WsusPort 8530
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath bundle.zip -Offline                      # use cached Microsoft data
```

The optional exe takes the same options with `-Input` instead of `-InputPath` (`UpdateHealthAnalyzer.exe -Input bundle.zip -SiteServer CM01`).

Reports are written to `.\UpdateHealthReports\<PC>_<timestamp>\UpdateHealthReport.html` and `analysis.json`.

**What it compares against**
- **Microsoft Windows release health pages (Windows 11 and Windows 10):** the latest monthly security (B) build and KB for the device's OS build, how many monthly updates the device is behind, out-of-band releases, and end-of-servicing dates for the device's edition. Hotpatch calendars are ignored.
- **Microsoft .NET release metadata:** for each installed runtime or SDK, the latest patch in its channel (SDKs are compared within their feature band), the number of security releases and CVEs it has missed, and whether the channel is end-of-life.
- **SCCM SMS Provider (WMI, as your account):**
  - device records (duplicates, GUID mismatch, obsolete, blocked, approval)
  - client activity and last policy request
  - collection membership, software update deployments and maintenance windows
  - the site's per-update compliance (required vs. installed, deployed vs. not deployed, and the last scan result received)
  - whether Microsoft's latest CU is in the SCCM catalog, is deployed, and is deployed to this device
  - client version vs. site version
- **WSUS (optional):** the device's last report/sync time and its install summary. This needs the WSUS console (RSAT "Windows Server Update Services Tools") on the analyzer PC.

Microsoft data is cached in `Analyzer\cache` (refreshed after 12 hours; change with `-CacheHours`), so later runs work with `-Offline`. To analyze on a PC with no internet, run the analyzer once on an online PC and copy the `cache` folder across with it.

**Permissions:** a ConfigMgr role with read access to devices, collections, deployments and software updates (Read-only Analyst works), plus DCOM/WMI access to the SMS Provider (the analyzer uses `Get-WmiObject` over DCOM, not WinRM).

## The report

1. **What needs to be updated:** Windows feature version, the Windows CU (installed vs. latest), the .NET Framework, every .NET runtime/SDK, and the SCCM client
2. **Findings:** ranked Critical to Low, each with a detail line and a recommended fix
3. **Missing updates**, merged from the WUA scan, the SCCM client scan, Software Center and the site
4. **Recent installs**, merged from WUA history (Software Center vs. Windows Update), Software Center apps, MSI events and servicing events
5. Software Center, SCCM client (signatures, CCMEval, log errors), SCCM server view, Windows Update, .NET, event highlights, system/network, and data sources

## Notes and limits

- Ages such as "last scan 9 days ago" are measured from when the bundle was **collected**. "Latest version" uses today's Microsoft data.
- The Windows CU check relies on Microsoft's release-information page layout. If Microsoft changes it, the report says the data was unavailable rather than guessing.
- Windows Server isn't covered by the Microsoft comparison. The SCCM and log checks still work for it.
- For a device on hotpatch, the build number may not match the monthly B build exactly. Check the hotpatch calendar.

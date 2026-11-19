# UpdateHealthKit

Finds out why a Windows 10/11 PC isn't getting updates from Software Center / SCCM, and what on it needs updating.

It has two parts:

| Part | Runs on | Needs network? | What it does |
|---|---|---|---|
| `Collector\Invoke-UpdateHealthCollector.ps1` (PowerShell 5.1) | The problem PC | No | Collects system, .NET, Windows Update, SCCM client, CCM logs and event logs into a zip |
| `Analyzer\UpdateHealthAnalyzer.exe` (C#, .NET Framework 4.8) | Your online admin PC | Yes (it can also use a cache) | Compares the zip with Microsoft's latest Windows/.NET releases and your SCCM site (plus WSUS if you want), then writes an HTML + JSON report |

```
UpdateHealthKit\
  Build\Build-UpdateHealthKit.ps1      compile + sign
  Collector\Invoke-UpdateHealthCollector.ps1
  Analyzer\src\*.cs                     analyzer source (C# 5, no Visual Studio needed)
  Analyzer\UpdateHealthAnalyzer.exe     created by the build
```

## 1. Build and sign (once, on your admin PC)

```powershell
cd UpdateHealthKit\Build
.\Build-UpdateHealthKit.ps1                       # newest code-signing cert in CurrentUser\My
.\Build-UpdateHealthKit.ps1 -Thumbprint <thumb>   # or pick a cert
.\Build-UpdateHealthKit.ps1 -SkipSign             # compile only
```

The build uses `csc.exe`, which comes with .NET Framework 4.8 (`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319`). It signs the exe, the collector and the build script with SHA-256 and a timestamp. **Re-run the build after you edit any file**, because an edit breaks the signature.

AppLocker: a publisher rule for your signing certificate covers both files. Signed scripts that are allowed by policy run in FullLanguage mode, which the collector needs for COM (Windows Update Agent) and WMI.

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
UpdateHealthAnalyzer.exe -Input E:\UpdateHealth_PC123_20261119-101500.zip -SiteServer CM01 -Open
UpdateHealthAnalyzer.exe -Input \\share\bundles -SiteServer CM01            # many bundles -> index.html
UpdateHealthAnalyzer.exe -Input bundle.zip -SiteServer CM01 -WsusServer SUP01 -WsusPort 8530
UpdateHealthAnalyzer.exe -Input bundle.zip -Offline                          # use cached Microsoft data
```

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

Microsoft data is cached in `.\cache` next to the exe (refreshed after 12 hours; change with `-CacheHours`), so later runs work with `-Offline`.

**Permissions:** a ConfigMgr role with read access to devices, collections, deployments and software updates (Read-only Analyst works), plus DCOM/WMI access to the SMS Provider.

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

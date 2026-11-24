# UpdateHealthKit

Finds out why a Windows 10/11 PC isn't getting updates from Software Center / SCCM, and what on it needs updating.

It has two parts, both plain Windows PowerShell 5.1 scripts. Nothing has to be compiled, and AppLocker treats them like any other signed script.

| Part | Runs on | Needs network? | What it does |
|---|---|---|---|
| `Collector\Invoke-UpdateHealthCollector.ps1` | The problem PC | No | Collects system, .NET, Windows Update, SCCM client, CCM logs and event logs into a zip |
| `Analyzer\Invoke-UpdateHealthAnalyzer.ps1` | An admin PC with internet and SCCM access | Yes (it can also use a cache) | Compares that zip with Microsoft's latest Windows/.NET releases and your SCCM site (plus WSUS if you want), then writes an HTML + JSON report |

```
Build\Build-UpdateHealthKit.ps1             sign the scripts (and optionally compile the .exe)
Collector\Invoke-UpdateHealthCollector.ps1  the collector
Analyzer\Invoke-UpdateHealthAnalyzer.ps1    the analyzer
Analyzer\UpdateHealthAnalyzer.exe           optional C# build of the analyzer (release zip only)
Analyzer\src\*.cs                           source for the optional .exe
```

You don't need the .exe. It does the same job as the analyzer script for environments that allow executables.

---

## Quick start

### Step 1. Download and sign (admin PC with internet)

1. Download **UpdateHealthKit.zip** from the [Latest build release](../../releases/tag/latest).
2. Right-click the zip → **Properties** → tick **Unblock** → **OK**. Then extract it, for example to `C:\Tools\UpdateHealthKit`.
3. Open **Windows PowerShell** in that folder and sign the scripts with your code-signing certificate:

   ```powershell
   cd C:\Tools\UpdateHealthKit
   Set-ExecutionPolicy -Scope Process Bypass          # this window only
   .\Build\Build-UpdateHealthKit.ps1 -SignOnly
   ```

   Do this on a PC with internet. The signature then gets a timestamp, which keeps it valid after your certificate expires. To pick a specific certificate, add `-Thumbprint <thumbprint>`. List your certificates with `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert`.

### Step 2. Copy to the problem PC (works with no internet)

Copy the whole `UpdateHealthKit` folder to a USB drive or an approved file share, then onto the problem PC. Only the `Collector` folder is needed there, but copying everything is fine.

### Step 3. Collect (on the problem PC)

Open **Windows PowerShell as Administrator** and run:

```powershell
cd E:\UpdateHealthKit                               # wherever you copied it (here: USB drive E:)
.\Collector\Invoke-UpdateHealthCollector.ps1
```

When it finishes (usually 1-3 minutes), it prints where the bundle went. By default that's next to the script:

```
E:\UpdateHealthKit\Collector\UpdateHealth_PC123_20261124-101500\       (folder)
E:\UpdateHealthKit\Collector\UpdateHealth_PC123_20261124-101500.zip    (the same thing zipped; bring this back)
```

If the script's folder is read-only, the bundle goes to `%TEMP%` instead. The console output shows the exact path.

### Step 4. Bring the zip back and analyze (admin PC)

Copy `UpdateHealth_<PC>_<date-time>.zip` back to the admin PC, then run:

```powershell
cd C:\Tools\UpdateHealthKit
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 `
    -InputPath  "C:\Bundles\UpdateHealth_PC123_20261124-101500.zip" `
    -SiteServer CM01 `
    -Open
```

- **`-InputPath`** is the zip from Step 3 (see [what to pass](#-inputpath-what-to-pass)).
- **`-SiteServer`** is your SCCM SMS Provider, usually the primary site server (see [how to find it](#-siteserver-how-to-find-yours)).
- **`-Open`** opens the report in your browser when it's done.

The report is written to `.\UpdateHealthReports\PC123_20261124-101500\UpdateHealthReport.html`, with `analysis.json` beside it.

---

## Analyzer parameters explained

### `-InputPath`: what to pass

The collector's output, after you copy it to the PC you're analyzing on. Any of these work:

| You pass | Example | Result |
|---|---|---|
| The zip | `-InputPath C:\Bundles\UpdateHealth_PC123_20261124-101500.zip` | One report |
| The unzipped folder | `-InputPath C:\Bundles\UpdateHealth_PC123_20261124-101500` | One report |
| The `collection.json` inside it | `-InputPath C:\Bundles\UpdateHealth_PC123_20261124-101500\collection.json` | One report |
| A folder full of zips/folders | `-InputPath C:\Bundles` or `-InputPath \\fileserver\it\UpdateHealth` | One report per PC, plus a summary `index.html` |
| Several paths | `-InputPath C:\Bundles\PC123.zip, C:\Bundles\PC456.zip` | One report per PC, plus `index.html` |

Put quotes around paths that contain spaces.

### `-SiteServer`: how to find yours

This is the **SMS Provider** of your SCCM site. In most environments that's the **primary site server**, the server your SCCM console connects to. You can use the short name (`CM01`) or the FQDN (`CM01.corp.example.com`).

Ways to find it:

1. **SCCM console:** go to **Administration → Site Configuration → Servers and Site System Roles**. Pick the server that lists the **SMS Provider** role.
2. **Console connection:** open the console's menu (top-left) → **Connect to a New Site**. The server shown there is the one the console uses.
3. **PowerShell**, if you know the site server and want to confirm it's the provider and see the site code:

   ```powershell
   Get-WmiObject -ComputerName CM01 -Namespace root\SMS -Class SMS_ProviderLocation |
       Select-Object Machine, SiteCode, ProviderForLocalSite
   ```

You usually don't need `-SiteCode`, because the analyzer reads it from the server. Pass it only if auto-detection fails, for example `-SiteCode ABC`.

**Run the analyzer as an account that can open the SCCM console.** Read-only Analyst is enough. It connects over WMI/DCOM, the same way the console does, so WinRM isn't required.

If you leave out `-SiteServer`, the analyzer still compares the PC against Microsoft's latest Windows and .NET releases and checks everything from the collected logs. It skips only the SCCM-side checks: device record, collections, deployments, maintenance windows, and whether the latest CU is in your catalog.

### All analyzer options

| Parameter | What it's for | Example |
|---|---|---|
| `-InputPath` | Bundle zip/folder(s), see above (required) | `-InputPath C:\Bundles\PC123.zip` |
| `-SiteServer` | SCCM SMS Provider / primary site server | `-SiteServer CM01` |
| `-SiteCode` | Site code, only if auto-detect fails | `-SiteCode ABC` |
| `-WsusServer` | Also look the device up in WSUS (needs the WSUS console / RSAT "Windows Server Update Services Tools" on this PC). Usually your SUP. | `-WsusServer SUP01` |
| `-WsusPort` | WSUS port: 8530 (HTTP, default) or 8531 (HTTPS) | `-WsusPort 8531` |
| `-WsusSsl` | Use HTTPS to WSUS | `-WsusSsl` |
| `-OutputPath` | Where reports go (default `.\UpdateHealthReports`) | `-OutputPath D:\Reports` |
| `-Offline` | Don't download Microsoft data; use the cache | `-Offline` |
| `-CacheDir` | Cache folder (default `Analyzer\cache`) | `-CacheDir D:\UHK\cache` |
| `-CacheHours` | Re-download Microsoft data older than this (default 12) | `-CacheHours 48` |
| `-Open` | Open the report when finished | `-Open` |

### Analyzer examples

```powershell
# One PC, compared against SCCM, open the report
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath C:\Bundles\UpdateHealth_PC123_20261124-101500.zip -SiteServer CM01 -Open

# Every bundle in a share -> one report each plus index.html
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath \\fileserver\it\UpdateHealth -SiteServer CM01.corp.example.com

# Also check the device in WSUS on the SUP (HTTPS)
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath C:\Bundles\PC123.zip -SiteServer CM01 -WsusServer SUP01 -WsusPort 8531 -WsusSsl

# No SCCM access from this PC: Microsoft comparison and log checks only
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath C:\Bundles\PC123.zip

# On a PC with no internet: reuse Microsoft data cached by an earlier online run
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath C:\Bundles\PC123.zip -SiteServer CM01 -Offline
```

To use the analyzer on a PC with no internet, run it once on an online PC first. Then copy the whole `Analyzer` folder, including the `cache` subfolder it created, and run with `-Offline`.

The optional exe takes the same options, with `-Input`/`-Output` instead of `-InputPath`/`-OutputPath`:
`.\Analyzer\UpdateHealthAnalyzer.exe -Input C:\Bundles\PC123.zip -SiteServer CM01 -Open`

---

## Collector parameters explained

Run from an **elevated** Windows PowerShell on the problem PC. All parameters are optional.

| Parameter | What it's for | Example |
|---|---|---|
| `-OutputPath` | Where to write the bundle (default: next to the script, else `%TEMP%`) | `-OutputPath E:\Bundles\PC123` |
| `-Days` | How many days of event logs, CCM logs and install history (default 30) | `-Days 60` |
| `-ScanCabPath` | Path to Microsoft's offline scan file `wsusscn2.cab`. Runs a real Windows Update scan for missing security updates with no network. Takes 5-20 minutes. | `-ScanCabPath E:\wsusscn2.cab` |
| `-OnlineScan` | Windows Update scan against the device's own update source (your SUP). Only useful if the PC can reach the SUP. | `-OnlineScan` |
| `-RunDismCheck` | `DISM /CheckHealth` to detect component store corruption (fast, read-only) | `-RunDismCheck` |
| `-IncludeWindowsUpdateLog` | Also convert the Windows Update ETL traces to `WindowsUpdate.log` (slow) | `-IncludeWindowsUpdateLog` |
| `-SkipRawLogs` | Don't copy raw CCM/CBS/DISM logs into the bundle (smaller zip) | `-SkipRawLogs` |
| `-SkipConnectivityTests` | Skip the DNS/TCP/HTTP tests to the MP and SUP | `-SkipConnectivityTests` |
| `-NoZip` | Leave the folder only, no zip | `-NoZip` |

### Collector examples

```powershell
# Defaults: last 30 days, bundle + zip next to the script
.\Collector\Invoke-UpdateHealthCollector.ps1

# Longer history and a component store check
.\Collector\Invoke-UpdateHealthCollector.ps1 -Days 60 -RunDismCheck

# Fully offline missing-update scan (download wsusscn2.cab on an online PC first and copy it alongside)
.\Collector\Invoke-UpdateHealthCollector.ps1 -ScanCabPath E:\wsusscn2.cab

# Write the bundle straight to a share the analyzer PC can read
.\Collector\Invoke-UpdateHealthCollector.ps1 -OutputPath \\fileserver\it\UpdateHealth\PC123
```

The collector only reads. The one exception: with `-ScanCabPath` it registers a temporary offline scan service and removes it when the scan finishes.

**What it collects**
- **System:** OS, edition, version and build.UBR, architecture (x64/ARM64/x86), model, BIOS, disk space, uptime, pending restart (CBS, WU, file renames, CCM), time sync, proxy, Secure Boot certificate status
- **.NET:** Framework 4.x release, 3.5, plus every .NET Runtime, ASP.NET Core, Desktop Runtime and SDK (x64, x86, and x64-on-ARM64)
- **Windows Update:** agent version, related services, WSUS/WUfB/MDM policies, Registry.pol health, hotfixes, the full WUA history (including which installs came from CcmExec, i.e. Software Center), an optional WUA scan, SoftwareDistribution size, optional DISM CheckHealth
- **SCCM client:** version, GUID, site, MP, SUP (CCM_UpdateSource), Software Updates client settings, cache, the client's own scan results (CCM_UpdateStatus), Software Center updates and apps with state and errors, maintenance windows, CCMEval, co-management
- **CCM logs:** about 27 logs parsed for errors, warnings and known failure signatures (scan failures, GPO conflict, WUA source errors, content/DP problems, MP communication, certificates, registration, maintenance windows, AppLocker blocks, WMI). Raw copies are included along with ccmsetup.log, CBS.log and dism.log.
- **Event logs:** System, Application, Setup, WindowsUpdateClient, BITS, MDM, AppLocker and CodeIntegrity
- **Connectivity:** DNS/TCP/HTTP tests to the SUP (`/ClientWebService/client.asmx`) and the MP (`/sms_mp/.sms_aut?mplist`). When the PC is offline these fail fast and are labelled as such.

---

## Signing and building

```powershell
.\Build\Build-UpdateHealthKit.ps1 -SignOnly                       # sign the scripts (and the .exe if present)
.\Build\Build-UpdateHealthKit.ps1 -SignOnly -Thumbprint 1A2B3C...   # use a specific certificate
.\Build\Build-UpdateHealthKit.ps1                                 # compile the optional .exe, then sign everything
.\Build\Build-UpdateHealthKit.ps1 -SkipSign                       # compile only
```

- By default it uses the newest valid code-signing certificate with a private key in `CurrentUser\My`.
- It signs with SHA-256 and a timestamp (default `http://timestamp.digicert.com`; change with `-TimestampServer`). If the timestamp server can't be reached, it signs without a timestamp and warns you.
- **Re-sign after you edit any script**, because an edit invalidates the signature.
- **AppLocker:** a publisher rule for your signing certificate covers everything. Signed scripts that policy allows run in FullLanguage mode, which both scripts need (COM for the Windows Update Agent, WMI, .NET classes).

---

## What the analyzer compares against

- **Microsoft Windows release health pages (Windows 11 and Windows 10):** the latest monthly security (B) build and KB for the device's OS build, how many monthly updates the device is behind, out-of-band releases, and end-of-servicing dates for the device's edition. Hotpatch calendars are ignored.
- **Microsoft .NET release metadata:** for each installed runtime or SDK, the latest patch in its channel (SDKs are compared within their feature band), the number of security releases and CVEs it has missed, and whether the channel is end-of-life.
- **SCCM SMS Provider (`-SiteServer`):**
  - device records (duplicates, GUID mismatch, obsolete, blocked, approval)
  - client activity and last policy request
  - collection membership, software update deployments and maintenance windows
  - the site's per-update compliance (required vs. installed, deployed vs. not deployed, and the last scan result received)
  - whether Microsoft's latest CU is in the SCCM catalog, is deployed, and is deployed to this device
  - client version vs. site version
- **WSUS (`-WsusServer`, optional):** the device's last report/sync time and its install summary.

## The report

1. **What needs to be updated:** Windows feature version, the Windows CU (installed vs. latest), the .NET Framework, every .NET runtime/SDK, and the SCCM client
2. **Findings:** ranked Critical to Low, each with a detail line and a recommended fix
3. **Missing updates**, merged from the WUA scan, the SCCM client scan, Software Center and the site
4. **Recent installs**, merged from WUA history (Software Center vs. Windows Update), Software Center apps, MSI events and servicing events
5. Software Center, SCCM client (signatures, CCMEval, log errors), SCCM server view, Windows Update, .NET, event highlights, system/network, and data sources

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "running scripts is disabled on this system" | Sign the scripts (Step 1), or for testing run `Set-ExecutionPolicy -Scope Process Bypass` in that window |
| "not digitally signed" right after downloading | You didn't **Unblock** the zip before extracting. Unblock the zip and extract again, or run `Get-ChildItem -Recurse | Unblock-File` in the folder |
| Collector warns "Not running elevated" | Close PowerShell and reopen it with **Run as administrator** |
| Analyzer: "Could not query the SMS Provider" / "Access denied" / "RPC server is unavailable" | Check the `-SiteServer` name. Run as an account with SCCM console rights. Make sure DCOM/WMI (TCP 135 + dynamic RPC) is open from this PC to the provider. If the site code isn't detected, pass `-SiteCode` |
| Analyzer: "Microsoft Windows release data unavailable" | This PC can't reach learn.microsoft.com. Run once on a PC with internet, then copy the `Analyzer\cache` folder and use `-Offline` |
| Analyzer: "WSUS administration API not found" | Install RSAT "Windows Server Update Services Tools" on the analyzer PC, or leave out `-WsusServer` |
| Report says "Windows Server isn't covered" | Expected. The Microsoft comparison covers Windows 10/11 clients. SCCM, log and event checks still run for servers |

## Notes and limits

- Ages such as "last scan 9 days ago" are measured from when the bundle was **collected**. "Latest version" uses today's Microsoft data.
- The Windows CU check relies on Microsoft's release-information page layout. If Microsoft changes it, the report says the data was unavailable rather than guessing.
- For a device on hotpatch, the build number may not match the monthly B build exactly. Check the hotpatch calendar.
- **Testing:** every push is tested on a Windows machine by GitHub Actions. The collector runs for real, then both analyzers process its output, plus a copy made to look like a Windows 11 client, and the build fails on any error. Sample reports from each run are attached to it as `e2e-sample-reports`. The SCCM and WSUS checks can't be exercised there because there's no site to query.

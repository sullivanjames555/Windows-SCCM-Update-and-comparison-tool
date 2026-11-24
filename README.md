# UpdateHealthKit

Finds out why a Windows PC or server isn't getting updates from Software Center / SCCM, and what on it needs updating. It covers Windows 10, Windows 11 and Windows Server 2016, 2019, 2022 and 2025. Each host is compared only against the updates for **its own OS version, edition and architecture**.

It has two parts, both plain Windows PowerShell 5.1 scripts. Nothing has to be compiled, and AppLocker treats them like any other signed script.

| Part | Runs on | Needs network? | What it does |
|---|---|---|---|
| `Collector\Invoke-UpdateHealthCollector.ps1` | The problem PC | No | Collects system, .NET, Windows Update, SCCM client, CCM logs and event logs into a zip |
| `Analyzer\Invoke-UpdateHealthAnalyzer.ps1` | An admin PC with internet and SCCM access | Yes (it can also use a cache) | Compares that zip with Microsoft's latest Windows/.NET releases and your SCCM site (plus WSUS if you want), then writes an HTML + JSON report |

```
Build\Build-UpdateHealthKit.ps1             signs the two scripts with your code-signing certificate
Collector\Invoke-UpdateHealthCollector.ps1  run on each host you're evaluating
Analyzer\Invoke-UpdateHealthAnalyzer.ps1    run on your admin PC against the collected zips
```

**Which script runs where:** run the **collector** on the host you're evaluating, and the **analyzer** on your admin PC. The collector needs no internet and no SCCM access, so it works on isolated hosts. The analyzer needs internet to fetch Microsoft's latest versions, and SCCM console rights for the SCCM checks. If a host has both, you can run both scripts on it.

---

## Quick start

### Step 1. Download and sign (admin PC with internet)

1. Download **UpdateHealthKit.zip** from the [Latest build release](../../releases/tag/latest).
2. Right-click the zip → **Properties** → tick **Unblock** → **OK**. Then extract it, for example to `C:\Tools\UpdateHealthKit`.
3. Open **Windows PowerShell** in that folder and sign the scripts with your code-signing certificate:

   ```powershell
   cd C:\Tools\UpdateHealthKit
   Set-ExecutionPolicy -Scope Process Bypass          # this window only
   .\Build\Build-UpdateHealthKit.ps1
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

When it finishes (usually 1-3 minutes), it prints where the bundle went. The bundle is always named after the host it ran on (`UpdateHealth_<HOSTNAME>_<date-time>`), so bundles from many hosts can sit in one folder. By default it goes next to the script:

```
E:\UpdateHealthKit\Collector\UpdateHealth_PC123_20261124-101500\       (folder)
E:\UpdateHealthKit\Collector\UpdateHealth_PC123_20261124-101500.zip    (the same thing zipped; bring this back)
```

If the script's folder is read-only, the bundle goes to `%TEMP%` instead. The console output shows the exact path.

**Several hosts:** run the collector on each one with the same `-OutputPath`, such as a share or the same USB folder. Each host adds its own `UpdateHealth_<HOSTNAME>_...zip` there:

```powershell
.\Collector\Invoke-UpdateHealthCollector.ps1 -OutputPath \\fileserver\it\UpdateHealth
```

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
- **`-Open`** also opens the HTML report in your browser.

When it's done, a **results window** pops up (see [below](#the-results-window)). It shows each system, how far behind it is, and what it needs. The full HTML report is written to `.\UpdateHealthReports\PC123_20261124-101500\UpdateHealthReport.html`, with `analysis.json` beside it.

To analyze several hosts at once, point `-InputPath` at the folder holding their zips:

```powershell
.\Analyzer\Invoke-UpdateHealthAnalyzer.ps1 -InputPath \\fileserver\it\UpdateHealth -SiteServer CM01
```

### The results window

One row per system analyzed, colored by its worst problem (red = critical, orange = high, yellow = medium, green = OK):

| Column | Meaning |
|---|---|
| Computer, OS, Build | The host's name, Windows version/edition, and build.UBR from the collected data |
| Windows updates | `Current`, or how many monthly security updates it's behind (e.g. `3 monthly security updates behind`) |
| Latest KB needed | The latest cumulative update for **that** OS version (e.g. Windows Server 2016 gets the Server 2016 KB, Windows 11 24H2 gets the 24H2 KB) |
| Support | Whether that OS version is still supported, and until when |
| .NET | How many .NET runtimes/SDKs need updating |
| Critical / High / Medium | Count of findings at each severity |

Select a system to see these tabs underneath:
- **What needs updating:** each component with its installed vs. latest version and the action to take.
- **Why it is not updating:** the findings with their recommended fixes.
- **Notes.**

**Open HTML report** (or double-click a row) opens that system's full report. Use `-NoGui` to skip the window, for example in scheduled runs.

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
| `-Open` | Also open the HTML report in the browser | `-Open` |
| `-NoGui` | Don't show the results window | `-NoGui` |

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

---

## Collector parameters explained

Run from an **elevated** Windows PowerShell on the problem PC. All parameters are optional.

| Parameter | What it's for | Example |
|---|---|---|
| `-OutputPath` | Folder to put the bundle in. The bundle inside is always named `UpdateHealth_<HOSTNAME>_<date-time>` (default folder: next to the script, else `%TEMP%`) | `-OutputPath \\fileserver\it\UpdateHealth` |
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

# Write the bundle straight to a share; run the same line on several hosts, then analyze the share
.\Collector\Invoke-UpdateHealthCollector.ps1 -OutputPath \\fileserver\it\UpdateHealth
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

## Signing

```powershell
.\Build\Build-UpdateHealthKit.ps1                          # sign both scripts with your newest code-signing cert
.\Build\Build-UpdateHealthKit.ps1 -Thumbprint 1A2B3C...      # use a specific certificate
```

- By default it uses the newest valid code-signing certificate with a private key in `CurrentUser\My`. List yours with `Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert`.
- It signs with SHA-256 and a timestamp (default `http://timestamp.digicert.com`; change with `-TimestampServer`). If the timestamp server can't be reached, it signs without a timestamp and warns you.
- **Re-sign after you edit either script**, because an edit invalidates the signature.
- **AppLocker:** a publisher rule for your signing certificate covers both scripts. Signed scripts that policy allows run in FullLanguage mode, which both scripts need (COM for the Windows Update Agent, WMI, .NET classes, and Windows Forms for the results window).

---

## What the analyzer compares against

- **Microsoft's Windows release health pages (Windows 11, Windows 10 and Windows Server):** the analyzer works out what the host is from the collected data:
  - client or server
  - build (for example 26100 = Windows 11 24H2 or Server 2025, 14393 = Server 2016)
  - edition (Home/Pro vs. Enterprise/Education vs. LTSC vs. Server)
  - architecture

  It then compares the host only against that OS's own release history: the latest monthly security (B) build and KB, how many monthly updates it's behind, any out-of-band releases, and the end-of-support date for that edition. Windows 11 24H2 and Server 2025 share build 26100 but are tracked separately. Hotpatch calendars are ignored.
- **.NET Framework:** compared against the newest version that OS can run. That's 4.8.1 on Windows 10 21H2+, Windows 11 and Server 2022+, and 4.8 on Server 2016/2019 and older Windows 10.
- **Microsoft .NET release metadata:** for each installed runtime or SDK, the latest patch in its channel (SDKs are compared within their feature band), the number of security releases and CVEs it has missed, and whether the channel is end-of-life.
- **SCCM SMS Provider (`-SiteServer`):**
  - device records (duplicates, GUID mismatch, obsolete, blocked, approval)
  - client activity and last policy request
  - collection membership, software update deployments and maintenance windows
  - the site's per-update compliance (required vs. installed, deployed vs. not deployed, and the last scan result received)
  - whether Microsoft's latest CU **for this OS** is in the SCCM catalog, is deployed, and is deployed to this device. It's matched by the catalog title, for example `Cumulative Update for Windows Server 2016 for x64-based Systems` or `Cumulative Update for Windows 11 Version 24H2 for x64-based Systems`.
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
| No results window appears | It needs an interactive desktop session in Windows PowerShell (not over a remote session or scheduled task). Use the HTML report, or `-Open` |
| "Build ... is not listed on Microsoft's release information pages" | Insider/preview or out-of-support build, or the cache is older than the OS. Run without `-Offline` to refresh |

## Notes and limits

- Ages such as "last scan 9 days ago" are measured from when the bundle was **collected**. "Latest version" uses today's Microsoft data.
- The Windows CU check relies on Microsoft's release-information page layout. If Microsoft changes it, the report says the data was unavailable rather than guessing.
- For a device on hotpatch, the build number may not match the monthly B build exactly. Check the hotpatch calendar.
- Windows Server, version 23H2 (Annual Channel) and Azure Edition hotpatch builds may not line up with the monthly B builds. Check those against the hotpatch calendar.
- **Testing:** every push is tested on a Windows Server 2025 machine by GitHub Actions. The collector runs for real. The analyzer then processes that bundle plus two copies made to look like a Windows 11 24H2 PC and a Windows Server 2016 server, and checks that each is compared against its own OS. It also opens the results window, clicks through every system and closes it. The build fails on any error. Sample reports from each run are attached to it as `e2e-sample-reports`. The SCCM and WSUS checks can't be exercised there because there's no site to query.

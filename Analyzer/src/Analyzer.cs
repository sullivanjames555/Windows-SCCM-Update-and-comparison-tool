// UpdateHealthKit analyzer - findings engine. Turns one collection.json (plus Microsoft and
// SCCM/WSUS data) into "what needs updating" rows and prioritised findings with fixes.
// C# 5 compatible.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace UpdateHealthKit
{
    internal sealed class Finding
    {
        public string Severity;
        public string Area;
        public string Title;
        public string Detail;
        public string Fix;
    }

    internal sealed class UpdateRow
    {
        public string Component;
        public string Installed;
        public string Latest;
        public string Status;
        public string Action;
        public string Severity;
    }

    internal sealed class AnalysisResult
    {
        public string ComputerName;
        public string BundlePath;
        public string ReportPath;
        public DateTime? CollectedAt;
        public object Data;
        public readonly List<Finding> Findings = new List<Finding>();
        public readonly List<UpdateRow> Updates = new List<UpdateRow>();
        public readonly List<Dictionary<string, string>> Missing = new List<Dictionary<string, string>>();
        public readonly List<Dictionary<string, string>> RecentInstalls = new List<Dictionary<string, string>>();
        public readonly List<Dictionary<string, string>> EventGroups = new List<Dictionary<string, string>>();
        public readonly List<string> Notes = new List<string>();
        public ServerView Server;
        public string ServerName;
        public string ServerError;
        public string SiteCode;
        public string SiteVersion;
        public Dictionary<string, string> Wsus;
        public string WsusError;
        public string LatestKb;
        public string CuPattern;
        public int MsWindowsVersions;
        public int MsWindowsReleaseBuilds;
        public int MsDotNetChannels;

        public int Count(string sev) { return Findings.Count(f => f.Severity == sev); }

        public Dictionary<string, object> ToDictionary()
        {
            var d = new Dictionary<string, object>();
            d["ComputerName"] = ComputerName;
            d["CollectedAt"] = J.Fmt(CollectedAt);
            d["AnalyzedAt"] = J.Fmt(DateTime.Now);
            d["AnalyzerVersion"] = Program.Version;
            d["Summary"] = new Dictionary<string, object>
            {
                { "Critical", Count(Sev.Critical) }, { "High", Count(Sev.High) }, { "Medium", Count(Sev.Medium) },
                { "Low", Count(Sev.Low) }, { "Info", Count(Sev.Info) }
            };
            d["Updates"] = Updates.Select(u => new Dictionary<string, object>
            {
                { "Component", u.Component }, { "Installed", u.Installed }, { "Latest", u.Latest },
                { "Status", u.Status }, { "Action", u.Action }, { "Severity", u.Severity }
            }).ToList();
            d["Findings"] = Findings.Select(f => new Dictionary<string, object>
            {
                { "Severity", f.Severity }, { "Area", f.Area }, { "Title", f.Title }, { "Detail", f.Detail }, { "Fix", f.Fix }
            }).ToList();
            d["MissingUpdates"] = Missing;
            d["RecentInstalls"] = RecentInstalls;
            d["Notes"] = Notes;
            d["MicrosoftData"] = new Dictionary<string, object>
            {
                { "WindowsVersions", MsWindowsVersions }, { "WindowsReleaseBuilds", MsWindowsReleaseBuilds }, { "DotNetChannels", MsDotNetChannels }
            };
            if (Server != null)
            {
                d["SccmServer"] = new Dictionary<string, object>
                {
                    { "Server", ServerName }, { "SiteCode", SiteCode }, { "ResourceId", Server.ResourceId },
                    { "Records", Server.Records.Count }, { "Collections", Server.Collections.Select(c => c.Value).ToList() },
                    { "Deployments", Server.Deployments }, { "MaintenanceWindows", Server.MaintenanceWindows },
                    { "LastStatusCheck", J.Fmt(Server.LastStatusCheck) }, { "Combined", Server.Combined },
                    { "RequiredUpdates", Server.Required.Select(u => new Dictionary<string, object>
                        { { "KB", "KB" + u.Article }, { "Title", u.Title }, { "DeployedToDevice", u.DeployedToDevice }, { "IsDeployed", u.IsDeployed }, { "LastError", u.LastError } }).ToList() },
                    { "Error", Server.Error }
                };
            }
            if (Wsus != null) d["Wsus"] = Wsus;
            return d;
        }
    }

    internal sealed class Analyzer
    {
        private readonly object c;
        private readonly MicrosoftData ms;
        private readonly SccmServer sccm;
        private readonly Options opt;
        private readonly AnalysisResult r = new AnalysisResult();

        private DateTime refNow;
        private int days;
        private int build;
        private int ubr;
        private string disp;
        private string edition;
        private string arch;
        private bool sccmInstalled;
        private bool likelyOffline;

        public Analyzer(object data, MicrosoftData ms, SccmServer sccm, Options opt)
        {
            c = data;
            this.ms = ms;
            this.sccm = sccm;
            this.opt = opt;
            r.Data = data;
        }

        public AnalysisResult Run()
        {
            r.ComputerName = J.S(c, "System.ComputerName") ?? J.S(c, "Meta.ComputerName");
            r.CollectedAt = J.T(c, "Meta.CollectedAtLocal");
            refNow = r.CollectedAt ?? DateTime.Now;
            days = J.I(c, "Meta.DaysBack") ?? 30;
            build = J.I(c, "System.CurrentBuild") ?? 0;
            ubr = J.I(c, "System.UBR") ?? 0;
            disp = J.S(c, "System.DisplayVersion") ?? J.S(c, "System.ReleaseId");
            edition = J.S(c, "System.EditionID") ?? "";
            arch = J.S(c, "System.UpdateArch") ?? "x64";
            sccmInstalled = J.B(c, "Sccm.Installed");
            likelyOffline = J.B(c, "Meta.LikelyOffline");
            r.MsWindowsVersions = ms.Windows.Versions.Count;
            r.MsWindowsReleaseBuilds = ms.Windows.Releases.Values.Sum(x => x.Count);
            r.MsDotNetChannels = ms.DotNet.Channels.Count;

            Step("Collection", AnalyzeMeta);
            Step("Windows", AnalyzeWindows);
            Step(".NET", AnalyzeDotNet);
            Step("Windows Update", AnalyzeWindowsUpdate);
            Step("SCCM client", AnalyzeSccmClient);
            Step("Event logs", AnalyzeEvents);
            Step("Connectivity", AnalyzeConnectivity);
            Step("SCCM server", AnalyzeServer);
            Step("WSUS", AnalyzeWsus);
            Step("Missing updates", BuildMissing);
            Step("Recent installs", BuildRecentInstalls);

            if (!r.Findings.Any(f => Sev.Rank(f.Severity) <= 1))
                Add(Sev.OK, "Summary", "No critical or high-severity problems found", "Review medium/low findings below.", null);

            var sorted = r.Findings.OrderBy(f => Sev.Rank(f.Severity)).ThenBy(f => f.Area).ToList();
            r.Findings.Clear();
            r.Findings.AddRange(sorted);
            return r;
        }

        private void Step(string name, Action a)
        {
            try { a(); }
            catch (Exception ex)
            {
                Add(Sev.Info, "Analyzer", "Analysis step '" + name + "' failed", ex.GetType().Name + ": " + ex.Message, "Report this with the bundle; other sections are unaffected.");
            }
        }

        private void Add(string sev, string area, string title, string detail, string fix)
        {
            r.Findings.Add(new Finding { Severity = sev, Area = area, Title = title, Detail = detail, Fix = fix });
        }

        private void Row(string component, string installed, string latest, string status, string action, string sev)
        {
            r.Updates.Add(new UpdateRow { Component = component, Installed = installed, Latest = latest, Status = status, Action = action, Severity = sev });
        }

        private static string Plural(int n, string word) { return n + " " + word + (n == 1 ? "" : "s"); }

        private static string Short(string s, int max)
        {
            if (s == null) return null;
            s = Regex.Replace(s, @"\s+", " ").Trim();
            return s.Length <= max ? s : s.Substring(0, max) + "...";
        }

        // ------------------------------------------------------------------ Meta
        private void AnalyzeMeta()
        {
            if (J.BN(c, "Meta.RunAsAdmin") == false)
                Add(Sev.Medium, "Collection", "Collector was not run as administrator",
                    "SCCM WMI, some event logs and Windows Update data may be missing, so some checks below are incomplete.",
                    "Re-run Invoke-UpdateHealthCollector.ps1 from an elevated PowerShell.");

            var errs = J.A(c, "Meta.SectionErrors");
            if (errs.Count > 0)
                Add(Sev.Info, "Collection", Plural(errs.Count, "collector section") + " reported errors",
                    string.Join("; ", errs.Take(10).Select(e => J.S(e, "Section") + ": " + Short(J.S(e, "Error"), 160))),
                    "Usually harmless (component not installed). Repeated WMI errors point to a broken WMI repository.");

            if (r.CollectedAt.HasValue && (DateTime.Now - r.CollectedAt.Value).TotalDays > 14)
                r.Notes.Add("This bundle was collected " + (int)(DateTime.Now - r.CollectedAt.Value).TotalDays +
                            " days ago. Ages (last scan, uptime, etc.) are measured from the collection time; 'latest version' comparisons use today's Microsoft data.");
            if (likelyOffline)
                r.Notes.Add("The device could not resolve its MP/SUP or the internet when collected (likely offline), so connectivity results reflect that.");
        }

        // ------------------------------------------------------------------ Windows
        private void AnalyzeWindows()
        {
            bool win11 = build >= 22000;
            string product = win11 ? "Windows 11" : "Windows 10";
            bool ltsc = Regex.IsMatch(edition, @"Enterprise(S|SN)$", RegexOptions.IgnoreCase);
            bool entClass = Regex.IsMatch(edition, "Enterprise|Education|ServerRdsh", RegexOptions.IgnoreCase);
            string installedBuild = build + "." + ubr;
            string instType = J.S(c, "System.InstallationType") ?? "";

            if (instType.IndexOf("Server", StringComparison.OrdinalIgnoreCase) >= 0 || edition.StartsWith("Server", StringComparison.OrdinalIgnoreCase))
            {
                Row("Windows Server cumulative update", installedBuild, "not compared", "Not checked", "Windows Server isn't covered by the Microsoft comparison; use the SCCM server view", Sev.Info);
                r.Notes.Add("This is Windows Server (" + edition + "). The Microsoft client release comparison was skipped; SCCM, log and event checks still apply.");
                return;
            }
            if (!string.IsNullOrEmpty(disp))
                r.CuPattern = string.Format(CultureInfo.InvariantCulture, "Cumulative Update for {0} Version {1} for {2}-based", product, disp, arch);

            if (build == 0)
            {
                Add(Sev.Info, "Windows", "OS build not present in the bundle", null, "Check the collector transcript for System errors.");
                return;
            }
            if (!ms.Windows.Loaded)
            {
                Row(product + " cumulative update", installedBuild, "unknown", "Not checked", "Microsoft release data unavailable (offline and no cache).", Sev.Info);
                Add(Sev.Info, "Windows", "Microsoft Windows release data unavailable", "Run the analyzer once with internet access to build the cache.", null);
                return;
            }

            OsVersionRow ver = ms.Windows.FindVersion(build, ltsc);
            List<OsRelease> rels = ms.Windows.GetReleases(build);
            List<OsRelease> bRels = rels.Where(x => x.Type == "B").ToList();
            if (bRels.Count == 0) bRels = rels.Where(x => x.Type != "Preview").ToList();
            OsRelease latestB = bRels.FirstOrDefault();
            OsRelease latestAny = rels.FirstOrDefault();

            // Feature version / end of servicing
            if (ver != null)
            {
                string eos = entClass ? ver.EosEnterprise : ver.EosHomePro;
                if (string.IsNullOrEmpty(eos)) eos = ver.EosEnterprise ?? ver.EosHomePro;
                bool ended = false;
                string eosText = eos;
                DateTime eosDate;
                if (eos != null && eos.IndexOf("End of", StringComparison.OrdinalIgnoreCase) >= 0) ended = true;
                else if (eos != null && DateTime.TryParse(eos, CultureInfo.InvariantCulture, DateTimeStyles.None, out eosDate))
                {
                    if (eosDate.Date < DateTime.Today) ended = true;
                    else if ((eosDate - DateTime.Today).TotalDays <= 120)
                        Add(Sev.Medium, "Windows", string.Format("{0} {1} reaches end of servicing on {2:yyyy-MM-dd}", product, disp, eosDate),
                            "Edition " + edition + ". After this date it receives no security updates.",
                            "Plan the feature update (SCCM servicing plan, feature update deployment, or in-place upgrade task sequence).");
                    eosText = "supported until " + eosDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                }
                OsVersionRow newest = ms.Windows.NewestVersion(win11);
                string newestText = newest != null ? newest.Version + " (" + newest.Major + ")" : "?";
                if (ended)
                {
                    Add(Sev.Critical, "Windows", string.Format("{0} {1} is out of servicing for the {2} edition", product, disp, edition),
                        "Microsoft no longer ships security updates for this version/edition (unless the device is enrolled in Extended Security Updates). Microsoft lists: " + eos,
                        "Upgrade to a supported feature update (newest: " + newestText + "). Until then the device will never show as compliant.");
                    Row(product + " feature version", disp + " (" + edition + ")", newestText, "Out of servicing", "Feature update required", Sev.Critical);
                }
                else
                {
                    bool behindFeature = newest != null && newest.Major != build && !ltsc;
                    Row(product + " feature version", disp + " (" + edition + ")", ltsc ? "LTSC" : newestText, eosText ?? "Supported",
                        behindFeature ? "Optional: newer feature update available" : "None", behindFeature ? Sev.Info : Sev.OK);
                }
            }
            else
            {
                Add(Sev.Info, "Windows", "Build " + build + " is not listed on Microsoft's release information pages",
                    "Insider, Server, or a version newer than the cached data.", "Run without -Offline to refresh Microsoft data.");
            }

            // Monthly cumulative update
            if (latestB == null)
            {
                Row(product + " cumulative update", installedBuild, "unknown", "Not checked", "No release history found for build " + build, Sev.Info);
                return;
            }
            r.LatestKb = latestB.Kb;
            string latestText = string.Format("{0} ({1}, {2})", latestB.BuildText, latestB.Kb, latestB.Date);
            OsRelease installedRel = rels.FirstOrDefault(x => x.Ubr == ubr);
            string installedText = installedBuild + (installedRel != null ? " (" + installedRel.Kb + ", " + installedRel.Date + ")" : "");

            if (ubr >= latestB.Ubr)
            {
                Row(product + " cumulative update", installedText, latestText, "Current", "None", Sev.OK);
            }
            else
            {
                int behind = bRels.Count(x => x.Ubr > ubr);
                double ageDays = latestB.DateValue.HasValue ? (DateTime.Today - latestB.DateValue.Value).TotalDays : 99;
                string sev = behind >= 3 ? Sev.Critical : behind == 2 ? Sev.High : (ageDays < 14 ? Sev.Low : Sev.Medium);
                string monthsText = Plural(behind, "monthly security update");
                Row(product + " cumulative update", installedText, latestText, monthsText + " behind", "Install " + latestB.Kb, sev);
                Add(sev, "Windows", "Windows is " + monthsText + " behind",
                    "Installed build " + installedText + ". Latest security update for " + product + " " + disp + " is " + latestB.Kb +
                    " (build " + latestB.BuildText + ", released " + latestB.Date + ").",
                    "Deploy " + latestB.Kb + " from SCCM. The SCCM server checks and client findings below explain why it hasn't installed.");
            }
            if (latestAny != null && latestAny.Ubr > latestB.Ubr && ubr < latestAny.Ubr && latestAny.Type == "OOB")
                Add(Sev.Medium, "Windows", "Out-of-band update " + latestAny.Kb + " is available",
                    "Build " + latestAny.BuildText + " released " + latestAny.Date + " (out-of-band fixes are usually for urgent issues).",
                    "Check the KB article; import/deploy it in SCCM if it applies to you.");
        }

        // ------------------------------------------------------------------ .NET
        private void AnalyzeDotNet()
        {
            // .NET Framework
            int? release = J.I(c, "DotNet.Framework.Release");
            string fv = J.S(c, "DotNet.Framework.FriendlyVersion");
            if (!release.HasValue)
            {
                Add(Sev.Medium, ".NET", "No .NET Framework 4.x detected", "The NDP\\v4\\Full registry key is missing (unusual on Windows 10/11).", "Repair .NET Framework through Windows Features or an in-place repair.");
            }
            else if (release.Value < 528040)
            {
                Row(".NET Framework", fv + " (release " + release + ")", "4.8.1", "Outdated", "Deploy .NET Framework 4.8.1 (or 4.8)", Sev.Medium);
                Add(Sev.Medium, ".NET", ".NET Framework " + fv + " is older than 4.8", "Older Framework versions miss current security fixes and some app requirements.", "Deploy .NET Framework 4.8.1 from SCCM.");
            }
            else if (release.Value < 533320 && build >= 19044)
            {
                Row(".NET Framework", fv + " (release " + release + ")", "4.8.1", "Supported", "Optional: 4.8.1 available for this OS", Sev.Info);
            }
            else
            {
                Row(".NET Framework", fv + " (release " + release + ")", "4.8.1", "Current", "Monthly Framework security fixes ship in the .NET Framework cumulative update (see missing updates)", Sev.OK);
            }

            // .NET (Core) 5+
            var installs = J.A(c, "DotNet.Installs");
            if (installs.Count == 0) return;
            if (!ms.DotNet.Loaded)
            {
                Add(Sev.Info, ".NET", ".NET release metadata unavailable", "Couldn't download or find cached releases-index.json, so " + Plural(installs.Count, "install") + " were not compared.", "Run with internet access once to build the cache.");
                return;
            }
            string newestLts = ms.DotNet.NewestLts();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (object inst in installs)
            {
                string kind = J.S(inst, "Kind");
                string version = J.S(inst, "Version");
                string archLabel = J.S(inst, "Architecture");
                if (kind == null || version == null) continue;
                if (kind != "Runtime" && kind != "AspNetCore" && kind != "WindowsDesktop" && kind != "SDK") continue;
                string key = kind + "|" + version + "|" + archLabel;
                if (!seen.Add(key)) continue;

                string label = KindLabel(kind) + " " + version + (string.IsNullOrEmpty(archLabel) ? "" : " (" + archLabel + ")");
                string channel = Ver.Channel(version);
                if (Ver.IsPreview(version))
                {
                    Row(label, version, "-", "Preview build", "Remove preview builds from production devices", Sev.Low);
                    continue;
                }
                DotNetChannel ch = ms.DotNet.GetChannel(channel);
                if (ch == null)
                {
                    Row(label, version, "?", "Unknown channel", "Not in Microsoft's release index", Sev.Info);
                    continue;
                }

                string latest;
                string installedRelease = null;
                if (kind == "SDK")
                {
                    string band = SdkBand(version);
                    latest = Ver.Max(ch.Releases.SelectMany(x => x.Sdks).Where(s => SdkBand(s) == band && !Ver.IsPreview(s)));
                    if (latest == null) latest = ch.LatestSdk;
                    var relWithSdk = ch.Releases.FirstOrDefault(x => x.Sdks.Contains(version));
                    if (relWithSdk != null) installedRelease = relWithSdk.Version;
                }
                else
                {
                    latest = Ver.Max(ch.Releases.Select(x => x.Component(kind)).Where(s => s != null && !Ver.IsPreview(s)));
                    if (latest == null) latest = ch.LatestRuntime;
                }

                int missedSec = 0, cves = 0;
                foreach (DotNetRelease rel in ch.Releases)
                {
                    if (!rel.Security) continue;
                    bool newer = kind == "SDK"
                        ? (installedRelease != null && Ver.Compare(rel.Version, installedRelease) > 0)
                        : (rel.Component(kind) != null && Ver.Compare(rel.Component(kind), version) > 0);
                    if (newer) { missedSec++; cves += rel.CveCount; }
                }

                bool outdated = latest != null && Ver.Compare(version, latest) < 0;
                string phase = ch.SupportPhase ?? "?";
                if (ch.IsEol)
                {
                    string eolText = ch.EolDate != null ? " on " + ch.EolDate : "";
                    Row(label, version, latest ?? "?", "Out of support (.NET " + channel + " ended" + eolText + ")",
                        "Upgrade apps to .NET " + (newestLts ?? "LTS") + " or remove this runtime", Sev.High);
                    Add(Sev.High, ".NET", KindLabel(kind) + " " + version + " is out of support",
                        ".NET " + channel + " reached end of support" + eolText + " and receives no more security fixes." +
                        (missedSec > 0 ? " It is also missing " + Plural(missedSec, "security release") + " (" + cves + " CVEs) from before end of support." : ""),
                        "Move the apps that need it to .NET " + (newestLts ?? "the current LTS") + ", then uninstall it (or deploy the final " + channel + " patch as a stopgap).");
                }
                else if (outdated)
                {
                    string sev = missedSec > 0 ? Sev.High : Sev.Medium;
                    string status = missedSec > 0 ? Plural(missedSec, "security release") + " behind (" + cves + " CVEs)" : "Patch available";
                    Row(label, version, latest, status, "Update to " + latest, sev);
                    Add(sev, ".NET", KindLabel(kind) + " " + version + " should be updated to " + latest,
                        ".NET " + channel + " (" + phase + ", " + (ch.ReleaseType ?? "?") + ") latest is " + latest + "." +
                        (missedSec > 0 ? " Missed " + Plural(missedSec, "security release") + " covering " + cves + " CVEs." : ""),
                        "Deploy the " + latest + " " + KindLabel(kind) + " (SCCM application or Microsoft Update 'Developer Tools, Runtimes and Redistributables' / .NET product category), then remove the old version if the installer doesn't.");
                }
                else
                {
                    Row(label, version, latest ?? version, "Current (" + phase + ")", "None", Sev.OK);
                }
            }
        }

        private static string KindLabel(string kind)
        {
            switch (kind)
            {
                case "Runtime": return ".NET Runtime";
                case "AspNetCore": return "ASP.NET Core Runtime";
                case "WindowsDesktop": return ".NET Desktop Runtime";
                case "SDK": return ".NET SDK";
                default: return kind;
            }
        }

        private static string SdkBand(string v)
        {
            Version p = Ver.Parse(v);
            return p == null ? null : p.Major + "." + p.Minor + "." + (p.Build / 100) + "xx";
        }

        // ------------------------------------------------------------------ Windows Update
        private static readonly string[] CriticalServices = { "wuauserv", "CcmExec", "Winmgmt" };
        private static readonly string[] ImportantServices = { "BITS", "CryptSvc", "TrustedInstaller", "msiserver" };

        private void AnalyzeWindowsUpdate()
        {
            foreach (object s in J.A(c, "WindowsUpdate.Services"))
            {
                string name = J.S(s, "Name"), start = J.S(s, "StartMode"), state = J.S(s, "State"), display = J.S(s, "DisplayName");
                if (name == null) continue;
                bool critical = CriticalServices.Contains(name, StringComparer.OrdinalIgnoreCase);
                bool important = ImportantServices.Contains(name, StringComparer.OrdinalIgnoreCase);
                if (string.Equals(start, "Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    string sev = critical ? Sev.Critical : important ? Sev.High : Sev.Medium;
                    Add(sev, "Services", display + " (" + name + ") is disabled",
                        "Windows Update / SCCM depend on this service.",
                        "Set-Service " + name + " -StartupType " + (name == "CcmExec" || name == "Winmgmt" || name == "CryptSvc" ? "Automatic" : "Manual") +
                        "; then find what disabled it (security baseline GPO, hardening script, or third-party tool).");
                }
                else if ((name == "CcmExec" || name == "Winmgmt" || name == "CryptSvc") && !string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
                {
                    Add(Sev.High, "Services", display + " (" + name + ") is " + (state ?? "not running"), "This service should always be running.",
                        "Start-Service " + name + "; check the System log for Service Control Manager errors (7000/7031/7034).");
                }
            }

            // WSUS / WUfB policy
            var pol = J.Dict(c, "WindowsUpdate.Policy");
            var au = J.Dict(c, "WindowsUpdate.PolicyAU");
            string wuServer = J.S(pol, "WUServer");
            bool useWu = J.I(au, "UseWUServer") == 1;
            string ccmSource = J.S(c, "Sccm.UpdateSource.ContentLocation");
            if (sccmInstalled)
            {
                if (string.IsNullOrEmpty(wuServer) || !useWu)
                {
                    Add(Sev.High, "Windows Update policy", "WSUS policy (WUServer / UseWUServer) is not set",
                        "SCCM writes these as local policy when the client is assigned a software update point. Missing values mean the SUP was never assigned, or a GPO/MDM policy removed them." +
                        (ccmSource != null ? " CCM_UpdateSource points to " + ccmSource + "." : ""),
                        "Check boundary groups include a SUP, that WUAHandler.log shows 'Enabling WUA Managed server policy', and that no GPO sets 'Specify intranet Microsoft update service location' to Disabled.");
                }
                else if (!string.IsNullOrEmpty(ccmSource) && !SameServer(wuServer, ccmSource))
                {
                    Add(Sev.High, "Windows Update policy", "WSUS server in policy differs from the SCCM software update point",
                        "Policy WUServer = " + wuServer + ", but the SCCM client expects " + ccmSource + ". A domain GPO is overriding SCCM (WUAHandler logs 'Group policy settings were overwritten by a higher authority').",
                        "Remove 'Specify intranet Microsoft update service location' from GPOs that apply to SCCM clients (gpresult /h on the device shows which GPO), then gpupdate /force and run the Software Updates Scan Cycle.");
                }
            }

            var regPolOk = J.BN(c, "WindowsUpdate.RegistryPol.HeaderOk");
            if (regPolOk == false)
                Add(Sev.High, "Windows Update policy", "Local Group Policy file Registry.pol looks corrupt",
                    "C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol does not start with the 'PReg' signature. SCCM can't write its WUA policy into a corrupt file (WUAHandler: 'Failed to Add Update Source', 0x80004005).",
                    "Rename Registry.pol to Registry.pol.old, run gpupdate /force, restart CcmExec, then trigger a Software Updates Scan Cycle.");

            var wufbKeys = new List<string>();
            foreach (string k in new[] { "SetPolicyDrivenUpdateSourceForQualityUpdates", "SetPolicyDrivenUpdateSourceForFeatureUpdates", "SetPolicyDrivenUpdateSourceForDriverUpdates", "SetPolicyDrivenUpdateSourceForOtherUpdates" })
            {
                int? v = J.I(pol, k);
                if (v.HasValue && v.Value == 0) wufbKeys.Add(k.Replace("SetPolicyDrivenUpdateSourceFor", "") + " = Windows Update (cloud)");
            }
            if (sccmInstalled && wufbKeys.Count > 0)
                Add(Sev.High, "Windows Update policy", "Some update types are set to come from Windows Update instead of WSUS/SCCM",
                    string.Join("; ", wufbKeys) + ". Those update types won't come from your SUP.",
                    "If SCCM should own updates, set 'Specify source service for specific classes of Windows Updates' to WSUS for each class (or remove the setting), or check the co-management Windows Update policies workload.");

            bool deferPolicies = pol != null && pol.Keys.Any(k => k.StartsWith("DeferQualityUpdates", StringComparison.OrdinalIgnoreCase) || k.StartsWith("DeferFeatureUpdates", StringComparison.OrdinalIgnoreCase) || k.StartsWith("PauseQualityUpdates", StringComparison.OrdinalIgnoreCase));
            if (sccmInstalled && deferPolicies && J.I(pol, "DisableDualScan") != 1 && wufbKeys.Count == 0)
                Add(Sev.Medium, "Windows Update policy", "Windows Update for Business deferral policies are set alongside WSUS",
                    "Deferral/pause policies with a WSUS server can trigger 'dual scan', where the device scans Microsoft Update instead of your SUP.",
                    "Remove WUfB deferral policies for SCCM-managed devices or enable 'Do not allow update deferral policies to cause scans against Windows Update'.");

            if (J.I(pol, "TargetReleaseVersion") == 1)
                r.Notes.Add("Feature version is pinned by policy: TargetReleaseVersionInfo = " + J.S(pol, "TargetReleaseVersionInfo") + " (ProductVersion " + J.S(pol, "ProductVersion") + ").");
            var mdm = J.Dict(c, "WindowsUpdate.MdmUpdatePolicy");
            if (mdm != null && mdm.Count > 0)
                r.Notes.Add("MDM (Intune) Windows Update policies are present on the device (" + string.Join(", ", mdm.Keys.Where(k => !k.EndsWith("_ProviderSet") && !k.EndsWith("_WinningProvider")).Take(8)) + "). If co-managed, check who owns the Windows Update policies workload.");

            // History
            var hist = J.A(c, "WindowsUpdate.History").Select(h => new
            {
                Date = J.T(h, "Date"),
                Title = J.S(h, "Title") ?? "",
                KB = J.S(h, "KB"),
                Result = J.S(h, "Result"),
                HResult = J.S(h, "HResult"),
                Client = J.S(h, "ClientApplicationID")
            }).ToList();
            DateTime windowStart = refNow.AddDays(-days);

            var fails = hist.Where(h => h.Date.HasValue && h.Date.Value >= windowStart && (h.Result == "Failed" || h.Result == "Aborted") && !IsDefinition(h.Title)).ToList();
            if (fails.Count > 0)
            {
                var groups = fails.GroupBy(h => (h.KB ?? Short(h.Title, 60)) + "|" + h.HResult)
                                  .Select(g => new { Key = g.Key, Count = g.Count(), Last = g.Max(x => x.Date), First = g.First() })
                                  .OrderByDescending(g => g.Count).Take(10).ToList();
                var lines = groups.Select(g => (g.First.KB ?? Short(g.First.Title, 60)) + ": " + (ErrorCodes.Describe(g.First.HResult) ?? g.First.HResult) + " x" + g.Count + ", last " + J.Fmt(g.Last));
                Add(Sev.High, "Windows Update", Plural(fails.Count, "update install failure") + " in the last " + days + " days",
                    string.Join(" | ", lines),
                    FixForCodes(fails.Select(f => f.HResult)));
            }

            var oks = hist.Where(h => (h.Result == "Succeeded" || h.Result == "SucceededWithErrors") && !IsDefinition(h.Title) && h.Date.HasValue).ToList();
            DateTime? lastOk = oks.Count > 0 ? oks.Max(h => h.Date) : null;
            if (hist.Count > 0)
            {
                if (!lastOk.HasValue)
                    Add(Sev.High, "Windows Update", "No successful update installs in Windows Update history",
                        "Only definition updates or failures were found in " + Plural(hist.Count, "history entry") + ".",
                        "Work through the SCCM scan/deployment findings; if the client scans fine, check content download (CAS.log) and install errors (WUAHandler.log).");
                else if ((refNow - lastOk.Value).TotalDays > 45)
                    Add(Sev.High, "Windows Update", "Last successful update install was " + (int)(refNow - lastOk.Value).TotalDays + " days ago",
                        "Last success: " + J.Fmt(lastOk), "See SCCM scan and deployment findings.");
            }
            var lastCu = hist.Where(h => h.Title.IndexOf("Cumulative Update for Windows", StringComparison.OrdinalIgnoreCase) >= 0 && h.Result == "Succeeded")
                             .OrderByDescending(h => h.Date).FirstOrDefault();
            if (lastCu != null) r.Notes.Add("Last cumulative update installed: " + lastCu.Title + " on " + J.Fmt(lastCu.Date) + " via " + (lastCu.Client ?? "?") + ".");

            // Reboot, uptime, disk, clock
            if (J.B(c, "PendingReboot.Any"))
            {
                double up = J.D(c, "System.UptimeDays") ?? 0;
                string reasons = string.Join(", ", J.A(c, "PendingReboot.Reasons").Select(x => Convert.ToString(x, CultureInfo.InvariantCulture)));
                Add(up > 7 ? Sev.High : Sev.Medium, "Restart", "Restart pending (" + reasons + ")",
                    "Uptime " + up.ToString("0.#", CultureInfo.InvariantCulture) + " days. Windows and SCCM won't install further updates until the pending restart completes.",
                    "Restart the device. If it keeps coming back, check deployments with 'Suppress restart' and the RebootCoordinator.log.");
            }
            double? upDays = J.D(c, "System.UptimeDays");
            if (upDays.HasValue && upDays.Value > 30 && !J.B(c, "PendingReboot.Any"))
                Add(Sev.Medium, "Restart", "Device hasn't restarted in " + (int)upDays.Value + " days", "Long uptime often hides a stuck servicing operation.", "Restart and re-run the scan cycle.");

            double? free = J.D(c, "System.SystemDriveFreeGB");
            if (free.HasValue && free.Value < 20)
                Add(free.Value < 10 ? Sev.High : Sev.Medium, "Disk", "Only " + free.Value.ToString("0.#", CultureInfo.InvariantCulture) + " GB free on " + (J.S(c, "System.SystemDrive") ?? "C:"),
                    "Cumulative updates need roughly 10-20 GB free to download, stage and install (plus the SCCM cache).",
                    "Free space: Disk Cleanup (Windows Update Cleanup), clear old ccmcache content, DISM /Online /Cleanup-Image /StartComponentCleanup.");

            double? sdMb = J.D(c, "WindowsUpdate.SoftwareDistributionSizeMB");
            if (sdMb.HasValue && sdMb.Value > 10240)
                Add(Sev.Low, "Disk", "SoftwareDistribution folder is " + (sdMb.Value / 1024).ToString("0.#", CultureInfo.InvariantCulture) + " GB", "Large stale download/datastore content.", "Stop wuauserv and bits, rename C:\\Windows\\SoftwareDistribution, restart services, run a scan.");

            string tsrc = J.S(c, "TimeSync.Source");
            if (tsrc != null && (tsrc.IndexOf("Local CMOS", StringComparison.OrdinalIgnoreCase) >= 0 || tsrc.IndexOf("Free-running", StringComparison.OrdinalIgnoreCase) >= 0))
                Add(Sev.Medium, "Time", "Clock is not syncing from a time source (" + tsrc + ")",
                    "Clock drift breaks Kerberos and TLS/certificate validation to the MP and SUP.", "w32tm /resync /rediscover; check domain hierarchy time sync and UDP 123.");

            // DISM
            if (J.B(c, "WindowsUpdate.Dism.Ran"))
            {
                string dism = J.S(c, "WindowsUpdate.Dism.Output") ?? "";
                if (dism.IndexOf("repairable", StringComparison.OrdinalIgnoreCase) >= 0 || dism.IndexOf("corrupt", StringComparison.OrdinalIgnoreCase) >= 0 && dism.IndexOf("No component store corruption", StringComparison.OrdinalIgnoreCase) < 0)
                    Add(Sev.High, "Servicing", "Component store corruption detected (DISM)", Short(dism, 400),
                        "DISM /Online /Cleanup-Image /RestoreHealth (add /Source:wim:<install.wim>:1 /LimitAccess if the device can't reach Windows Update), then sfc /scannow.");
                else if (dism.IndexOf("No component store corruption", StringComparison.OrdinalIgnoreCase) >= 0)
                    r.Notes.Add("DISM CheckHealth: no component store corruption detected.");
            }

            // WUA scan in the bundle
            string scanErr = J.S(c, "WindowsUpdate.Scan.Error");
            if (scanErr != null)
                Add(Sev.Medium, "Windows Update", "Windows Update scan during collection failed (" + J.S(c, "WindowsUpdate.Scan.Mode") + ")",
                    (ErrorCodes.Describe(J.S(c, "WindowsUpdate.Scan.ErrorCode")) ?? "") + " " + Short(scanErr, 300),
                    FixForCodes(new[] { J.S(c, "WindowsUpdate.Scan.ErrorCode") }));
            if (J.B(c, "WindowsUpdate.Scan.Ran"))
            {
                var missing = J.A(c, "WindowsUpdate.Scan.Missing");
                int crit = missing.Count(m => string.Equals(J.S(m, "Severity"), "Critical", StringComparison.OrdinalIgnoreCase));
                if (missing.Count > 0)
                    Add(crit > 0 ? Sev.High : Sev.Medium, "Windows Update", Plural(missing.Count, "missing update") + " found by the " + J.S(c, "WindowsUpdate.Scan.Mode") + " scan" + (crit > 0 ? " (" + crit + " critical)" : ""),
                        string.Join("; ", missing.Take(8).Select(m => J.S(m, "KB") + " " + Short(J.S(m, "Title"), 80))),
                        "See 'Missing updates' below; compare with the SCCM server view to see if they are deployed.");
            }

            // Secure Boot certificate servicing (2026 certificate expiry)
            if (J.BN(c, "SecureBoot.Enabled") == true)
            {
                var sbs = J.Dict(c, "SecureBoot.Servicing");
                string status = J.S(sbs, "UEFICA2023Status");
                if (status != null && !string.Equals(status, "Updated", StringComparison.OrdinalIgnoreCase))
                    Add(Sev.Medium, "Secure Boot", "Secure Boot 2023 certificate update not complete (status: " + status + ")",
                        "Microsoft's original Secure Boot certificates began expiring in 2026; devices need the 2023 CA certificates to keep receiving boot-component updates.",
                        "Make sure the latest cumulative update is installed and the device has restarted; follow Microsoft's Secure Boot certificate update guidance for your hardware.");
            }
        }

        private static bool IsDefinition(string title)
        {
            if (string.IsNullOrEmpty(title)) return false;
            return title.IndexOf("Security Intelligence Update", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   title.IndexOf("Definition Update", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   title.IndexOf("KB2267602", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool SameServer(string a, string b)
        {
            try
            {
                var ua = new Uri(a.Trim());
                var ub = new Uri(b.Trim());
                string ha = ua.Host.Split('.')[0], hb = ub.Host.Split('.')[0];
                return string.Equals(ha, hb, StringComparison.OrdinalIgnoreCase) && ua.Port == ub.Port;
            }
            catch { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
        }

        private static string FixForCodes(IEnumerable<string> codes)
        {
            var set = new HashSet<uint>();
            foreach (string s in codes) { uint? u = ErrorCodes.ToCode(s); if (u.HasValue) set.Add(u.Value); }
            var tips = new List<string>();
            if (set.Contains(0x80244022) || set.Contains(0x8024401C) || set.Contains(0x8024401F) || set.Contains(0x80244010))
                tips.Add("SUP/WSUS is overloaded or its IIS app pool is stopping: raise WsusPool private memory limit (0 or 8 GB+) and queue length, run WSUS cleanup/decline superseded updates");
            if (set.Contains(0x8024402C) || set.Contains(0x80072EE2) || set.Contains(0x80072EFD) || set.Contains(0x80072EE7))
                tips.Add("Device can't reach the SUP: check DNS, proxy (netsh winhttp show proxy), firewall to port 8530/8531, VPN split tunnel");
            if (set.Contains(0x80072F8F) || set.Contains(0x800B0109))
                tips.Add("TLS/certificate failure: check the clock, TLS 1.2 settings, and the SUP certificate chain");
            if (set.Contains(0x80073712) || set.Contains(0x800F081F) || set.Contains(0x800F0831))
                tips.Add("Component store corruption: DISM /Online /Cleanup-Image /RestoreHealth then sfc /scannow");
            if (set.Contains(0x800F0922))
                tips.Add("Check free space on the EFI/recovery partitions and disconnect VPN during install");
            if (set.Contains(0x80070070))
                tips.Add("Free disk space");
            if (set.Contains(0x800704EC) || set.Contains(0x800711C7))
                tips.Add("Installer blocked by AppLocker/WDAC: allow ccmcache, CCM and SoftwareDistribution paths or Microsoft-signed publishers");
            if (set.Contains(0x80070643) || set.Contains(0x8024200B))
                tips.Add("Installer failure: check CBS.log / the update's MSI log; retry after a restart");
            if (set.Contains(0x80240022))
                tips.Add("All updates failed: look at the individual update errors in WUAHandler.log/UpdatesHandler.log");
            if (set.Contains(0x80244007))
                tips.Add("SOAP fault from WSUS: run WSUS cleanup/reindex; on the client reset SoftwareDistribution");
            if (tips.Count == 0)
                tips.Add("Look up the error in WUAHandler.log/UpdatesHandler.log and CBS.log; a reset of SoftwareDistribution and catroot2 followed by a scan cycle fixes many transient failures");
            return string.Join(". ", tips) + ".";
        }

        // ------------------------------------------------------------------ SCCM client
        private static readonly string[] EvalStates =
        {
            "None", "Available", "Submitted", "Detecting", "PreDownload", "Downloading", "WaitInstall", "Installing",
            "PendingSoftReboot", "PendingHardReboot", "WaitReboot", "Verifying", "InstallComplete", "Error",
            "WaitServiceWindow", "WaitUserLogon", "WaitUserLogoff", "WaitJobUserLogon", "WaitUserReconnect",
            "PendingUserLogoff", "PendingUpdate", "WaitingRetry", "WaitPresModeOff", "WaitForOrchestration"
        };

        internal static string EvalStateName(int? s)
        {
            if (!s.HasValue) return null;
            return (s.Value >= 0 && s.Value < EvalStates.Length) ? EvalStates[s.Value] : s.Value.ToString(CultureInfo.InvariantCulture);
        }

        private static readonly Dictionary<string, string> SignatureFixes = new Dictionary<string, string>
        {
            { "SCAN_FAILED", "Decode the error code in WUAHandler.log/ScanAgent.log. 0x80244022/0x8024401C = SUP WSUS app pool problems; 0x8024402C/0x80072EE2 = name resolution, proxy or firewall to the SUP (8530/8531)." },
            { "GPO_CONFLICT", "Find the GPO that sets 'Specify intranet Microsoft update service location' (gpresult /h) and remove it from SCCM-managed devices, or make it match the SUP. Then gpupdate /force and run the Software Updates Scan Cycle." },
            { "WUA_SOURCE", "Usually a corrupt Registry.pol or broken WUA: rename C:\\Windows\\System32\\GroupPolicy\\Machine\\Registry.pol, gpupdate /force, reset SoftwareDistribution/catroot2, restart CcmExec, trigger a scan." },
            { "INSTALL_FAIL", "Check the error code in UpdatesHandler.log/WUAHandler.log and CBS.log. Common fixes: free disk space, DISM /RestoreHealth, restart and retry, check AppLocker blocks." },
            { "NO_SERVICE_WINDOW", "Check maintenance windows on the device's collections (see SCCM server view). Make sure an 'All deployments' or 'Software updates' window exists and is long enough, or allow installs outside maintenance windows." },
            { "CONTENT", "Confirm the device's boundary group has a DP holding the update deployment package; check CAS.log, LocationServices.log and DataTransferService.log for the content ID." },
            { "MP_COMM", "Check MP health (mpcontrol.log on the MP), client certificate/PKI, proxy and firewall from the client to the MP; test http(s)://<MP>/sms_mp/.sms_aut?mplist." },
            { "CERT", "Check the client certificate in the LocalMachine\\SMS store (self-signed) or the PKI client auth cert; verify the clock and CRL access. Re-key: stop CcmExec, delete the SMS certificates, start CcmExec." },
            { "REGISTRATION", "The client isn't registered/approved: approve it in the console, verify boundary/site assignment, review ClientIDManagerStartup.log; reinstall if the identity is corrupt." },
            { "POLICY", "Trigger Machine Policy Retrieval & Evaluation; if it keeps failing, reset policy (SMS_Client ResetPolicy) and check PolicyAgent.log." },
            { "REBOOT", "Restart the device so pending updates can finish." },
            { "APPLOCKER", "Installers are blocked by AppLocker/WDAC (0x800704EC/0x800711C7). Add allow rules for C:\\Windows\\ccmcache\\*, C:\\Windows\\CCM\\* and C:\\Windows\\SoftwareDistribution\\Download\\* or Microsoft publisher rules for MSI/EXE/script." },
            { "WMI", "Check WMI: winmgmt /verifyrepository (salvage if inconsistent), then repair the client (ccmsetup /forceinstall or ccmrepair.exe)." },
            { "APP_FAIL", "Review AppEnforce.log for the exit code and the detection method of the failing application." }
        };

        private void AnalyzeSccmClient()
        {
            if (!sccmInstalled)
            {
                Add(Sev.Critical, "SCCM client", "ConfigMgr client is not installed (no CcmExec service)",
                    "Without the client the device never receives Software Center updates.",
                    "Install the client: ccmsetup.exe /mp:<MP FQDN> SMSSITECODE=<code> (or client push).");
                return;
            }
            if (J.BN(c, "Sccm.NamespaceOk") == false)
                Add(Sev.Critical, "SCCM client", "CCM WMI namespace is missing or broken", Short(J.S(c, "Sccm.NamespaceError"), 300),
                    "winmgmt /verifyrepository; if inconsistent winmgmt /salvagerepository; then ccmsetup.exe /forceinstall to rebuild the client.");

            string state = J.S(c, "Sccm.ServiceState");
            if (state != null && !string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase))
                Add(Sev.Critical, "SCCM client", "SMS Agent Host (CcmExec) is " + state, "The client does nothing while this service is stopped.", "Start-Service CcmExec; check System log events 7031/7034 for crashes.");

            if (string.IsNullOrEmpty(J.S(c, "Sccm.SiteCode")))
                Add(Sev.Critical, "SCCM client", "Client is not assigned to a site", "No AssignedSiteCode in the registry.", "Check boundary groups for site assignment, or reinstall with SMSSITECODE=<code>.");
            if (string.IsNullOrEmpty(J.S(c, "Sccm.ManagementPoint")))
                Add(Sev.High, "SCCM client", "Client has no current management point", "SMS_Authority.CurrentManagementPoint is empty.", "Check LocationServices.log and boundary groups; confirm the MP is healthy.");

            var sum = J.Dict(c, "Sccm.SumConfig");
            if (J.S(c, "Sccm.NamespaceOk") != null && sum == null)
                Add(Sev.High, "SCCM client", "Software Updates client settings policy not found", "CCM_SoftwareUpdatesClientConfig is missing from ActualConfig; the client may not have received machine policy.", "Trigger Machine Policy Retrieval; check PolicyAgent.log and client settings deployment.");
            else if (sum != null)
            {
                bool? enabled = J.BN(sum, "ComponentEnabled") ?? J.BN(sum, "Enabled");
                if (enabled == false)
                    Add(Sev.Critical, "SCCM client", "Software Updates are disabled in client settings", "CCM_SoftwareUpdatesClientConfig.ComponentEnabled = False.", "Enable 'Software Updates' in the client settings deployed to this device's collections.");
            }

            string source = J.S(c, "Sccm.UpdateSource.ContentLocation");
            if (J.S(c, "Sccm.NamespaceOk") != null && string.IsNullOrEmpty(source))
                Add(Sev.High, "SCCM client", "Client has no software update point (CCM_UpdateSource empty)", "The client hasn't been told which SUP to scan against.", "Check boundary groups include a SUP, the SUP role is healthy (WCM.log/WSUSCtrl.log), and LocationServices.log on the client.");

            // Scan recency from CCM logs
            DateTime? lastScan = J.T(c, "Sccm.LastSuccessfulScan");
            DateTime? lastFail = J.T(c, "Sccm.LastScanFailure");
            if (!lastScan.HasValue)
                Add(Sev.High, "SCCM client", "No successful software update scan in the last " + days + " days of CCM logs",
                    lastFail.HasValue ? "Last scan failure: " + J.Fmt(lastFail) + "." : "WUAHandler.log/ScanAgent.log show no completed scan.",
                    "Run the 'Software Updates Scan Cycle' action and read WUAHandler.log; see scan failure details below.");
            else if ((refNow - lastScan.Value).TotalDays > 7)
                Add(Sev.High, "SCCM client", "Last successful update scan was " + (int)(refNow - lastScan.Value).TotalDays + " days ago", "Last success " + J.Fmt(lastScan) + (lastFail.HasValue ? ", last failure " + J.Fmt(lastFail) : ""), "Trigger a scan cycle and check WUAHandler.log.");
            else
                r.Notes.Add("Last successful SCCM update scan: " + J.Fmt(lastScan) + ".");

            // Log signatures
            foreach (object s in J.A(c, "Sccm.LogSignatures"))
            {
                string id = J.S(s, "Id");
                if (id == null || id == "SCAN_OK") continue;
                int hits = J.I(s, "Hits") ?? J.I(s, "Count") ?? 0;
                string fix;
                SignatureFixes.TryGetValue(id, out fix);
                Add(Sev.Normalize(J.S(s, "Severity")), "SCCM logs", J.S(s, "Title") + " (" + hits + "x, last " + J.Fmt(J.T(s, "LastSeen")) + " in " + J.S(s, "LastLog") + ".log)",
                    Short(J.S(s, "Sample"), 400), fix);
            }

            var codes = J.Dict(c, "Sccm.LogErrorCodes");
            if (codes != null && codes.Count > 0)
            {
                var decoded = codes.OrderByDescending(kv => J.L(kv.Value, null) ?? 0).Take(8)
                    .Select(kv => (ErrorCodes.Describe(kv.Key) ?? kv.Key) + " x" + Convert.ToString(kv.Value, CultureInfo.InvariantCulture)).ToList();
                Add(Sev.Info, "SCCM logs", "Error codes seen in CCM logs (top " + decoded.Count + ")", string.Join(" | ", decoded), FixForCodes(codes.Keys));
            }

            string wsusLog = J.S(c, "Sccm.WsusUrlFromLog");
            if (!string.IsNullOrEmpty(wsusLog) && !string.IsNullOrEmpty(source) && !SameServer(wsusLog, source))
                r.Notes.Add("WUAHandler.log last referenced " + wsusLog + " while CCM_UpdateSource is " + source + ".");

            // Software Center updates
            var scu = J.A(c, "Sccm.SoftwareCenterUpdates");
            var errored = scu.Where(u => (J.I(u, "EvaluationState") ?? 0) == 13 || (J.L(u, "ErrorCode") ?? 0) != 0).ToList();
            if (errored.Count > 0)
                Add(Sev.High, "Software Center", Plural(errored.Count, "deployed update") + " in an error state in Software Center",
                    string.Join(" | ", errored.Take(8).Select(u => "KB" + J.S(u, "ArticleID") + " " + Short(J.S(u, "Name"), 60) + ": " + (ErrorCodes.Describe(J.S(u, "ErrorCode")) ?? EvalStateName(J.I(u, "EvaluationState"))))),
                    FixForCodes(errored.Select(u => J.S(u, "ErrorCode"))) + " Retry from Software Center or run the Software Updates Deployment Evaluation Cycle.");
            var waitingMw = scu.Count(u => J.I(u, "EvaluationState") == 14);
            if (waitingMw > 0)
                Add(Sev.Medium, "Software Center", Plural(waitingMw, "update") + " waiting for a maintenance window", "EvaluationState = WaitServiceWindow.", SignatureFixes["NO_SERVICE_WINDOW"]);
            var waitingReboot = scu.Count(u => { int s = J.I(u, "EvaluationState") ?? 0; return s == 8 || s == 9 || s == 10; });
            if (waitingReboot > 0)
                Add(Sev.Medium, "Software Center", Plural(waitingReboot, "update") + " installed and waiting for a restart", null, "Restart the device to finish installation.");
            if (scu.Count > 0)
                r.Notes.Add("Software Center shows " + Plural(scu.Count, "deployed update") + ": " +
                    string.Join(", ", scu.GroupBy(u => EvalStateName(J.I(u, "EvaluationState")) ?? "?").Select(g => g.Key + " " + g.Count())) + ".");

            // Client scan view vs Software Center
            var status = J.A(c, "Sccm.UpdateStatus");
            int clientMissing = status.Count(s => string.Equals(J.S(s, "Status"), "Missing", StringComparison.OrdinalIgnoreCase));
            if (clientMissing > 0 && scu.Count == 0)
                Add(Sev.Medium, "SCCM client", "Client scan reports " + Plural(clientMissing, "missing update") + " but none are deployed to it",
                    "CCM_UpdateStatus lists them as Missing, yet Software Center has no update deployments.",
                    "Deploy the needed software update groups to a collection containing this device (see SCCM server view), or check that the device is in the expected collections.");

            // Maintenance windows (client view)
            var mws = J.A(c, "Sccm.ServiceWindows");
            if (mws.Count > 0)
            {
                bool applicable = mws.Any(w => { int t = J.I(w, "Type") ?? 0; return t == 1 || t == 4; });
                if (!applicable)
                    Add(Sev.Info, "Maintenance windows", "Device has maintenance windows, none of type 'All deployments' or 'Software updates'",
                        Plural(mws.Count, "window") + " found. Verify updates can install when you expect.", "Review the maintenance windows on the device's collections.");
                var shortOnes = mws.Where(w => { int t = J.I(w, "Type") ?? 0; long d = J.L(w, "Duration") ?? 0; return (t == 1 || t == 4) && d > 0 && d < 3600; }).ToList();
                if (shortOnes.Count > 0)
                    Add(Sev.Low, "Maintenance windows", Plural(shortOnes.Count, "maintenance window") + " shorter than 60 minutes",
                        "Cumulative updates default to a 60+ minute max run time and won't start in a shorter window.", "Lengthen the windows or lower the update's maximum run time.");
            }

            // Cache
            double? cacheMb = J.D(c, "Sccm.Cache.SizeMB");
            if (cacheMb.HasValue && cacheMb.Value > 0 && cacheMb.Value < 10240)
                Add(Sev.Low, "SCCM client", "ccmcache is only " + (cacheMb.Value / 1024).ToString("0.#", CultureInfo.InvariantCulture) + " GB",
                    "Feature updates and large cumulative updates can exceed a small cache.", "Raise the client cache size in client settings (10-25 GB is common).");

            // CCMEval
            string evalSummary = J.S(c, "Sccm.CcmEval.Summary");
            var failedChecks = J.A(c, "Sccm.CcmEval.Checks").Where(k =>
            {
                string res = J.S(k, "Result") ?? "";
                return res.Length > 0 && !res.Equals("Passed", StringComparison.OrdinalIgnoreCase) && !res.Equals("Not Applicable", StringComparison.OrdinalIgnoreCase);
            }).ToList();
            if (failedChecks.Count > 0 || (evalSummary != null && !evalSummary.Equals("Passed", StringComparison.OrdinalIgnoreCase)))
                Add(Sev.High, "SCCM client", "CCMEval health check: " + (evalSummary ?? "failures"),
                    string.Join(" | ", failedChecks.Take(8).Select(k => Short(J.S(k, "Description"), 80) + " = " + J.S(k, "Result"))),
                    "Review CcmEval.log; repair the client (ccmrepair.exe or ccmsetup /forceinstall).");

            // Applications
            var apps = J.A(c, "Sccm.Applications");
            var failedApps = apps.Where(a => (J.L(a, "ErrorCode") ?? 0) != 0).ToList();
            if (failedApps.Count > 0)
                Add(Sev.Medium, "Software Center", Plural(failedApps.Count, "application") + " with install errors in Software Center",
                    string.Join(" | ", failedApps.Take(8).Select(a => J.S(a, "Name") + ": " + (ErrorCodes.Describe(J.S(a, "ErrorCode")) ?? J.S(a, "ErrorCode")))),
                    SignatureFixes["APP_FAIL"]);

            // Co-management
            if (J.B(c, "Sccm.CoManagement.IntuneEnrolled"))
                r.Notes.Add("Device is MDM-enrolled (co-managed" + (J.S(c, "Sccm.CoManagement.CoManagementFlags") != null ? ", flags " + J.S(c, "Sccm.CoManagement.CoManagementFlags") : "") +
                            "). If the 'Windows Update policies' workload is moved to Intune, SCCM software update deployments stop applying.");
        }

        // ------------------------------------------------------------------ Events
        private sealed class Ev
        {
            public string Log;
            public string Provider;
            public string Message;
            public string Tag;
            public int Id;
            public int Level;
            public DateTime? Time;
        }

        private void AnalyzeEvents()
        {
            var evs = J.A(c, "Events").Select(e => new Ev
            {
                Log = J.S(e, "Log"),
                Provider = J.S(e, "Provider") ?? "",
                Message = J.S(e, "Message") ?? "",
                Tag = J.S(e, "Tag"),
                Id = J.I(e, "Id") ?? 0,
                Level = J.I(e, "Level") ?? 4,
                Time = J.T(e, "Time")
            }).ToList();
            if (evs.Count == 0) return;

            // Windows Update client install failures (event 20) / download failures (31)
            var wu20 = evs.Where(e => e.Provider.IndexOf("WindowsUpdateClient", StringComparison.OrdinalIgnoreCase) >= 0 && e.Id == 20).ToList();
            if (wu20.Count > 0)
            {
                var codes = wu20.SelectMany(e => ErrorCodes.FindCodes(e.Message)).GroupBy(x => x).OrderByDescending(g => g.Count()).Take(5)
                                .Select(g => (ErrorCodes.Describe(g.Key) ?? g.Key) + " x" + g.Count());
                Add(Sev.High, "Event log", Plural(wu20.Count, "Windows Update installation failure") + " (WindowsUpdateClient event 20)",
                    "Latest: " + Short(wu20.OrderByDescending(e => e.Time).First().Message, 250) + " | Codes: " + string.Join(", ", codes),
                    FixForCodes(wu20.SelectMany(e => ErrorCodes.FindCodes(e.Message))));
            }
            var wu31 = evs.Count(e => e.Provider.IndexOf("WindowsUpdateClient", StringComparison.OrdinalIgnoreCase) >= 0 && e.Id == 31);
            if (wu31 > 0)
                Add(Sev.Medium, "Event log", Plural(wu31, "Windows Update download failure") + " (event 31)", null, "Check BITS, disk space, and DP/SUP reachability.");

            // Service crashes / start failures for update-related services
            string[] svcWords = { "Windows Update", "SMS Agent Host", "Background Intelligent Transfer", "Cryptographic Services", "Windows Management Instrumentation", "Windows Modules Installer", "Windows Installer", "Update Orchestrator" };
            var scm = evs.Where(e => e.Provider.Equals("Service Control Manager", StringComparison.OrdinalIgnoreCase) &&
                                     new[] { 7000, 7009, 7011, 7022, 7023, 7024, 7031, 7034 }.Contains(e.Id) &&
                                     svcWords.Any(w => e.Message.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
            if (scm.Count > 0)
                Add(Sev.High, "Event log", Plural(scm.Count, "service failure") + " for update-related services",
                    string.Join(" | ", scm.OrderByDescending(e => e.Time).Take(5).Select(e => J.Fmt(e.Time) + " " + e.Id + ": " + Short(e.Message, 140))),
                    "Investigate the crashing service (Application log for faulting module); repair WMI or the SCCM client if CcmExec/Winmgmt crash repeatedly.");

            // Disk / file system
            var disk = evs.Where(e => (e.Provider.Equals("disk", StringComparison.OrdinalIgnoreCase) && (e.Id == 7 || e.Id == 51 || e.Id == 153)) ||
                                      (e.Provider.IndexOf("Ntfs", StringComparison.OrdinalIgnoreCase) >= 0 && (e.Id == 55 || e.Id == 98 || e.Id == 140))).ToList();
            if (disk.Count > 0)
                Add(Sev.High, "Event log", Plural(disk.Count, "disk or file system error"), Short(disk.OrderByDescending(e => e.Time).First().Message, 250),
                    "Check disk health (chkdsk /scan, SMART/vendor diagnostics). Failing storage causes servicing corruption.");

            // Unexpected shutdowns
            var crashes = evs.Count(e => (e.Id == 41 && e.Provider.IndexOf("Kernel-Power", StringComparison.OrdinalIgnoreCase) >= 0) || (e.Id == 6008 && e.Provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase)));
            if (crashes >= 3)
                Add(Sev.Medium, "Event log", Plural(crashes, "unexpected shutdown") + " in " + days + " days", "Power loss or crashes during servicing can leave updates half-installed.", "Check power settings, BSOD dumps and hardware.");

            // Domain / time
            if (evs.Any(e => e.Id == 5719 && e.Provider.IndexOf("NETLOGON", StringComparison.OrdinalIgnoreCase) >= 0))
                Add(Sev.Medium, "Event log", "Netlogon couldn't reach a domain controller (5719)", null, "Check network, DNS and the secure channel (Test-ComputerSecureChannel).");
            if (evs.Any(e => e.Provider.IndexOf("Time-Service", StringComparison.OrdinalIgnoreCase) >= 0 && e.Level <= 3))
                Add(Sev.Low, "Event log", "Windows Time service warnings", null, "w32tm /query /status; resync with the domain hierarchy.");

            // AppLocker
            var blocked = evs.Where(e => e.Provider.IndexOf("AppLocker", StringComparison.OrdinalIgnoreCase) >= 0 && (e.Id == 8004 || e.Id == 8007)).ToList();
            var audited = evs.Where(e => e.Provider.IndexOf("AppLocker", StringComparison.OrdinalIgnoreCase) >= 0 && (e.Id == 8003 || e.Id == 8006)).ToList();
            if (blocked.Count > 0)
            {
                var updRelated = blocked.Where(e => Regex.IsMatch(e.Message, @"ccmcache|\\CCM\\|SoftwareDistribution|ccmsetup|\\Temp\\", RegexOptions.IgnoreCase)).ToList();
                var paths = blocked.Select(e => { var m = Regex.Match(e.Message, @"^(.*?) was (prevented|not allowed)"); return m.Success ? m.Groups[1].Value : Short(e.Message, 120); })
                                   .GroupBy(x => x, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).Take(6).Select(g => g.Key + " x" + g.Count());
                Add(updRelated.Count > 0 ? Sev.High : Sev.Medium, "AppLocker", Plural(blocked.Count, "file") + " blocked by AppLocker" + (updRelated.Count > 0 ? " (" + updRelated.Count + " from SCCM/Windows Update paths)" : ""),
                    string.Join(" | ", paths), SignatureFixes["APPLOCKER"]);
            }
            if (audited.Count > 0)
                r.Notes.Add("AppLocker audit mode would have blocked " + Plural(audited.Count, "file") + " (events 8003/8006). Check these before enforcing.");

            var msiFail = evs.Where(e => e.Provider.Equals("MsiInstaller", StringComparison.OrdinalIgnoreCase) &&
                                         (e.Id == 11708 || (e.Id == 1033 && !Regex.IsMatch(e.Message, @"(status|Status):\s*0\b")))).ToList();
            if (msiFail.Count > 0)
                Add(Sev.Medium, "Event log", Plural(msiFail.Count, "MSI install failure"), string.Join(" | ", msiFail.OrderByDescending(e => e.Time).Take(4).Select(e => Short(e.Message, 160))),
                    "Check AppEnforce.log for the matching deployment and the MSI verbose log.");

            var setupErr = evs.Where(e => e.Tag == "Setup" && e.Level <= 2).ToList();
            if (setupErr.Count > 0)
                Add(Sev.Medium, "Event log", Plural(setupErr.Count, "servicing error") + " in the Setup log", string.Join(" | ", setupErr.Take(4).Select(e => Short(e.Message, 160))), "Review CBS.log around these times; run DISM /RestoreHealth.");

            // Top error groups for the report
            var groups = evs.Where(e => e.Level >= 1 && e.Level <= 2)
                            .GroupBy(e => e.Log + "|" + e.Provider + "|" + e.Id)
                            .OrderByDescending(x => x.Count()).Take(25).ToList();
            foreach (var grp in groups)
            {
                var latest = grp.OrderByDescending(e => e.Time).First();
                r.EventGroups.Add(new Dictionary<string, string>
                {
                    { "Log", latest.Log }, { "Provider", latest.Provider }, { "Id", latest.Id.ToString(CultureInfo.InvariantCulture) },
                    { "Count", grp.Count().ToString(CultureInfo.InvariantCulture) }, { "Last", J.Fmt(latest.Time) }, { "Sample", Short(latest.Message, 220) }
                });
            }
        }

        // ------------------------------------------------------------------ Connectivity
        private void AnalyzeConnectivity()
        {
            foreach (object t in J.A(c, "Network.Connectivity"))
            {
                string purpose = J.S(t, "Purpose") ?? "";
                if (purpose.IndexOf("informational", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                string host = J.S(t, "Host"), port = J.S(t, "Port"), http = J.S(t, "Http"), err = J.S(t, "Error");
                string sevFail = likelyOffline ? Sev.Info : Sev.High;
                if (!J.B(t, "DnsOk"))
                    Add(sevFail, "Connectivity", "Can't resolve " + host + " (" + purpose + ")", err, "Check DNS suffix/servers, VPN, and that the name in policy is correct.");
                else if (!J.B(t, "TcpOk"))
                    Add(sevFail, "Connectivity", "Can't connect to " + host + ":" + port + " (" + purpose + ")", err, "Check firewall rules (client and server), the IIS site on that port, and any proxy.");
                else if (http != null && (http.StartsWith("ERR") || Regex.IsMatch(http, @"HTTP [45]\d\d")))
                {
                    bool mpHttps403 = purpose.IndexOf("Management point", StringComparison.OrdinalIgnoreCase) >= 0 && http.Contains("403");
                    Add(mpHttps403 ? Sev.Info : Sev.Medium, "Connectivity", purpose + " answered " + http, host + ":" + port,
                        purpose.IndexOf("WSUS", StringComparison.OrdinalIgnoreCase) >= 0 || purpose.IndexOf("SUP", StringComparison.OrdinalIgnoreCase) >= 0
                            ? "HTTP 503 = WsusPool stopped; 404 = wrong port/vdir; 401/403 = permissions or proxy. Check IIS on the SUP."
                            : "Check MP health (mpcontrol.log) and whether the MP requires HTTPS/client certificates.");
                }
            }
        }

        // ------------------------------------------------------------------ SCCM server
        private void AnalyzeServer()
        {
            if (sccm == null)
            {
                r.Notes.Add("SCCM server comparison skipped (run with -SiteServer <SMS Provider> to compare with the site).");
                return;
            }
            r.ServerName = sccm.Server;
            r.SiteCode = sccm.SiteCode;
            r.SiteVersion = sccm.SiteVersion;
            if (!sccm.Connected)
            {
                r.ServerError = sccm.Error;
                Add(Sev.Medium, "SCCM server", "Could not query the SMS Provider " + sccm.Server, sccm.Error,
                    "Run as an account with at least Read-only Analyst rights, check DCOM/WMI firewall rules to the provider, or pass -SiteCode.");
                return;
            }

            string name = r.ComputerName;
            ServerView v = sccm.Inspect(name, r.CuPattern, r.LatestKb);
            r.Server = v;
            if (v.Error != null)
                Add(Sev.Medium, "SCCM server", "Part of the SMS Provider query failed", v.Error, "Results below may be partial.");

            if (v.Records.Count == 0)
            {
                Add(Sev.Critical, "SCCM server", "Device " + name + " was not found in SCCM",
                    "No SMS_R_System record. The client has never registered, was deleted, or is reporting under another name.",
                    "Check ClientIDManagerStartup.log and LocationServices.log on the client; verify discovery; reinstall the client if needed.");
                return;
            }
            if (v.Records.Count > 1)
                Add(Sev.High, "SCCM server", Plural(v.Records.Count, "SCCM record") + " exist for " + name,
                    string.Join(" | ", v.Records.Select(x => "ResourceId " + x["ResourceId"] + " client=" + x["Client"] + " obsolete=" + x["Obsolete"] + " GUID " + x["SMSUniqueIdentifier"])),
                    "Delete the obsolete/duplicate records. If several are active, the image may share an SMS GUID: run ccmsetup /forceinstall or delete SMSCFG.INI and the SMS certificates, then restart CcmExec.");

            string clientGuid = J.S(c, "Sccm.ClientId");
            if (clientGuid != null && v.SmsGuid != null && !string.Equals(clientGuid, v.SmsGuid, StringComparison.OrdinalIgnoreCase))
                Add(Sev.High, "SCCM server", "SCCM record GUID doesn't match the client's GUID",
                    "Client: " + clientGuid + " / Site: " + v.SmsGuid + ". The device's state messages and inventory land on another record (or nowhere).",
                    "Delete the stale record and trigger a Discovery Data Collection Cycle on the client; if the client GUID keeps changing, reinstall the client.");

            if (v.Combined != null)
            {
                Func<string, string> cv = k => { string x; return v.Combined.TryGetValue(k, out x) ? x : null; };
                if (cv("IsObsolete") == "True" || cv("IsObsolete") == "1")
                    Add(Sev.High, "SCCM server", "Device record is marked obsolete", null, "Delete the obsolete record; the active record should be recreated by the client.");
                if (cv("IsBlocked") == "True" || cv("IsBlocked") == "1")
                    Add(Sev.High, "SCCM server", "Device is blocked in SCCM", null, "Unblock the device in the console.");
                if (cv("IsApproved") == "0")
                    Add(Sev.High, "SCCM server", "Client is not approved", null, "Approve the client in the console (or adjust the site's approval setting).");
                if (cv("ClientActiveStatus") == "0")
                    Add(Sev.High, "SCCM server", "Site reports the client as inactive", "Client activity: last active " + cv("LastActiveTime") + ", last policy request " + cv("LastPolicyRequest") + ".", "Client isn't talking to the MP: see client MP communication findings.");
                DateTime? lastPolicy = J.ParseDate(cv("LastPolicyRequest"));
                if (lastPolicy.HasValue && (DateTime.Now - lastPolicy.Value).TotalDays > 7)
                    Add(Sev.High, "SCCM server", "Site hasn't received a policy request from this device in " + (int)(DateTime.Now - lastPolicy.Value).TotalDays + " days",
                        "Last policy request " + J.Fmt(lastPolicy) + " via " + cv("LastMPServerName") + ".", "Check client-to-MP communication (CcmMessaging.log, LocationServices.log) and whether the device is online.");
                DateTime? lastHw = J.ParseDate(cv("LastHardwareScan"));
                if (lastHw.HasValue && (DateTime.Now - lastHw.Value).TotalDays > 14)
                    Add(Sev.Medium, "SCCM server", "Last hardware inventory received " + (int)(DateTime.Now - lastHw.Value).TotalDays + " days ago", null, "Inventory and state messages share the same path to the MP; check MP communication.");
            }

            // Client version vs site
            string clientVer = J.S(c, "Sccm.ClientVersion");
            if (clientVer != null && sccm.SiteVersion != null)
            {
                Version cvv = Ver.Parse(clientVer), sv = Ver.Parse(sccm.SiteVersion);
                if (cvv != null && sv != null && cvv.Build < sv.Build)
                {
                    Row("ConfigMgr client", clientVer, "site " + sccm.SiteVersion, "Older than site", "Upgrade the client (automatic client upgrade or client push)", Sev.Medium);
                    Add(Sev.Medium, "SCCM client", "ConfigMgr client " + clientVer + " is older than the site (" + sccm.SiteVersion + ")", null,
                        "Enable automatic client upgrade in Hierarchy Settings or push the client.");
                }
                else Row("ConfigMgr client", clientVer, "site " + sccm.SiteVersion, "Current", "None", Sev.OK);
            }

            // Deployments, compliance
            if (v.Deployments.Count == 0)
                Add(Sev.High, "SCCM server", "No software update deployments target any collection this device is in",
                    "Device is in " + Plural(v.Collections.Count, "collection") + ".", "Add the device to a collection that receives your monthly SUG/ADR deployment.");

            if (!v.LastStatusCheck.HasValue)
                Add(Sev.High, "SCCM server", "Site has no update compliance data for this device",
                    "SMS_UpdateComplianceStatus has no rows: the client has never sent scan results (state messages).",
                    "Fix the client scan first; then run 'Software Updates Scan Cycle' and check StateMessage.log.");
            else if ((DateTime.Now - v.LastStatusCheck.Value).TotalDays > 7)
                Add(Sev.High, "SCCM server", "Site's latest update scan result from this device is " + (int)(DateTime.Now - v.LastStatusCheck.Value).TotalDays + " days old",
                    "Last status check " + J.Fmt(v.LastStatusCheck) + ".", "The client isn't scanning or isn't delivering state messages; see client scan findings.");

            var deployedMissing = v.Required.Where(u => u.DeployedToDevice && !u.IsExpired).ToList();
            var notDeployed = v.Required.Where(u => !u.DeployedToDevice && !u.IsExpired && !u.IsSuperseded).ToList();
            if (deployedMissing.Count > 0)
                Add(Sev.High, "SCCM server", Plural(deployedMissing.Count, "deployed update") + " required but not installed (site view)",
                    string.Join(" | ", deployedMissing.Take(10).Select(u => "KB" + u.Article + " " + Short(u.Title, 70) + (u.LastError != null ? " (" + (ErrorCodes.Describe(u.LastError) ?? u.LastError) + ")" : ""))),
                    "These are deployed to the device, so this is a client-side install problem: work through the client findings (scan, content, maintenance window, restart, install errors).");
            if (notDeployed.Count > 0)
                Add(Sev.Medium, "SCCM server", Plural(notDeployed.Count, "required update") + " not deployed to this device",
                    string.Join(" | ", notDeployed.Take(10).Select(u => "KB" + u.Article + " " + Short(u.Title, 70))),
                    "Add them to a software update group deployed to one of this device's collections (or adjust the ADR criteria).");

            // Microsoft's latest CU vs the site catalog
            if (r.LatestKb != null)
            {
                var inCat = v.LatestMicrosoftKbInCatalog ?? new List<ServerUpdate>();
                if (inCat.Count == 0)
                    Add(Sev.High, "SCCM server", "Latest Microsoft cumulative update " + r.LatestKb + " is not in the SCCM catalog for " + (r.CuPattern ?? "this OS"),
                        "The SUP hasn't synchronized it, or the product/classification isn't selected.",
                        "Check SUP sync (wsyncmgr.log, WCM.log), that the OS product (e.g. 'Windows 11') and 'Security Updates' classification are selected, and run a sync.");
                else
                {
                    ServerUpdate e = inCat.First();
                    if (!e.IsDeployed)
                        Add(Sev.High, "SCCM server", r.LatestKb + " is in SCCM but not deployed anywhere", e.Title, "Add it to the monthly SUG / check that the ADR ran and its criteria match.");
                    else if (!e.DeployedToDevice)
                        Add(Sev.High, "SCCM server", r.LatestKb + " is deployed, but not to any collection containing this device", e.Title, "Check which collection the deployment targets and the device's membership.");
                    else
                        r.Notes.Add(r.LatestKb + " is deployed to this device (" + e.Title + ").");
                }
            }

            // Server-side maintenance windows
            if (v.MaintenanceWindows.Count > 0)
            {
                bool applicable = v.MaintenanceWindows.Any(w => (w["TypeId"] == "1" || w["TypeId"] == "4") && w["Enabled"] != "False");
                if (!applicable)
                    Add(Sev.Medium, "Maintenance windows", "Device's collections have maintenance windows, but none for all deployments or software updates",
                        string.Join(" | ", v.MaintenanceWindows.Take(6).Select(w => w["Collection"] + ": " + w["Name"] + " (" + w["Type"] + ")")),
                        "Add a 'Software updates' or 'All deployments' maintenance window, or allow the deployment to install outside maintenance windows.");
            }
        }

        // ------------------------------------------------------------------ WSUS
        private void AnalyzeWsus()
        {
            if (string.IsNullOrEmpty(opt.WsusServer)) return;
            string err;
            string fqdn = J.S(c, "System.Fqdn");
            var w = WsusCheck.Lookup(opt.WsusServer, opt.WsusPort, opt.WsusSsl, fqdn, r.ComputerName, out err);
            r.Wsus = w;
            r.WsusError = err;
            if (err != null) { Add(Sev.Info, "WSUS", "WSUS check not available", err, null); return; }
            if (w == null) return;
            if (w["Found"] != "True")
            {
                Add(Sev.Medium, "WSUS", "Device not found in WSUS " + opt.WsusServer,
                    "WSUS creates the computer object the first time the device scans successfully.", "Fix the client scan (see SCCM client findings).");
                return;
            }
            string lr;
            DateTime? last = w.TryGetValue("LastReportedStatusTime", out lr) ? J.ParseDate(lr) : null;
            if (last.HasValue && (DateTime.Now - last.Value).TotalDays > 7)
                Add(Sev.High, "WSUS", "Device last reported to WSUS " + (int)(DateTime.Now - last.Value).TotalDays + " days ago", "Last reported " + J.Fmt(last) + ".", "The WUA scan isn't completing; see scan failures.");
            string failed;
            if (w.TryGetValue("FailedCount", out failed) && failed != null && failed != "0")
                Add(Sev.Medium, "WSUS", "WSUS reports " + failed + " failed update(s) for this device", null, "Compare with the Windows Update history failures above.");
        }

        // ------------------------------------------------------------------ Missing updates (merged)
        private void BuildMissing()
        {
            var map = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            Action<string, string, string, string, string> add = (kb, title, source, severity, extra) =>
            {
                string key = !string.IsNullOrEmpty(kb) ? kb : (title ?? "?");
                Dictionary<string, string> row;
                if (!map.TryGetValue(key, out row))
                {
                    row = new Dictionary<string, string> { { "KB", kb }, { "Title", title }, { "Sources", source }, { "Severity", severity }, { "Notes", extra } };
                    map[key] = row;
                }
                else
                {
                    if (row["Sources"].IndexOf(source, StringComparison.OrdinalIgnoreCase) < 0) row["Sources"] += "; " + source;
                    if (string.IsNullOrEmpty(row["Severity"])) row["Severity"] = severity;
                    if (!string.IsNullOrEmpty(extra)) row["Notes"] = string.IsNullOrEmpty(row["Notes"]) ? extra : row["Notes"] + "; " + extra;
                }
            };

            string scanMode = J.S(c, "WindowsUpdate.Scan.Mode");
            foreach (object m in J.A(c, "WindowsUpdate.Scan.Missing"))
                add(J.S(m, "KB"), J.S(m, "Title"), "WUA scan (" + scanMode + ")", J.S(m, "Severity"), null);

            foreach (object s in J.A(c, "Sccm.UpdateStatus"))
            {
                if (!string.Equals(J.S(s, "Status"), "Missing", StringComparison.OrdinalIgnoreCase)) continue;
                string art = J.S(s, "Article");
                add(string.IsNullOrEmpty(art) ? null : "KB" + art, J.S(s, "Title"), "SCCM client scan", null, null);
            }

            foreach (object u in J.A(c, "Sccm.SoftwareCenterUpdates"))
            {
                string art = J.S(u, "ArticleID");
                int? es = J.I(u, "EvaluationState");
                if (es == 12) continue; // InstallComplete
                add(string.IsNullOrEmpty(art) ? null : "KB" + art, J.S(u, "Name"), "Software Center", null,
                    "State " + EvalStateName(es) + (J.S(u, "Deadline") != null ? ", deadline " + J.Fmt(J.T(u, "Deadline")) : ""));
            }

            if (r.Server != null)
                foreach (ServerUpdate su in r.Server.Required)
                    add("KB" + su.Article, su.Title, "SCCM site (required)", null, su.DeployedToDevice ? "deployed to device" : "NOT deployed to device");

            r.Missing.AddRange(map.Values.OrderBy(x => x["KB"] ?? "zzz"));
        }

        // ------------------------------------------------------------------ Recent installs (merged)
        private void BuildRecentInstalls()
        {
            DateTime start = refNow.AddDays(-days);
            var list = new List<KeyValuePair<DateTime, Dictionary<string, string>>>();

            foreach (object h in J.A(c, "WindowsUpdate.History"))
            {
                DateTime? d = J.T(h, "Date");
                if (!d.HasValue || d.Value < start) continue;
                string client = J.S(h, "ClientApplicationID") ?? "";
                string via = client.Equals("CcmExec", StringComparison.OrdinalIgnoreCase) ? "SCCM / Software Center (WUA)" : "Windows Update Agent (" + (client.Length > 0 ? client : "?") + ")";
                string res = J.S(h, "Result");
                list.Add(new KeyValuePair<DateTime, Dictionary<string, string>>(d.Value, new Dictionary<string, string>
                {
                    { "Time", J.Fmt(d) }, { "Item", J.S(h, "Title") }, { "Result", res }, { "Source", via },
                    { "Error", res == "Succeeded" ? null : ErrorCodes.Describe(J.S(h, "HResult")) }
                }));
            }

            foreach (object a in J.A(c, "Sccm.Applications"))
            {
                DateTime? d = J.T(a, "LastInstallTime");
                if (!d.HasValue || d.Value < start) continue;
                list.Add(new KeyValuePair<DateTime, Dictionary<string, string>>(d.Value, new Dictionary<string, string>
                {
                    { "Time", J.Fmt(d) }, { "Item", J.S(a, "Name") + " " + J.S(a, "SoftwareVersion") }, { "Result", J.S(a, "InstallState") },
                    { "Source", "Software Center application" }, { "Error", ErrorCodes.Describe(J.S(a, "ErrorCode")) }
                }));
            }

            foreach (object e in J.A(c, "Events"))
            {
                string tag = J.S(e, "Tag");
                int id = J.I(e, "Id") ?? 0;
                string msg = J.S(e, "Message") ?? "";
                DateTime? d = J.T(e, "Time");
                if (!d.HasValue) continue;
                if (tag == "MSI" && (id == 1033 || id == 11707 || id == 11708))
                {
                    string res = id == 11708 ? "Failed" : (id == 11707 ? "Succeeded" : (Regex.IsMatch(msg, @"status:\s*0\b", RegexOptions.IgnoreCase) ? "Succeeded" : "See message"));
                    list.Add(new KeyValuePair<DateTime, Dictionary<string, string>>(d.Value, new Dictionary<string, string>
                    {
                        { "Time", J.Fmt(d) }, { "Item", Short(msg, 160) }, { "Result", res }, { "Source", "MSI (Application log)" }, { "Error", null }
                    }));
                }
                else if (tag == "Setup")
                {
                    var m = Regex.Match(msg, @"Package (\S+) was successfully changed to the (\w+) state", RegexOptions.IgnoreCase);
                    if (m.Success)
                        list.Add(new KeyValuePair<DateTime, Dictionary<string, string>>(d.Value, new Dictionary<string, string>
                        {
                            { "Time", J.Fmt(d) }, { "Item", m.Groups[1].Value }, { "Result", m.Groups[2].Value }, { "Source", "Servicing (Setup log)" }, { "Error", null }
                        }));
                    else if ((J.I(e, "Level") ?? 4) <= 2)
                        list.Add(new KeyValuePair<DateTime, Dictionary<string, string>>(d.Value, new Dictionary<string, string>
                        {
                            { "Time", J.Fmt(d) }, { "Item", Short(msg, 160) }, { "Result", "Error" }, { "Source", "Servicing (Setup log)" }, { "Error", string.Join(", ", ErrorCodes.FindCodes(msg).Select(x => ErrorCodes.Describe(x))) }
                        }));
                }
            }

            r.RecentInstalls.AddRange(list.OrderByDescending(x => x.Key).Take(300).Select(x => x.Value));
        }
    }
}

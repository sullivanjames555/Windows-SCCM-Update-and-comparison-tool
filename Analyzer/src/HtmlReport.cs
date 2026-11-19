// UpdateHealthKit analyzer - self-contained HTML report (no scripts, no external resources).
// C# 5 compatible.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace UpdateHealthKit
{
    internal static class HtmlReport
    {
        private const string Css = @"
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
";

        private static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }
        private static string Badge(string sev) { string s = Sev.Normalize(sev); return "<span class=\"b " + s + "\">" + s + "</span>"; }

        private static void Table(StringBuilder sb, string[] headers, IEnumerable<string[]> rows, string emptyText)
        {
            var list = rows.ToList();
            if (list.Count == 0) { sb.Append("<p class=\"muted\">").Append(H(emptyText ?? "None.")).Append("</p>"); return; }
            sb.Append("<table><thead><tr>");
            foreach (string h in headers) sb.Append("<th>").Append(H(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (string[] row in list)
            {
                sb.Append("<tr>");
                foreach (string cell in row) sb.Append("<td>").Append(cell ?? "").Append("</td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }

        private static void KV(StringBuilder sb, IEnumerable<KeyValuePair<string, string>> items)
        {
            sb.Append("<table><tbody>");
            foreach (var kv in items)
            {
                if (kv.Value == null) continue;
                sb.Append("<tr><td class=\"k\">").Append(H(kv.Key)).Append("</td><td>").Append(H(kv.Value)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        private static KeyValuePair<string, string> P(string k, string v) { return new KeyValuePair<string, string>(k, v); }

        private static void DictTable(StringBuilder sb, IDictionary<string, object> d, string emptyText)
        {
            if (d == null || d.Count == 0) { sb.Append("<p class=\"muted\">").Append(H(emptyText)).Append("</p>"); return; }
            KV(sb, d.Select(kv => P(kv.Key, kv.Value == null ? "" : Convert.ToString(kv.Value, CultureInfo.InvariantCulture))));
        }

        public static string Build(AnalysisResult r, MicrosoftData ms)
        {
            object c = r.Data;
            var sb = new StringBuilder(256 * 1024);
            string title = "Update Health Report - " + (r.ComputerName ?? "?");
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.Append("<title>").Append(H(title)).Append("</title><style>").Append(Css).Append("</style></head><body>");

            // Header
            sb.Append("<header><h1>").Append(H(title)).Append("</h1><div class=\"sub\">");
            sb.Append(H(J.S(c, "System.OSCaption") + " " + (J.S(c, "System.DisplayVersion") ?? "") + " - build " + J.S(c, "System.FullBuild") + " - " + J.S(c, "System.UpdateArch")));
            sb.Append(" &middot; Collected ").Append(H(J.Fmt(r.CollectedAt))).Append(" &middot; Analyzed ").Append(H(J.Fmt(DateTime.Now)));
            sb.Append("</div><div class=\"chips\">");
            foreach (string s in new[] { Sev.Critical, Sev.High, Sev.Medium, Sev.Low, Sev.Info })
                sb.Append("<div class=\"chip\"><b>").Append(r.Count(s)).Append("</b>").Append(s).Append("</div>");
            sb.Append("</div></header><main>");

            sb.Append("<nav><a href=\"#updates\">What needs updating</a><a href=\"#findings\">Findings</a><a href=\"#missing\">Missing updates</a>")
              .Append("<a href=\"#recent\">Recent installs</a><a href=\"#sc\">Software Center</a><a href=\"#client\">SCCM client</a>")
              .Append("<a href=\"#server\">SCCM server</a><a href=\"#wu\">Windows Update</a><a href=\"#dotnet\">.NET</a><a href=\"#events\">Events</a>")
              .Append("<a href=\"#system\">System</a><a href=\"#sources\">Data sources</a></nav>");

            // What needs updating
            sb.Append("<section id=\"updates\"><h2>What needs to be updated</h2>");
            Table(sb, new[] { "", "Component", "Installed", "Latest", "Status", "Action" },
                r.Updates.OrderBy(u => Sev.Rank(u.Severity)).Select(u => new[] { Badge(u.Severity), H(u.Component), H(u.Installed), H(u.Latest), H(u.Status), H(u.Action) }),
                "No version data.");
            sb.Append("</section>");

            // Findings
            sb.Append("<section id=\"findings\"><h2>Findings - why it isn't updating</h2>");
            Table(sb, new[] { "Severity", "Area", "Finding", "Recommended fix" },
                r.Findings.Select(f => new[]
                {
                    Badge(f.Severity), H(f.Area),
                    "<b>" + H(f.Title) + "</b>" + (string.IsNullOrEmpty(f.Detail) ? "" : "<div class=\"small muted\">" + H(f.Detail) + "</div>"),
                    "<span class=\"fix\">" + H(f.Fix) + "</span>"
                }), "No findings.");
            if (r.Notes.Count > 0)
            {
                sb.Append("<h3>Notes</h3><ul>");
                foreach (string n in r.Notes) sb.Append("<li>").Append(H(n)).Append("</li>");
                sb.Append("</ul>");
            }
            sb.Append("</section>");

            // Missing updates
            sb.Append("<section id=\"missing\"><h2>Missing updates (all sources)</h2>");
            Table(sb, new[] { "KB", "Title", "Severity", "Seen by", "Notes" },
                r.Missing.Select(m => new[] { H(m["KB"]), H(m["Title"]), H(m["Severity"]), H(m["Sources"]), H(m["Notes"]) }),
                "No missing updates reported by the client scan, Software Center, WUA scan or the site.");
            sb.Append("</section>");

            // Recent installs
            sb.Append("<section id=\"recent\"><h2>Recent installs (last ").Append(J.I(c, "Meta.DaysBack") ?? 30).Append(" days)</h2>");
            Table(sb, new[] { "Time", "Item", "Result", "Source", "Error" },
                r.RecentInstalls.Select(x => new[] { H(x["Time"]), H(x["Item"]), H(x["Result"]), H(x["Source"]), H(x["Error"]) }),
                "No installs recorded in the window.");
            sb.Append("</section>");

            // Software Center
            sb.Append("<section id=\"sc\"><h2>Software Center</h2><h3>Deployed software updates</h3>");
            Table(sb, new[] { "KB", "Name", "State", "Error", "Deadline", "Progress" },
                J.A(c, "Sccm.SoftwareCenterUpdates").Select(u => new[]
                {
                    H("KB" + J.S(u, "ArticleID")), H(J.S(u, "Name")), H(Analyzer.EvalStateName(J.I(u, "EvaluationState"))),
                    H(ErrorCodes.Describe(J.S(u, "ErrorCode"))), H(J.Fmt(J.T(u, "Deadline"))), H(J.S(u, "PercentComplete") != null ? J.S(u, "PercentComplete") + "%" : "")
                }), "No software updates are deployed to this device in Software Center.");
            sb.Append("<h3>Applications</h3>");
            Table(sb, new[] { "Name", "Version", "Install state", "Last install", "Error", "Target" },
                J.A(c, "Sccm.Applications").OrderByDescending(a => J.S(a, "LastInstallTime") ?? "").Select(a => new[]
                {
                    H(J.S(a, "Name")), H(J.S(a, "SoftwareVersion")), H(J.S(a, "InstallState")), H(J.Fmt(J.T(a, "LastInstallTime"))),
                    H(ErrorCodes.Describe(J.S(a, "ErrorCode"))), H(J.B(a, "IsMachineTarget") ? "Device" : "User")
                }), "No applications.");
            sb.Append("</section>");

            // SCCM client
            sb.Append("<section id=\"client\"><h2>SCCM client</h2><div class=\"grid\"><div>");
            KV(sb, new[]
            {
                P("Installed", J.S(c, "Sccm.Installed")), P("CcmExec", J.S(c, "Sccm.ServiceState") + " / " + J.S(c, "Sccm.ServiceStartMode")),
                P("Client version", J.S(c, "Sccm.ClientVersion")), P("Client GUID", J.S(c, "Sccm.ClientId")), P("Site code", J.S(c, "Sccm.SiteCode")),
                P("Management point", J.S(c, "Sccm.ManagementPoint")), P("HTTPS state", J.S(c, "Sccm.HttpsState")),
                P("SUP (CCM_UpdateSource)", J.S(c, "Sccm.UpdateSource.ContentLocation")), P("SUP from WUAHandler.log", J.S(c, "Sccm.WsusUrlFromLog")),
                P("Last successful scan (logs)", J.Fmt(J.T(c, "Sccm.LastSuccessfulScan"))), P("Last scan failure (logs)", J.Fmt(J.T(c, "Sccm.LastScanFailure"))),
                P("Cache", J.S(c, "Sccm.Cache.Location") != null ? J.S(c, "Sccm.Cache.Location") + " - " + J.S(c, "Sccm.Cache.UsedMB") + " of " + J.S(c, "Sccm.Cache.SizeMB") + " MB used" : null),
                P("CCMEval", J.S(c, "Sccm.CcmEval.Summary") != null ? J.S(c, "Sccm.CcmEval.Summary") + " (" + J.S(c, "Sccm.CcmEval.FileTime") + ")" : null),
                P("Intune enrolled", J.S(c, "Sccm.CoManagement.IntuneEnrolled")), P("Co-management flags", J.S(c, "Sccm.CoManagement.CoManagementFlags"))
            });
            sb.Append("</div><div><h3>Maintenance windows (client)</h3>");
            Table(sb, new[] { "Type", "Start", "End", "Duration (min)" },
                J.A(c, "Sccm.ServiceWindows").Select(w => new[]
                {
                    H(WindowType(J.S(w, "Type"))), H(J.Fmt(J.T(w, "StartTime"))), H(J.Fmt(J.T(w, "EndTime"))),
                    H(J.L(w, "Duration").HasValue ? (J.L(w, "Duration").Value / 60).ToString(CultureInfo.InvariantCulture) : "")
                }), "No maintenance windows - deployments can install at any time.");
            sb.Append("<h3>Client update scan (CCM_UpdateStatus)</h3>");
            var us = J.A(c, "Sccm.UpdateStatus");
            sb.Append("<p>").Append(us.Count).Append(" updates evaluated: ")
              .Append(H(string.Join(", ", us.GroupBy(u => J.S(u, "Status") ?? "?").Select(g => g.Key + " " + g.Count())))).Append("</p>");
            sb.Append("</div></div>");

            sb.Append("<h3>Known failure signatures in CCM logs</h3>");
            Table(sb, new[] { "Severity", "Signature", "Hits", "First", "Last", "Log", "Latest line" },
                J.A(c, "Sccm.LogSignatures").OrderBy(s => Sev.Rank(J.S(s, "Severity"))).Select(s => new[]
                {
                    Badge(J.S(s, "Severity")), H(J.S(s, "Title")), H(J.S(s, "Hits") ?? J.S(s, "Count")), H(J.Fmt(J.T(s, "FirstSeen"))), H(J.Fmt(J.T(s, "LastSeen"))),
                    H(J.S(s, "LastLog")), "<span class=\"mono\">" + H(J.S(s, "Sample")) + "</span>"
                }), "No known failure signatures matched.");

            sb.Append("<h3>CCMEval checks</h3>");
            Table(sb, new[] { "Check", "Result", "Code" },
                J.A(c, "Sccm.CcmEval.Checks").Select(k => new[] { H(J.S(k, "Description")), H(J.S(k, "Result")), H(J.S(k, "ResultCode")) }), "CcmEvalReport.xml not found.");

            sb.Append("<h3>CCM log errors and warnings</h3>");
            Table(sb, new[] { "Log", "Entries", "Errors", "Warnings" },
                J.A(c, "Sccm.LogsParsed").Select(l => new[] { H(J.S(l, "Log")), H(J.S(l, "Entries")), H(J.S(l, "Errors")), H(J.S(l, "Warnings")) }), "No CCM logs parsed.");
            foreach (var grp in J.A(c, "Sccm.LogEntries").GroupBy(e => J.S(e, "Log") ?? "?").OrderBy(g => g.Key))
            {
                sb.Append("<details><summary>").Append(H(grp.Key)).Append(".log - ").Append(grp.Count()).Append(" entries</summary>");
                Table(sb, new[] { "Time", "Type", "Component", "Message" },
                    grp.OrderByDescending(e => J.S(e, "Time") ?? "").Select(e => new[]
                    {
                        H(J.Fmt(J.T(e, "Time"))), H(J.S(e, "Type") == "3" ? "Error" : "Warning"), H(J.S(e, "Component")), "<span class=\"mono\">" + H(J.S(e, "Message")) + "</span>"
                    }), null);
                sb.Append("</details>");
            }
            sb.Append("</section>");

            // SCCM server
            sb.Append("<section id=\"server\"><h2>SCCM server view</h2>");
            if (r.Server == null)
            {
                sb.Append("<p class=\"muted\">").Append(H(r.ServerError != null ? "Not available: " + r.ServerError : "Not checked. Run the analyzer with -SiteServer <SMS Provider>.")).Append("</p>");
            }
            else
            {
                ServerView v = r.Server;
                sb.Append("<p>SMS Provider <b>").Append(H(r.ServerName)).Append("</b>, site ").Append(H(r.SiteCode)).Append(" (").Append(H(r.SiteVersion)).Append(")</p>");
                if (v.Error != null) sb.Append("<p class=\"muted\">Query error: ").Append(H(v.Error)).Append("</p>");
                sb.Append("<h3>Device records</h3>");
                Table(sb, new[] { "ResourceId", "GUID", "Client", "Client version", "Active", "Obsolete", "Build", "Last logon", "Created" },
                    v.Records.Select(x => new[] { H(x["ResourceId"]), H(x["SMSUniqueIdentifier"]), H(x["Client"]), H(x["ClientVersion"]), H(x["Active"]), H(x["Obsolete"]), H(x["Build"]), H(x["LastLogon"]), H(x["CreationDate"]) }),
                    "No records.");
                if (v.Combined != null)
                {
                    sb.Append("<details><summary>Client status (SMS_CombinedDeviceResources)</summary>");
                    KV(sb, v.Combined.Select(kv => P(kv.Key, kv.Value)));
                    sb.Append("</details>");
                }
                sb.Append("<p>Last update scan result received: <b>").Append(H(J.Fmt(v.LastStatusCheck) ?? "never")).Append("</b> &middot; ")
                  .Append(v.ComplianceRows).Append(" compliance rows, ").Append(v.InstalledCount).Append(" installed, ").Append(v.Required.Count).Append(" required</p>");

                sb.Append("<h3>Latest cumulative update</h3>");
                var cuRows = new List<string[]>();
                if (v.LatestMicrosoftKbInCatalog != null)
                    foreach (ServerUpdate mk in v.LatestMicrosoftKbInCatalog)
                        cuRows.Add(new[] { H("Microsoft latest (" + r.LatestKb + ")"), H(mk.Title), H(YesNo(mk.IsDeployed)), H(YesNo(mk.DeployedToDevice)), H(YesNo(mk.IsSuperseded)), H(J.FmtDay(mk.DatePosted)) });
                if (v.LatestCuInCatalog != null)
                {
                    ServerUpdate cu = v.LatestCuInCatalog;
                    cuRows.Add(new[] { H("Newest in SCCM catalog"), H(cu.Title), H(YesNo(cu.IsDeployed)), H(YesNo(cu.DeployedToDevice)), H(YesNo(cu.IsSuperseded)), H(J.FmtDay(cu.DatePosted)) });
                }
                Table(sb, new[] { "", "Update", "Deployed", "To this device", "Superseded", "Posted" }, cuRows,
                    "No matching cumulative update found in the SCCM catalog for pattern: " + (v.CuSearchPattern ?? "(unknown)"));

                sb.Append("<h3>Required updates (site view)</h3>");
                Table(sb, new[] { "KB", "Title", "Deployed to device", "Deployed anywhere", "Superseded", "Last error" },
                    v.Required.OrderBy(u => u.DeployedToDevice ? 0 : 1).Select(u => new[] { H("KB" + u.Article), H(u.Title), H(YesNo(u.DeployedToDevice)), H(YesNo(u.IsDeployed)), H(YesNo(u.IsSuperseded)), H(ErrorCodes.Describe(u.LastError)) }),
                    "The site reports no required updates for this device.");

                sb.Append("<h3>Software update deployments to this device</h3>");
                Table(sb, new[] { "Deployment", "Collection", "Purpose", "Enabled", "Available", "Deadline", "Updates", "Ignore MW" },
                    v.Deployments.Select(d => new[] { H(d["Name"]), H(d["Collection"]), H(d["Purpose"]), H(d["Enabled"]), H(d["Start"]), H(d["Deadline"]), H(d["Updates"]), H(d["OverrideMaintenanceWindow"]) }),
                    "No software update deployments target this device's collections.");

                sb.Append("<h3>Maintenance windows (collections)</h3>");
                Table(sb, new[] { "Collection", "Name", "Type", "Enabled", "Start", "Duration (min)", "Description" },
                    v.MaintenanceWindows.Select(w => new[] { H(w["Collection"]), H(w["Name"]), H(w["Type"]), H(w["Enabled"]), H(w["Start"]), H(w["DurationMin"]), H(w["Description"]) }),
                    "No maintenance windows on this device's collections.");

                sb.Append("<details><summary>Collection membership (").Append(v.Collections.Count).Append(")</summary><ul>");
                foreach (var col in v.Collections.OrderBy(x => x.Value)) sb.Append("<li>").Append(H(col.Value + " (" + col.Key + ")")).Append("</li>");
                sb.Append("</ul></details>");
            }
            if (r.Wsus != null || r.WsusError != null)
            {
                sb.Append("<h3>WSUS</h3>");
                if (r.Wsus != null) KV(sb, r.Wsus.Select(kv => P(kv.Key, kv.Value)));
                else sb.Append("<p class=\"muted\">").Append(H(r.WsusError)).Append("</p>");
            }
            sb.Append("</section>");

            // Windows Update
            sb.Append("<section id=\"wu\"><h2>Windows Update</h2><div class=\"grid\"><div>");
            KV(sb, new[]
            {
                P("Agent version", J.S(c, "WindowsUpdate.AgentVersion")), P("History entries", J.S(c, "WindowsUpdate.HistoryTotal")),
                P("SoftwareDistribution size", J.S(c, "WindowsUpdate.SoftwareDistributionSizeMB") != null ? J.S(c, "WindowsUpdate.SoftwareDistributionSizeMB") + " MB" : null),
                P("Registry.pol", J.S(c, "WindowsUpdate.RegistryPol.HeaderOk") != null ? (J.B(c, "WindowsUpdate.RegistryPol.HeaderOk") ? "OK" : "CORRUPT header " + J.S(c, "WindowsUpdate.RegistryPol.Header")) + ", " + J.S(c, "WindowsUpdate.RegistryPol.SizeBytes") + " bytes" : null),
                P("Scan during collection", J.S(c, "WindowsUpdate.Scan.Mode") != null ? J.S(c, "WindowsUpdate.Scan.Mode") + " - " + (J.S(c, "WindowsUpdate.Scan.ResultCode") ?? J.S(c, "WindowsUpdate.Scan.Error")) : "not run"),
                P("DISM CheckHealth", J.B(c, "WindowsUpdate.Dism.Ran") ? J.S(c, "WindowsUpdate.Dism.Output") : "not run")
            });
            sb.Append("<h3>Services</h3>");
            Table(sb, new[] { "Service", "State", "Start mode", "Account" },
                J.A(c, "WindowsUpdate.Services").Select(s => new[] { H(J.S(s, "DisplayName") + " (" + J.S(s, "Name") + ")"), H(J.S(s, "State")), H(J.S(s, "StartMode")), H(J.S(s, "StartName")) }), "No service data.");
            sb.Append("</div><div><h3>Policy: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate</h3>");
            DictTable(sb, J.Dict(c, "WindowsUpdate.Policy"), "No WindowsUpdate policy key.");
            sb.Append("<h3>Policy: ...\\WindowsUpdate\\AU</h3>");
            DictTable(sb, J.Dict(c, "WindowsUpdate.PolicyAU"), "No AU policy key.");
            sb.Append("<details><summary>MDM update policy (PolicyManager)</summary>");
            DictTable(sb, J.Dict(c, "WindowsUpdate.MdmUpdatePolicy"), "None.");
            sb.Append("</details><details><summary>Registered update services</summary>");
            Table(sb, new[] { "Name", "ServiceID", "Default AU", "Managed" },
                J.A(c, "WindowsUpdate.RegisteredServices").Select(s => new[] { H(J.S(s, "Name")), "<span class=\"mono\">" + H(J.S(s, "ServiceID")) + "</span>", H(J.S(s, "IsDefaultAUService")), H(J.S(s, "IsManaged")) }), "None.");
            sb.Append("</details></div></div>");
            sb.Append("<details><summary>Windows Update history (").Append(J.A(c, "WindowsUpdate.History").Count).Append(" entries)</summary>");
            Table(sb, new[] { "Date", "Title", "Result", "HResult", "Client" },
                J.A(c, "WindowsUpdate.History").Select(h => new[] { H(J.Fmt(J.T(h, "Date"))), H(J.S(h, "Title")), H(J.S(h, "Result")), H(ErrorCodes.Describe(J.S(h, "HResult"))), H(J.S(h, "ClientApplicationID")) }), "No history.");
            sb.Append("</details><details><summary>Installed hotfixes (").Append(J.A(c, "WindowsUpdate.HotFixes").Count).Append(")</summary>");
            Table(sb, new[] { "HotFix", "Description", "Installed on", "By" },
                J.A(c, "WindowsUpdate.HotFixes").OrderByDescending(h => J.S(h, "InstalledOn") ?? "").Select(h => new[] { H(J.S(h, "HotFixID")), H(J.S(h, "Description")), H(J.FmtDay(J.T(h, "InstalledOn"))), H(J.S(h, "InstalledBy")) }), "None.");
            sb.Append("</details></section>");

            // .NET
            sb.Append("<section id=\"dotnet\"><h2>.NET</h2>");
            KV(sb, new[]
            {
                P(".NET Framework 4.x", J.S(c, "DotNet.Framework.FriendlyVersion") + " (release " + J.S(c, "DotNet.Framework.Release") + ", " + J.S(c, "DotNet.Framework.Version") + ")"),
                P(".NET Framework 3.5", J.B(c, "DotNet.Framework.Net35Installed") ? "Installed" : "Not installed")
            });
            Table(sb, new[] { "Kind", "Version", "Architecture", "Path" },
                J.A(c, "DotNet.Installs").Select(i => new[] { H(J.S(i, "Kind")), H(J.S(i, "Version")), H(J.S(i, "Architecture")), "<span class=\"mono\">" + H(J.S(i, "Path")) + "</span>" }),
                "No .NET (Core/5+) runtimes or SDKs installed.");
            sb.Append("</section>");

            // Events
            sb.Append("<section id=\"events\"><h2>Event log highlights</h2><h3>Most frequent errors</h3>");
            Table(sb, new[] { "Log", "Source", "ID", "Count", "Last", "Sample" },
                r.EventGroups.Select(g => new[] { H(g["Log"]), H(g["Provider"]), H(g["Id"]), H(g["Count"]), H(g["Last"]), "<span class=\"small\">" + H(g["Sample"]) + "</span>" }), "No error events in the window.");
            var events = J.A(c, "Events");
            foreach (var grp in events.GroupBy(e => J.S(e, "Tag") ?? "?").OrderBy(g => g.Key))
            {
                sb.Append("<details><summary>").Append(H(grp.Key)).Append(" - ").Append(grp.Count()).Append(" events</summary>");
                Table(sb, new[] { "Time", "Level", "Source", "ID", "Message" },
                    grp.OrderByDescending(e => J.S(e, "Time") ?? "").Take(300).Select(e => new[]
                    {
                        H(J.Fmt(J.T(e, "Time"))), H(J.S(e, "LevelName") ?? J.S(e, "Level")), H(J.S(e, "Provider")), H(J.S(e, "Id")), "<span class=\"small\">" + H(J.S(e, "Message")) + "</span>"
                    }), null);
                sb.Append("</details>");
            }
            sb.Append("<h3>Event logs queried</h3>");
            Table(sb, new[] { "Query", "Log", "Events", "Error" },
                J.A(c, "EventLogStatus").Select(s => new[] { H(J.S(s, "Tag")), H(J.S(s, "Log")), H(J.S(s, "Count")), H(J.S(s, "Error")) }), "None.");
            sb.Append("</section>");

            // System
            sb.Append("<section id=\"system\"><h2>System</h2><div class=\"grid\"><div>");
            KV(sb, new[]
            {
                P("Computer", J.S(c, "System.ComputerName")), P("FQDN", J.S(c, "System.Fqdn")), P("Domain", J.S(c, "System.Domain")),
                P("Model", J.S(c, "System.Manufacturer") + " " + J.S(c, "System.Model")), P("Serial", J.S(c, "System.SerialNumber")), P("BIOS", J.S(c, "System.BiosVersion")),
                P("OS", J.S(c, "System.OSCaption")), P("Edition", J.S(c, "System.EditionID")), P("Version", J.S(c, "System.DisplayVersion") ?? J.S(c, "System.ReleaseId")),
                P("Build", J.S(c, "System.FullBuild")), P("Architecture", J.S(c, "System.ProcessorArchitecture") + " / " + J.S(c, "System.OSArchitecture")),
                P("CPU", J.S(c, "System.CpuName")), P("Memory", J.S(c, "System.MemoryGB") + " GB"),
                P("System drive", J.S(c, "System.SystemDrive") + " " + J.S(c, "System.SystemDriveFreeGB") + " GB free of " + J.S(c, "System.SystemDriveSizeGB") + " GB"),
                P("Installed", J.Fmt(J.T(c, "System.InstallDate"))), P("Last boot", J.Fmt(J.T(c, "System.LastBootTime"))), P("Uptime (days)", J.S(c, "System.UptimeDays")),
                P("Pending restart", J.B(c, "PendingReboot.Any") ? string.Join(", ", J.A(c, "PendingReboot.Reasons").Select(x => Convert.ToString(x, CultureInfo.InvariantCulture))) : "No"),
                P("Time source", J.S(c, "TimeSync.Source")), P("Secure Boot", J.S(c, "SecureBoot.Enabled")),
                P("Secure Boot 2023 CA status", J.S(c, "SecureBoot.Servicing.UEFICA2023Status")),
                P("Collector", J.S(c, "Meta.CollectorVersion") + " as " + J.S(c, "Meta.RunAsUser") + (J.B(c, "Meta.RunAsAdmin") ? " (elevated)" : " (NOT elevated)"))
            });
            sb.Append("</div><div><h3>Network</h3>");
            Table(sb, new[] { "Adapter", "IP", "Gateway", "DNS" },
                J.A(c, "Network.Adapters").Select(a => new[] { H(J.S(a, "Description")), H(J.S(a, "IPAddress")), H(J.S(a, "Gateway")), H(J.S(a, "DnsServers")) }), "No adapters.");
            sb.Append("<p class=\"small mono\">").Append(H(J.S(c, "Network.WinHttpProxy"))).Append("</p>");
            sb.Append("<h3>Connectivity tests (from the device)</h3>");
            Table(sb, new[] { "Purpose", "Target", "DNS", "TCP", "HTTP", "Error" },
                J.A(c, "Network.Connectivity").Select(t => new[] { H(J.S(t, "Purpose")), H(J.S(t, "Host") + ":" + J.S(t, "Port")), H(J.B(t, "DnsOk") ? "OK" : "FAIL"), H(J.B(t, "TcpOk") ? "OK" : "FAIL"), H(J.S(t, "Http")), H(J.S(t, "Error")) }),
                "Connectivity tests were skipped.");
            sb.Append("</div></div>");
            var secErr = J.A(c, "Meta.SectionErrors");
            if (secErr.Count > 0)
            {
                sb.Append("<details><summary>Collector section errors (").Append(secErr.Count).Append(")</summary>");
                Table(sb, new[] { "Section", "Error" }, secErr.Select(e => new[] { H(J.S(e, "Section")), H(J.S(e, "Error")) }), null);
                sb.Append("</details>");
            }
            sb.Append("</section>");

            // Data sources
            sb.Append("<section id=\"sources\"><h2>Data sources</h2>");
            KV(sb, new[]
            {
                P("Windows 11 release information", ms.SourceText("windows11-release-information.html")),
                P("Windows 10 release information", ms.SourceText("windows10-release-information.html")),
                P(".NET releases index", ms.SourceText("dotnet-releases-index.json")),
                P("SCCM SMS Provider", r.ServerName != null ? r.ServerName + " site " + r.SiteCode : "not used"),
                P("WSUS", opt_WsusText(r)),
                P("Bundle", r.BundlePath),
                P("Analyzer", Program.Version)
            });
            sb.Append("<p class=\"small muted\">Microsoft pages: ").Append(H(MicrosoftData.Win11Url)).Append(" and ").Append(H(MicrosoftData.Win10Url)).Append("</p>");
            sb.Append("</section>");

            sb.Append("</main></body></html>");
            return sb.ToString();
        }

        private static string opt_WsusText(AnalysisResult r)
        {
            if (r.Wsus != null) { string s; return r.Wsus.TryGetValue("Server", out s) ? s : "used"; }
            return r.WsusError ?? "not used";
        }

        private static string YesNo(bool b) { return b ? "Yes" : "No"; }

        private static string WindowType(string id)
        {
            switch (id)
            {
                case "1": return "All deployments";
                case "2": return "Programs";
                case "3": return "Reboot required";
                case "4": return "Software updates";
                case "5": return "Task sequences";
                case "6": return "Non-working hours";
                default: return id;
            }
        }

        public static string BuildIndex(List<AnalysisResult> results, string outRoot)
        {
            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Update Health Summary</title><style>").Append(Css).Append("</style></head><body>");
            sb.Append("<header><h1>Update Health Summary</h1><div class=\"sub\">").Append(results.Count).Append(" devices &middot; ").Append(H(J.Fmt(DateTime.Now))).Append("</div></header><main><section>");
            Table(sb, new[] { "Computer", "Collected", "Build", "Critical", "High", "Medium", "Top finding", "Report" },
                results.OrderBy(x => x.Count(Sev.Critical) > 0 ? 0 : 1).ThenByDescending(x => x.Count(Sev.High)).Select(x =>
                {
                    var top = x.Findings.FirstOrDefault();
                    string rel = x.ReportPath != null && x.ReportPath.StartsWith(outRoot, StringComparison.OrdinalIgnoreCase)
                        ? x.ReportPath.Substring(outRoot.Length).TrimStart('\\', '/').Replace('\\', '/') : x.ReportPath;
                    return new[]
                    {
                        H(x.ComputerName), H(J.Fmt(x.CollectedAt)), H(J.S(x.Data, "System.FullBuild")),
                        x.Count(Sev.Critical) > 0 ? Badge(Sev.Critical) + " " + x.Count(Sev.Critical) : "0",
                        x.Count(Sev.High) > 0 ? Badge(Sev.High) + " " + x.Count(Sev.High) : "0",
                        x.Count(Sev.Medium).ToString(CultureInfo.InvariantCulture),
                        top != null ? H(top.Title) : "",
                        "<a href=\"" + H(rel) + "\">open</a>"
                    };
                }), "No results.");
            sb.Append("</section></main></body></html>");
            return sb.ToString();
        }
    }
}

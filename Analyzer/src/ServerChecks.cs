// UpdateHealthKit analyzer - live checks against the ConfigMgr SMS Provider (WMI) and,
// optionally, the WSUS server API. Runs as the current Windows user.
// C# 5 compatible.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;

namespace UpdateHealthKit
{
    internal sealed class ServerUpdate
    {
        public uint CiId;
        public string Article;
        public string Title;
        public bool IsDeployed;
        public bool IsSuperseded;
        public bool IsExpired;
        public DateTime? DatePosted;
        public bool DeployedToDevice;
        public string LastError;
        public DateTime? LastCheck;
    }

    internal sealed class ServerView
    {
        public string Error;
        public readonly List<Dictionary<string, string>> Records = new List<Dictionary<string, string>>();
        public long ResourceId;
        public string SmsGuid;
        public Dictionary<string, string> Combined;
        public readonly List<KeyValuePair<string, string>> Collections = new List<KeyValuePair<string, string>>();
        public readonly List<Dictionary<string, string>> Deployments = new List<Dictionary<string, string>>();
        public readonly List<Dictionary<string, string>> MaintenanceWindows = new List<Dictionary<string, string>>();
        public readonly HashSet<uint> DeployedCIs = new HashSet<uint>();
        public int ComplianceRows;
        public int InstalledCount;
        public DateTime? LastStatusCheck;
        public readonly List<ServerUpdate> Required = new List<ServerUpdate>();
        public string CuSearchPattern;
        public ServerUpdate LatestCuInCatalog;
        public List<ServerUpdate> LatestMicrosoftKbInCatalog;
        public string LatestMicrosoftKb;
    }

    internal sealed class SccmServer
    {
        public readonly string Server;
        public string SiteCode;
        public string SiteVersion;
        public string Error;
        private ManagementScope scope;

        public SccmServer(string server, string siteCode)
        {
            Server = server;
            SiteCode = siteCode;
        }

        public bool Connected { get { return scope != null && scope.IsConnected; } }

        public bool Connect()
        {
            try
            {
                var opts = new ConnectionOptions
                {
                    Impersonation = ImpersonationLevel.Impersonate,
                    Authentication = AuthenticationLevel.PacketPrivacy,
                    EnablePrivileges = true,
                    Timeout = TimeSpan.FromSeconds(60)
                };
                if (string.IsNullOrEmpty(SiteCode))
                {
                    var rootScope = new ManagementScope(@"\\" + Server + @"\root\SMS", opts);
                    rootScope.Connect();
                    using (var s = new ManagementObjectSearcher(rootScope, new ObjectQuery("SELECT SiteCode FROM SMS_ProviderLocation WHERE ProviderForLocalSite = true")))
                    {
                        foreach (ManagementBaseObject mo in s.Get()) { SiteCode = Str(mo, "SiteCode"); break; }
                    }
                    if (string.IsNullOrEmpty(SiteCode)) { Error = "Could not determine the site code from SMS_ProviderLocation. Pass -SiteCode."; return false; }
                }
                scope = new ManagementScope(@"\\" + Server + @"\root\SMS\site_" + SiteCode, opts);
                scope.Connect();
                var site = Query("SELECT Version FROM SMS_Site WHERE SiteCode = '" + Esc(SiteCode) + "'").FirstOrDefault();
                if (site != null) SiteVersion = Str(site, "Version");
                return true;
            }
            catch (Exception ex)
            {
                Error = ex.Message;
                scope = null;
                return false;
            }
        }

        public List<ManagementBaseObject> Query(string wql)
        {
            var list = new List<ManagementBaseObject>();
            using (var s = new ManagementObjectSearcher(scope, new ObjectQuery(wql)))
            {
                s.Options.Timeout = TimeSpan.FromMinutes(5);
                foreach (ManagementBaseObject mo in s.Get()) list.Add(mo);
            }
            return list;
        }

        /// <summary>Everything the site knows about one device, for comparison with the client bundle.</summary>
        public ServerView Inspect(string computerName, string cuPattern, string latestKb)
        {
            var v = new ServerView { CuSearchPattern = cuPattern, LatestMicrosoftKb = latestKb };
            try
            {
                var recs = Query("SELECT * FROM SMS_R_System WHERE Name = '" + Esc(computerName) + "'");
                foreach (var r in recs)
                {
                    v.Records.Add(new Dictionary<string, string>
                    {
                        { "ResourceId", Str(r, "ResourceId") },
                        { "SMSUniqueIdentifier", Str(r, "SMSUniqueIdentifier") },
                        { "Client", Str(r, "Client") },
                        { "ClientVersion", Str(r, "ClientVersion") },
                        { "Active", Str(r, "Active") },
                        { "Obsolete", Str(r, "Obsolete") },
                        { "Decommissioned", Str(r, "Decommissioned") },
                        { "OS", Str(r, "OperatingSystemNameandVersion") },
                        { "Build", Str(r, "BuildExt") ?? Str(r, "Build") },
                        { "LastLogon", J.Fmt(Date(r, "LastLogonTimestamp", true)) },
                        { "CreationDate", J.Fmt(Date(r, "CreationDate", true)) }
                    });
                }
                var primary = recs
                    .OrderByDescending(r => Str(r, "Client") == "1" ? 1 : 0)
                    .ThenByDescending(r => Str(r, "Obsolete") == "1" ? 0 : 1)
                    .ThenByDescending(r => ToLong(Str(r, "ResourceId")))
                    .FirstOrDefault();
                if (primary == null) return v;
                v.ResourceId = ToLong(Str(primary, "ResourceId"));
                v.SmsGuid = Str(primary, "SMSUniqueIdentifier");

                var cdr = Query("SELECT * FROM SMS_CombinedDeviceResources WHERE ResourceID = " + v.ResourceId).FirstOrDefault();
                if (cdr != null)
                {
                    v.Combined = new Dictionary<string, string>();
                    foreach (string pn in new[] { "ClientActiveStatus", "ClientVersion", "IsActive", "IsObsolete", "IsBlocked", "IsApproved",
                                                  "IsClient", "LastActiveTime", "LastPolicyRequest", "LastDDR", "LastHardwareScan",
                                                  "LastSoftwareScan", "LastMPServerName", "LastClientCheckTime", "ClientCheckPass",
                                                  "CNIsOnline", "CNLastOnlineTime", "CoManaged", "SiteCode", "DeviceOS", "DeviceOSBuild" })
                    {
                        string val = Str(cdr, pn);
                        if (val != null && val.Length >= 14 && char.IsDigit(val[0]) && val.Length > 14 && val[14] == '.') val = J.Fmt(WmiDate(val, true));
                        v.Combined[pn] = val;
                    }
                }

                // Collection membership
                var colIds = Query("SELECT CollectionID FROM SMS_FullCollectionMembership WHERE ResourceID = " + v.ResourceId)
                    .Select(m => Str(m, "CollectionID")).Where(x => x != null).Distinct().ToList();
                var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var batch in Batch(colIds, 20))
                {
                    string filter = string.Join(" OR ", batch.Select(id => "CollectionID = '" + Esc(id) + "'"));
                    foreach (var c in Query("SELECT CollectionID, Name FROM SMS_Collection WHERE " + filter))
                        names[Str(c, "CollectionID")] = Str(c, "Name");
                }
                foreach (string id in colIds)
                    v.Collections.Add(new KeyValuePair<string, string>(id, names.ContainsKey(id) ? names[id] : id));

                // Software update deployments targeting those collections
                foreach (var batch in Batch(colIds, 20))
                {
                    string filter = string.Join(" OR ", batch.Select(id => "TargetCollectionID = '" + Esc(id) + "'"));
                    foreach (var a in Query("SELECT * FROM SMS_UpdatesAssignment WHERE " + filter))
                    {
                        LoadLazy(a);
                        int count = 0;
                        var arr = P(a, "AssignedCIs") as Array;
                        if (arr != null)
                            foreach (object x in arr) { v.DeployedCIs.Add(Convert.ToUInt32(x, CultureInfo.InvariantCulture)); count++; }
                        bool gmt = Str(a, "UseGMTTimes") == "True";
                        string deadline = J.Fmt(Date(a, "EnforcementDeadline", gmt));
                        string col = Str(a, "TargetCollectionID");
                        v.Deployments.Add(new Dictionary<string, string>
                        {
                            { "Name", Str(a, "AssignmentName") },
                            { "Collection", (col != null && names.ContainsKey(col)) ? names[col] + " (" + col + ")" : col },
                            { "Purpose", deadline == null ? "Available" : "Required" },
                            { "Enabled", Str(a, "Enabled") },
                            { "Start", J.Fmt(Date(a, "StartTime", gmt)) },
                            { "Deadline", deadline },
                            { "Updates", count.ToString(CultureInfo.InvariantCulture) },
                            { "OverrideMaintenanceWindow", Str(a, "OverrideServiceWindows") },
                            { "RebootOutsideMaintenanceWindow", Str(a, "RebootOutsideOfServiceWindows") },
                            { "SuppressReboot", Str(a, "SuppressReboot") }
                        });
                    }
                }

                // Maintenance windows on those collections
                foreach (var batch in Batch(colIds, 20))
                {
                    string filter = string.Join(" OR ", batch.Select(id => "CollectionID = '" + Esc(id) + "'"));
                    foreach (var cs in Query("SELECT * FROM SMS_CollectionSettings WHERE " + filter))
                    {
                        LoadLazy(cs);
                        var sws = P(cs, "ServiceWindows") as ManagementBaseObject[];
                        if (sws == null) continue;
                        string col = Str(cs, "CollectionID");
                        foreach (var sw in sws)
                        {
                            bool gmt = Str(sw, "IsGMT") == "True";
                            v.MaintenanceWindows.Add(new Dictionary<string, string>
                            {
                                { "Collection", (col != null && names.ContainsKey(col)) ? names[col] : col },
                                { "Name", Str(sw, "Name") },
                                { "Type", WindowType(Str(sw, "ServiceWindowType")) },
                                { "TypeId", Str(sw, "ServiceWindowType") },
                                { "Enabled", Str(sw, "IsEnabled") },
                                { "Start", J.Fmt(Date(sw, "StartTime", gmt)) },
                                { "DurationMin", Str(sw, "Duration") },
                                { "Recurrence", Str(sw, "RecurrenceType") },
                                { "Description", Str(sw, "Description") }
                            });
                        }
                    }
                }

                // Per-update compliance the site has received from this client
                var comp = Query("SELECT CI_ID, Status, LastStatusCheckTime, LastErrorCode, LastEnforcementMessageID FROM SMS_UpdateComplianceStatus WHERE MachineID = " + v.ResourceId);
                v.ComplianceRows = comp.Count;
                var required = new Dictionary<uint, ManagementBaseObject>();
                foreach (var c in comp)
                {
                    DateTime? chk = WmiDate(Str(c, "LastStatusCheckTime"), true);
                    if (chk.HasValue && (!v.LastStatusCheck.HasValue || chk.Value > v.LastStatusCheck.Value)) v.LastStatusCheck = chk;
                    string st = Str(c, "Status");
                    uint id = Convert.ToUInt32(P(c, "CI_ID"), CultureInfo.InvariantCulture);
                    if (st == "2") required[id] = c;
                    else if (st == "3") v.InstalledCount++;
                }
                foreach (var batch in Batch(required.Keys.ToList(), 25))
                {
                    string filter = string.Join(" OR ", batch.Select(id => "CI_ID = " + id.ToString(CultureInfo.InvariantCulture)));
                    foreach (var u in Query("SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE " + filter))
                    {
                        ServerUpdate su = ToUpdate(u, v.DeployedCIs);
                        ManagementBaseObject c;
                        if (required.TryGetValue(su.CiId, out c))
                        {
                            su.LastError = ErrorCodes.Hex(P(c, "LastErrorCode"));
                            if (su.LastError == "0x00000000") su.LastError = null;
                            su.LastCheck = WmiDate(Str(c, "LastStatusCheckTime"), true);
                        }
                        v.Required.Add(su);
                    }
                }

                // Latest cumulative update for this OS/arch in the site's catalog, and Microsoft's latest KB
                if (!string.IsNullOrEmpty(cuPattern))
                {
                    v.LatestCuInCatalog = Query("SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE LocalizedDisplayName LIKE '%" + Esc(cuPattern) + "%' AND IsExpired = 0")
                        .Select(u => ToUpdate(u, v.DeployedCIs))
                        .OrderByDescending(u => u.DatePosted ?? DateTime.MinValue)
                        .FirstOrDefault();
                }
                if (!string.IsNullOrEmpty(latestKb))
                {
                    string digits = latestKb.ToUpperInvariant().Replace("KB", "");
                    v.LatestMicrosoftKbInCatalog = Query("SELECT CI_ID, ArticleID, LocalizedDisplayName, IsDeployed, IsSuperseded, IsExpired, DatePosted FROM SMS_SoftwareUpdate WHERE ArticleID = '" + Esc(digits) + "'")
                        .Select(u => ToUpdate(u, v.DeployedCIs))
                        .Where(u => string.IsNullOrEmpty(cuPattern) || (u.Title ?? "").IndexOf(cuPattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                v.Error = ex.Message;
            }
            return v;
        }

        private static ServerUpdate ToUpdate(ManagementBaseObject u, HashSet<uint> deployed)
        {
            uint id = Convert.ToUInt32(P(u, "CI_ID"), CultureInfo.InvariantCulture);
            return new ServerUpdate
            {
                CiId = id,
                Article = Str(u, "ArticleID"),
                Title = Str(u, "LocalizedDisplayName"),
                IsDeployed = Str(u, "IsDeployed") == "True",
                IsSuperseded = Str(u, "IsSuperseded") == "True",
                IsExpired = Str(u, "IsExpired") == "True",
                DatePosted = WmiDate(Str(u, "DatePosted"), true),
                DeployedToDevice = deployed.Contains(id)
            };
        }

        private static void LoadLazy(ManagementBaseObject o)
        {
            var mo = o as ManagementObject;
            if (mo == null) return;
            try { mo.Get(); } catch { }
        }

        private static string WindowType(string id)
        {
            switch (id)
            {
                case "1": return "All deployments";
                case "2": return "Programs";
                case "3": return "Reboot required";
                case "4": return "Software updates";
                case "5": return "Task sequences";
                case "6": return "User defined (non-working hours)";
                default: return id;
            }
        }

        internal static IEnumerable<List<T>> Batch<T>(List<T> source, int size)
        {
            for (int i = 0; i < source.Count; i += size)
                yield return source.GetRange(i, Math.Min(size, source.Count - i));
        }

        internal static object P(ManagementBaseObject mo, string name)
        {
            if (mo == null) return null;
            try { return mo[name]; } catch { return null; }
        }

        internal static string Str(ManagementBaseObject mo, string name)
        {
            object v = P(mo, name);
            return v == null ? null : Convert.ToString(v, CultureInfo.InvariantCulture);
        }

        internal static DateTime? Date(ManagementBaseObject mo, string name, bool assumeUtc)
        {
            return WmiDate(Str(mo, name), assumeUtc);
        }

        /// <summary>Parses CIM DATETIME. SMS Provider values end in "+***"; treat them as UTC or local per the caller.</summary>
        internal static DateTime? WmiDate(string s, bool assumeUtc)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 14) return null;
            try
            {
                if (s.Contains("***"))
                {
                    var d = DateTime.ParseExact(s.Substring(0, 14), "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                    if (d.Year < 1980) return null;
                    return assumeUtc ? DateTime.SpecifyKind(d, DateTimeKind.Utc).ToLocalTime() : d;
                }
                DateTime r = ManagementDateTimeConverter.ToDateTime(s);
                return r.Year < 1980 ? (DateTime?)null : r;
            }
            catch { return null; }
        }

        internal static string Esc(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace("'", "\\'");
        }

        private static long ToLong(string s)
        {
            long l;
            return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out l) ? l : 0;
        }
    }

    /// <summary>Optional WSUS lookup through the WSUS administration API, loaded by reflection so the
    /// analyzer builds and runs on PCs without the WSUS console.</summary>
    internal static class WsusCheck
    {
        public static Dictionary<string, string> Lookup(string server, int port, bool ssl, string fqdn, string shortName, out string error)
        {
            error = null;
            Assembly asm = null;
            foreach (string ver in new[] { "4.0.0.0", "3.0.0.0" })
            {
                try { asm = Assembly.Load("Microsoft.UpdateServices.Administration, Version=" + ver + ", Culture=neutral, PublicKeyToken=31bf3856ad364e35"); break; }
                catch { }
            }
            if (asm == null)
            {
                string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Update Services\Api\Microsoft.UpdateServices.Administration.dll");
                if (File.Exists(p)) { try { asm = Assembly.LoadFrom(p); } catch { } }
            }
            if (asm == null)
            {
                error = "WSUS administration API not found on this PC. Install RSAT 'Windows Server Update Services Tools' (or run on the SUP) to enable the WSUS check.";
                return null;
            }

            try
            {
                Type proxy = asm.GetType("Microsoft.UpdateServices.Administration.AdminProxy", true);
                MethodInfo getServer = proxy.GetMethod("GetUpdateServer", new[] { typeof(string), typeof(bool), typeof(int) });
                object srv = getServer.Invoke(null, new object[] { server, ssl, port });

                Type iServer = asm.GetType("Microsoft.UpdateServices.Administration.IUpdateServer", true);
                MethodInfo byName = iServer.GetMethod("GetComputerTargetByName", new[] { typeof(string) });
                object target = null;
                foreach (string n in new[] { fqdn, shortName })
                {
                    if (string.IsNullOrEmpty(n)) continue;
                    try { target = byName.Invoke(srv, new object[] { n }); }
                    catch (TargetInvocationException) { target = null; }
                    if (target != null) break;
                }

                var result = new Dictionary<string, string>();
                result["Server"] = server + ":" + port + (ssl ? " (SSL)" : "");
                if (target == null) { result["Found"] = "False"; return result; }
                result["Found"] = "True";

                Type iTarget = asm.GetType("Microsoft.UpdateServices.Administration.IComputerTarget", true);
                foreach (string prop in new[] { "FullDomainName", "IPAddress", "LastReportedStatusTime", "LastSyncTime", "LastSyncResult",
                                                "LastReportedInventoryTime", "ClientVersion", "OSDescription", "RequestedTargetGroupName" })
                {
                    object val = GetProp(target, iTarget, prop);
                    if (val is DateTime)
                    {
                        var d = (DateTime)val;
                        val = d.Year < 1980 ? null : J.Fmt(d.Kind == DateTimeKind.Local ? d : DateTime.SpecifyKind(d, DateTimeKind.Utc).ToLocalTime());
                    }
                    result[prop] = val == null ? null : Convert.ToString(val, CultureInfo.InvariantCulture);
                }

                MethodInfo summary = iTarget.GetMethod("GetUpdateInstallationSummary", Type.EmptyTypes);
                if (summary != null)
                {
                    object s = summary.Invoke(target, null);
                    if (s != null)
                    {
                        Type iSummary = asm.GetType("Microsoft.UpdateServices.Administration.IUpdateInstallationSummary", false);
                        foreach (string prop in new[] { "InstalledCount", "InstalledPendingRebootCount", "NotInstalledCount", "DownloadedCount", "FailedCount", "UnknownCount", "NotApplicableCount" })
                        {
                            object val = GetProp(s, iSummary, prop);
                            result[prop] = val == null ? null : Convert.ToString(val, CultureInfo.InvariantCulture);
                        }
                    }
                }
                return result;
            }
            catch (Exception ex)
            {
                Exception inner = ex is TargetInvocationException && ex.InnerException != null ? ex.InnerException : ex;
                error = "WSUS query failed: " + inner.Message;
                return null;
            }
        }

        private static object GetProp(object obj, Type iface, string name)
        {
            try
            {
                PropertyInfo pi = null;
                if (iface != null) pi = iface.GetProperty(name);
                if (pi == null) pi = obj.GetType().GetProperty(name);
                if (pi == null)
                {
                    foreach (Type t in obj.GetType().GetInterfaces())
                    {
                        pi = t.GetProperty(name);
                        if (pi != null) break;
                    }
                }
                return pi == null ? null : pi.GetValue(obj, null);
            }
            catch { return null; }
        }
    }
}

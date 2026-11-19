// UpdateHealthKit analyzer - Microsoft reference data:
//  * Windows release health pages (latest monthly security build per OS version, end of servicing)
//  * .NET release metadata feeds (latest patch per channel, support phase, security releases)
// C# 5 compatible.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace UpdateHealthKit
{
    internal sealed class MicrosoftData
    {
        public const string Win11Url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information";
        public const string Win10Url = "https://learn.microsoft.com/en-us/windows/release-health/release-information";

        public readonly WebCache Cache;
        public readonly WindowsReleaseCatalog Windows = new WindowsReleaseCatalog();
        public readonly DotNetCatalog DotNet;

        public MicrosoftData(WebCache cache)
        {
            Cache = cache;
            DotNet = new DotNetCatalog(cache);
        }

        public void LoadWindows()
        {
            Windows.Parse(Cache.Get("windows11-release-information.html", Win11Url));
            Windows.Parse(Cache.Get("windows10-release-information.html", Win10Url));
        }

        public void LoadDotNetIndex()
        {
            DotNet.LoadIndex();
        }

        public string SourceText(string name)
        {
            string s;
            return Cache.Sources.TryGetValue(name, out s) ? s : "not loaded";
        }
    }

    internal sealed class OsRelease
    {
        public int Major;
        public int Ubr;
        public string Kb;
        public string Date;
        public string Type;        // B (monthly security), Preview (C/D), OOB, Unknown
        public string RawType;
        public string VersionName; // e.g. 24H2

        public DateTime? DateValue
        {
            get
            {
                DateTime d;
                if (DateTime.TryParse(Date, CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) return d;
                return null;
            }
        }

        public string BuildText { get { return Major + "." + Ubr; } }
    }

    internal sealed class OsVersionRow
    {
        public string Version;
        public string Channel;
        public string Availability;
        public string EosHomePro;
        public string EosEnterprise;
        public string LatestUpdate;
        public string LatestRevisionDate;
        public int Major;
        public int LatestUbr;
        public bool IsLtsc { get { return Channel != null && (Channel.IndexOf("Long", StringComparison.OrdinalIgnoreCase) >= 0 || Channel.IndexOf("LTSC", StringComparison.OrdinalIgnoreCase) >= 0); } }
    }

    /// <summary>Parses the Windows release health "release information" pages.</summary>
    internal sealed class WindowsReleaseCatalog
    {
        public readonly List<OsVersionRow> Versions = new List<OsVersionRow>();
        public readonly Dictionary<int, List<OsRelease>> Releases = new Dictionary<int, List<OsRelease>>();

        public bool Loaded { get { return Versions.Count > 0 || Releases.Count > 0; } }

        public void Parse(string html)
        {
            if (string.IsNullOrEmpty(html)) return;

            var headings = new List<KeyValuePair<int, string>>();
            foreach (Match m in Regex.Matches(html, @"<h2[^>]*>([\s\S]*?)</h2>", RegexOptions.IgnoreCase))
                headings.Add(new KeyValuePair<int, string>(m.Index, Clean(m.Groups[1].Value)));

            var versionMarks = new List<KeyValuePair<int, string>>();
            foreach (Match m in Regex.Matches(html, @"Version\s+([0-9]{2}H[0-9]|[0-9]{4}|LTSC\s?\d{4})\s*\(OS build (\d{5})\)", RegexOptions.IgnoreCase))
                versionMarks.Add(new KeyValuePair<int, string>(m.Index, m.Groups[1].Value));

            foreach (Match t in Regex.Matches(html, @"<table[\s\S]*?</table>", RegexOptions.IgnoreCase))
            {
                string section = "";
                foreach (var kv in headings) { if (kv.Key < t.Index) section = kv.Value; else break; }
                string versionName = null;
                foreach (var kv in versionMarks) { if (kv.Key < t.Index) versionName = kv.Value; else break; }

                List<string> header = null;
                var rows = new List<List<string>>();
                foreach (Match r in Regex.Matches(t.Value, @"<tr[\s\S]*?</tr>", RegexOptions.IgnoreCase))
                {
                    var cells = new List<string>();
                    bool isHeader = false;
                    foreach (Match c in Regex.Matches(r.Value, @"<t([hd])[^>]*>([\s\S]*?)</t[hd]>", RegexOptions.IgnoreCase))
                    {
                        if (c.Groups[1].Value.Equals("h", StringComparison.OrdinalIgnoreCase)) isHeader = true;
                        cells.Add(Clean(c.Groups[2].Value));
                    }
                    if (cells.Count == 0) continue;
                    if (header == null && isHeader) { header = cells; continue; }
                    rows.Add(cells);
                }
                if (header == null) continue;

                bool hotpatch = section.IndexOf("hotpatch", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                header.Any(h => h.IndexOf("hotpatch", StringComparison.OrdinalIgnoreCase) >= 0);

                if (Find(header, "Latest build") >= 0)
                {
                    ParseSummary(header, rows);
                    continue;
                }
                if (hotpatch) continue;

                int iBuild = Find(header, "Build");
                int iKb = Find(header, "KB article");
                if (iKb < 0) iKb = Find(header, "KB");
                if (iBuild < 0 || iKb < 0) continue;
                int iType = Find(header, "Update type");
                int iDate = Find(header, "Availability date");
                if (iDate < 0) iDate = Find(header, "date");

                foreach (var row in rows)
                {
                    if (row.Count <= Math.Max(iBuild, iKb)) continue;
                    if (row.Any(x => x.IndexOf("hotpatch", StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                    var bm = Regex.Match(row[iBuild], @"^(\d{5})\.(\d+)");
                    if (!bm.Success) continue;
                    var km = Regex.Match(row[iKb], @"KB\s?(\d{6,8})", RegexOptions.IgnoreCase);
                    if (!km.Success) continue;
                    string rawType = (iType >= 0 && iType < row.Count) ? row[iType] : null;
                    Add(new OsRelease
                    {
                        Major = int.Parse(bm.Groups[1].Value, CultureInfo.InvariantCulture),
                        Ubr = int.Parse(bm.Groups[2].Value, CultureInfo.InvariantCulture),
                        Kb = "KB" + km.Groups[1].Value,
                        Date = (iDate >= 0 && iDate < row.Count) ? row[iDate] : null,
                        RawType = rawType,
                        Type = NormalizeType(rawType),
                        VersionName = versionName
                    });
                }
            }
        }

        private void ParseSummary(List<string> header, List<List<string>> rows)
        {
            int iVer = Find(header, "Version");
            int iSvc = Find(header, "Servicing option");
            int iAvail = Find(header, "Availability date");
            int iHome = -1, iEnt = -1, iExt = -1;
            for (int i = 0; i < header.Count; i++)
            {
                string h = header[i];
                if (iHome < 0 && h.IndexOf("Home", StringComparison.OrdinalIgnoreCase) >= 0) iHome = i;
                else if (iEnt < 0 && h.IndexOf("Enterprise", StringComparison.OrdinalIgnoreCase) >= 0 &&
                         (h.IndexOf("End", StringComparison.OrdinalIgnoreCase) >= 0 || h.IndexOf("support", StringComparison.OrdinalIgnoreCase) >= 0)) iEnt = i;
                if (iExt < 0 && h.IndexOf("Extended", StringComparison.OrdinalIgnoreCase) >= 0) iExt = i;
            }
            if (iExt >= 0) iEnt = iExt;
            if (iEnt < 0)
            {
                for (int i = 0; i < header.Count; i++)
                    if (i != iHome && header[i].IndexOf("End of", StringComparison.OrdinalIgnoreCase) >= 0) { iEnt = i; break; }
            }
            int iLatestUpd = Find(header, "Latest update");
            int iLatestRev = Find(header, "Latest revision date");
            int iLatestBuild = Find(header, "Latest build");

            foreach (var row in rows)
            {
                if (iLatestBuild < 0 || iLatestBuild >= row.Count) continue;
                var bm = Regex.Match(row[iLatestBuild], @"(\d{5})\.(\d+)");
                if (!bm.Success) continue;
                Versions.Add(new OsVersionRow
                {
                    Version = Cell(row, iVer),
                    Channel = Cell(row, iSvc),
                    Availability = Cell(row, iAvail),
                    EosHomePro = Cell(row, iHome),
                    EosEnterprise = Cell(row, iEnt),
                    LatestUpdate = Cell(row, iLatestUpd),
                    LatestRevisionDate = Cell(row, iLatestRev),
                    Major = int.Parse(bm.Groups[1].Value, CultureInfo.InvariantCulture),
                    LatestUbr = int.Parse(bm.Groups[2].Value, CultureInfo.InvariantCulture)
                });
            }
        }

        private void Add(OsRelease rel)
        {
            List<OsRelease> list;
            if (!Releases.TryGetValue(rel.Major, out list)) { list = new List<OsRelease>(); Releases[rel.Major] = list; }
            if (list.Any(x => x.Ubr == rel.Ubr)) return;
            list.Add(rel);
        }

        public OsVersionRow FindVersion(int major, bool ltsc)
        {
            var candidates = Versions.Where(v => v.Major == major).ToList();
            if (candidates.Count == 0) return null;
            var pick = candidates.FirstOrDefault(v => v.IsLtsc == ltsc);
            return pick ?? candidates[0];
        }

        /// <summary>All releases for a build, newest first.</summary>
        public List<OsRelease> GetReleases(int major)
        {
            List<OsRelease> l;
            if (!Releases.TryGetValue(major, out l)) return new List<OsRelease>();
            return l.OrderByDescending(r => r.Ubr).ToList();
        }

        /// <summary>Newest general-availability version for Windows 10 (major below 22000) or Windows 11.</summary>
        public OsVersionRow NewestVersion(bool windows11)
        {
            return Versions.Where(v => (v.Major >= 22000) == windows11 && !v.IsLtsc)
                           .OrderByDescending(v => v.Availability ?? "")
                           .FirstOrDefault();
        }

        private static string NormalizeType(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return "Unknown";
            string s = raw.Trim();
            if (s.IndexOf("OOB", StringComparison.OrdinalIgnoreCase) >= 0) return "OOB";
            if (Regex.IsMatch(s, @"(^|\s)B$", RegexOptions.IgnoreCase)) return "B";
            if (Regex.IsMatch(s, @"(^|\s)[CD]$", RegexOptions.IgnoreCase)) return "Preview";
            return "Unknown";
        }

        private static string Cell(List<string> row, int i)
        {
            return (i >= 0 && i < row.Count) ? row[i] : null;
        }

        private static int Find(List<string> header, string name)
        {
            for (int i = 0; i < header.Count; i++)
                if (header[i].Equals(name, StringComparison.OrdinalIgnoreCase)) return i;
            for (int i = 0; i < header.Count; i++)
                if (header[i].IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0) return i;
            return -1;
        }

        internal static string Clean(string html)
        {
            string s = Regex.Replace(html ?? "", @"<[^>]+>", " ");
            s = WebUtility.HtmlDecode(s);
            s = Regex.Replace(s, @"\s+", " ");
            return s.Trim();
        }
    }

    internal sealed class DotNetRelease
    {
        public string Version;
        public string Date;
        public bool Security;
        public int CveCount;
        public string Runtime;
        public string AspNetCore;
        public string WindowsDesktop;
        public readonly List<string> Sdks = new List<string>();

        public string Component(string kind)
        {
            switch (kind)
            {
                case "Runtime": return Runtime;
                case "AspNetCore": return AspNetCore;
                case "WindowsDesktop": return WindowsDesktop;
                default: return null;
            }
        }
    }

    internal sealed class DotNetChannel
    {
        public string Channel;
        public string LatestRelease;
        public string LatestReleaseDate;
        public string LatestRuntime;
        public string LatestSdk;
        public string SupportPhase;
        public string EolDate;
        public string ReleaseType;
        public string ReleasesUrl;
        public bool ReleasesLoaded;
        public readonly List<DotNetRelease> Releases = new List<DotNetRelease>();

        public bool IsEol
        {
            get
            {
                if (string.Equals(SupportPhase, "eol", StringComparison.OrdinalIgnoreCase)) return true;
                DateTime d;
                return DateTime.TryParse(EolDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out d) && d.Date < DateTime.Today;
            }
        }
    }

    internal sealed class DotNetCatalog
    {
        private const string IndexUrl = "https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json";
        private const string IndexUrlLegacy = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json";

        private readonly WebCache cache;
        public readonly Dictionary<string, DotNetChannel> Channels = new Dictionary<string, DotNetChannel>(StringComparer.OrdinalIgnoreCase);

        public DotNetCatalog(WebCache cache) { this.cache = cache; }

        public bool Loaded { get { return Channels.Count > 0; } }

        public bool LoadIndex()
        {
            string text = cache.Get("dotnet-releases-index.json", IndexUrl, IndexUrlLegacy);
            if (text == null) return false;
            try
            {
                object root = J.Parse(text);
                foreach (object item in J.A(root, "releases-index"))
                {
                    var ch = new DotNetChannel
                    {
                        Channel = J.S(item, "channel-version"),
                        LatestRelease = J.S(item, "latest-release"),
                        LatestReleaseDate = J.S(item, "latest-release-date"),
                        LatestRuntime = J.S(item, "latest-runtime"),
                        LatestSdk = J.S(item, "latest-sdk"),
                        SupportPhase = J.S(item, "support-phase"),
                        EolDate = J.S(item, "eol-date"),
                        ReleaseType = J.S(item, "release-type"),
                        ReleasesUrl = Convert.ToString(J.Key(item, "releases.json"), CultureInfo.InvariantCulture)
                    };
                    if (!string.IsNullOrEmpty(ch.Channel)) Channels[ch.Channel] = ch;
                }
            }
            catch (Exception ex)
            {
                cache.Notes.Add(".NET releases index could not be parsed: " + ex.Message);
            }
            return Channels.Count > 0;
        }

        /// <summary>Returns the channel with its releases.json loaded (downloaded once, cached).</summary>
        public DotNetChannel GetChannel(string channel)
        {
            if (string.IsNullOrEmpty(channel)) return null;
            DotNetChannel ch;
            if (!Channels.TryGetValue(channel, out ch)) return null;
            if (ch.ReleasesLoaded) return ch;
            ch.ReleasesLoaded = true;
            if (string.IsNullOrEmpty(ch.ReleasesUrl)) return ch;

            string alt = ch.ReleasesUrl.Replace("https://builds.dotnet.microsoft.com", "https://dotnetcli.blob.core.windows.net");
            string text = cache.Get("dotnet-" + channel + "-releases.json", ch.ReleasesUrl, alt == ch.ReleasesUrl ? null : alt);
            if (text == null) return ch;
            try
            {
                object root = J.Parse(text);
                foreach (object r in J.A(root, "releases"))
                {
                    var rel = new DotNetRelease
                    {
                        Version = J.S(r, "release-version"),
                        Date = J.S(r, "release-date"),
                        Security = J.B(r, "security"),
                        CveCount = J.A(r, "cve-list").Count,
                        Runtime = J.S(r, "runtime.version"),
                        AspNetCore = J.S(r, "aspnetcore-runtime.version"),
                        WindowsDesktop = J.S(r, "windowsdesktop.version")
                    };
                    foreach (object s in J.A(r, "sdks"))
                    {
                        string v = J.S(s, "version");
                        if (v != null && !rel.Sdks.Contains(v)) rel.Sdks.Add(v);
                    }
                    string sdk1 = J.S(r, "sdk.version");
                    if (sdk1 != null && !rel.Sdks.Contains(sdk1)) rel.Sdks.Add(sdk1);
                    ch.Releases.Add(rel);
                }
            }
            catch (Exception ex)
            {
                cache.Notes.Add(".NET " + channel + " releases.json could not be parsed: " + ex.Message);
            }
            return ch;
        }

        /// <summary>Newest supported LTS channel (e.g. "10.0").</summary>
        public string NewestLts()
        {
            return Ver.Max(Channels.Values
                .Where(c => string.Equals(c.ReleaseType, "lts", StringComparison.OrdinalIgnoreCase) && !c.IsEol &&
                            !string.Equals(c.SupportPhase, "preview", StringComparison.OrdinalIgnoreCase) &&
                            !string.Equals(c.SupportPhase, "go-live", StringComparison.OrdinalIgnoreCase))
                .Select(c => c.Channel));
        }
    }
}

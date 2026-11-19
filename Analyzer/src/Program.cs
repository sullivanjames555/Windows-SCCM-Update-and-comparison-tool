// UpdateHealthKit analyzer - entry point, options, bundle loading, web cache.
// Written for the C# 5 compiler that ships with .NET Framework 4.8 (csc.exe in
// %WINDIR%\Microsoft.NET\Framework64\v4.0.30319), so no Visual Studio is required.
// Keep to C# 5 syntax: no string interpolation, no ?. operator, no expression-bodied members.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;

[assembly: AssemblyTitle("UpdateHealthKit Analyzer")]
[assembly: AssemblyDescription("Compares UpdateHealthKit collector bundles with Microsoft release data and ConfigMgr/WSUS.")]
[assembly: AssemblyProduct("UpdateHealthKit")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace UpdateHealthKit
{
    internal static class Program
    {
        public const string Version = "1.0.0";

        private static int Main(string[] args)
        {
            Options opt;
            string parseError;
            if (!Options.TryParse(args, out opt, out parseError))
            {
                if (parseError != null) Console.Error.WriteLine("ERROR: " + parseError);
                Options.PrintUsage();
                return 2;
            }

            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }
            try
            {
                if (WebRequest.DefaultWebProxy != null) WebRequest.DefaultWebProxy.Credentials = CredentialCache.DefaultCredentials;
            }
            catch { }

            Console.WriteLine("UpdateHealthKit analyzer " + Version);

            string outRoot = opt.OutputDir ?? Path.Combine(Environment.CurrentDirectory, "UpdateHealthReports");
            Directory.CreateDirectory(outRoot);

            var warnings = new List<string>();
            List<string> bundles = BundleLoader.Resolve(opt.Inputs, outRoot, warnings);
            foreach (var w in warnings) Console.WriteLine("WARNING: " + w);
            if (bundles.Count == 0)
            {
                Console.Error.WriteLine("ERROR: no collection.json found in the given input(s).");
                return 1;
            }
            Console.WriteLine("Bundles to analyze: " + bundles.Count);

            // Microsoft reference data (shared by all bundles)
            string cacheDir = opt.CacheDir ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cache");
            var cache = new WebCache(cacheDir, opt.Offline, opt.CacheMaxAgeHours);
            var ms = new MicrosoftData(cache);
            Console.WriteLine(opt.Offline ? "Offline mode: using cached Microsoft data only." : "Downloading Microsoft release data...");
            ms.LoadWindows();
            ms.LoadDotNetIndex();

            // SCCM / WSUS
            SccmServer sccm = null;
            if (!string.IsNullOrEmpty(opt.SiteServer))
            {
                Console.WriteLine("Connecting to SMS Provider " + opt.SiteServer + "...");
                sccm = new SccmServer(opt.SiteServer, opt.SiteCode);
                if (sccm.Connect()) Console.WriteLine("  Connected to site " + sccm.SiteCode + (sccm.SiteVersion != null ? " (version " + sccm.SiteVersion + ")" : ""));
                else Console.WriteLine("  WARNING: could not connect: " + sccm.Error);
            }

            var summaries = new List<AnalysisResult>();
            int failures = 0;
            foreach (string bundle in bundles)
            {
                try
                {
                    Console.WriteLine();
                    Console.WriteLine("Analyzing " + bundle);
                    object data = J.Load(bundle);
                    var analyzer = new Analyzer(data, ms, sccm, opt);
                    AnalysisResult result = analyzer.Run();
                    result.BundlePath = bundle;

                    string folderName = Safe(result.ComputerName ?? "UNKNOWN") + "_" +
                        (result.CollectedAt.HasValue ? result.CollectedAt.Value.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) : "nodate");
                    string dir = Path.Combine(outRoot, folderName);
                    Directory.CreateDirectory(dir);
                    string html = Path.Combine(dir, "UpdateHealthReport.html");
                    string json = Path.Combine(dir, "analysis.json");
                    File.WriteAllText(html, HtmlReport.Build(result, ms), new UTF8Encoding(false));
                    File.WriteAllText(json, J.Pretty(J.Serialize(result.ToDictionary())), new UTF8Encoding(false));
                    result.ReportPath = html;
                    summaries.Add(result);

                    Console.WriteLine(string.Format("  {0}: Critical {1}, High {2}, Medium {3}, Low {4}",
                        result.ComputerName, result.Count(Sev.Critical), result.Count(Sev.High), result.Count(Sev.Medium), result.Count(Sev.Low)));
                    foreach (var f in result.Findings.Where(x => Sev.Rank(x.Severity) <= 1).Take(8))
                        Console.WriteLine("    [" + f.Severity + "] " + f.Title);
                    Console.WriteLine("  Report: " + html);
                }
                catch (Exception ex)
                {
                    failures++;
                    Console.Error.WriteLine("  ERROR analyzing " + bundle + ": " + ex);
                }
            }

            if (summaries.Count > 1)
            {
                string index = Path.Combine(outRoot, "index.html");
                File.WriteAllText(index, HtmlReport.BuildIndex(summaries, outRoot), new UTF8Encoding(false));
                Console.WriteLine();
                Console.WriteLine("Summary: " + index);
                if (opt.OpenReport) TryOpen(index);
            }
            else if (summaries.Count == 1 && opt.OpenReport)
            {
                TryOpen(summaries[0].ReportPath);
            }

            foreach (var n in cache.Notes) Console.WriteLine("NOTE: " + n);
            return failures > 0 ? 1 : 0;
        }

        private static void TryOpen(string path)
        {
            try { Process.Start(path); } catch { }
        }

        internal static string Safe(string s)
        {
            var sb = new StringBuilder();
            foreach (char ch in s) sb.Append(Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch);
            return sb.ToString();
        }
    }

    internal sealed class Options
    {
        public List<string> Inputs = new List<string>();
        public string OutputDir;
        public string SiteServer;
        public string SiteCode;
        public string WsusServer;
        public int WsusPort = 8530;
        public bool WsusSsl;
        public bool Offline;
        public string CacheDir;
        public int CacheMaxAgeHours = 12;
        public bool OpenReport;

        public static bool TryParse(string[] args, out Options o, out string error)
        {
            o = new Options();
            error = null;
            if (args == null || args.Length == 0) return false;
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i];
                    bool isSwitch = a.StartsWith("-") || (a.StartsWith("/") && a.Length > 1 && !a.Contains("\\"));
                    if (!isSwitch) { o.Inputs.Add(a); continue; }
                    string key = a.TrimStart('-', '/').ToLowerInvariant();
                    switch (key)
                    {
                        case "input": case "i": case "path": o.Inputs.Add(Next(args, ref i, a)); break;
                        case "output": case "o": case "outputdir": o.OutputDir = Next(args, ref i, a); break;
                        case "siteserver": case "smsprovider": case "server": o.SiteServer = Next(args, ref i, a); break;
                        case "sitecode": o.SiteCode = Next(args, ref i, a); break;
                        case "wsusserver": case "wsus": o.WsusServer = Next(args, ref i, a); break;
                        case "wsusport": o.WsusPort = int.Parse(Next(args, ref i, a), CultureInfo.InvariantCulture); break;
                        case "wsusssl": o.WsusSsl = true; break;
                        case "offline": o.Offline = true; break;
                        case "cachedir": o.CacheDir = Next(args, ref i, a); break;
                        case "cachehours": o.CacheMaxAgeHours = int.Parse(Next(args, ref i, a), CultureInfo.InvariantCulture); break;
                        case "open": o.OpenReport = true; break;
                        case "help": case "h": case "?": return false;
                        default: error = "Unknown argument: " + a; return false;
                    }
                }
            }
            catch (Exception ex) { error = ex.Message; return false; }
            if (o.Inputs.Count == 0) { error = "No -Input given."; return false; }
            return true;
        }

        private static string Next(string[] args, ref int i, string name)
        {
            if (i + 1 >= args.Length) throw new ArgumentException("Missing value for " + name);
            i++;
            return args[i];
        }

        public static void PrintUsage()
        {
            Console.WriteLine(@"
UpdateHealthAnalyzer.exe -Input <bundle.zip | bundle folder | folder of bundles> [options]

  -Input <path>        Collector output: the .zip, the folder, collection.json, or a folder
                       containing many bundles (repeatable).
  -Output <folder>     Where to write reports. Default: .\UpdateHealthReports
  -SiteServer <name>   SMS Provider (usually the primary site server) to compare against.
  -SiteCode <code>     Site code. Auto-detected from the SMS Provider if omitted.
  -WsusServer <name>   Optional: WSUS/SUP server to look the device up in (needs the WSUS
                       console / RSAT 'Windows Server Update Services Tools' on this PC).
  -WsusPort <port>     WSUS port. Default 8530 (8531 for SSL).
  -WsusSsl             Connect to WSUS over SSL.
  -Offline             Don't download; use the cached Microsoft data in .\cache.
  -CacheDir <folder>   Cache location. Default: .\cache next to the exe.
  -CacheHours <n>      Re-download Microsoft data older than n hours. Default 12.
  -Open                Open the report when done.

Example:
  UpdateHealthAnalyzer.exe -Input E:\UpdateHealth_PC123_20261119-101500.zip -SiteServer CM01 -Open
");
        }
    }

    internal static class BundleLoader
    {
        public static List<string> Resolve(IEnumerable<string> inputs, string workDir, List<string> warnings)
        {
            var result = new List<string>();
            foreach (string raw in inputs)
            {
                string p;
                try { p = Path.GetFullPath(Environment.ExpandEnvironmentVariables(raw.Trim('"'))); }
                catch (Exception ex) { warnings.Add("Bad path '" + raw + "': " + ex.Message); continue; }

                if (File.Exists(p))
                {
                    if (p.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                    {
                        string j = ExtractZip(p, workDir, warnings);
                        if (j != null) result.Add(j);
                    }
                    else if (Path.GetFileName(p).Equals("collection.json", StringComparison.OrdinalIgnoreCase)) result.Add(p);
                    else warnings.Add("Unsupported file (expected .zip or collection.json): " + p);
                }
                else if (Directory.Exists(p))
                {
                    string direct = Path.Combine(p, "collection.json");
                    if (File.Exists(direct)) { result.Add(direct); continue; }
                    foreach (string f in Directory.GetFiles(p, "collection.json", SearchOption.AllDirectories))
                    {
                        if (f.IndexOf("\\_extracted\\", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                        result.Add(f);
                    }
                    foreach (string z in Directory.GetFiles(p, "*.zip", SearchOption.TopDirectoryOnly))
                    {
                        string sibling = Path.Combine(Path.GetDirectoryName(z), Path.GetFileNameWithoutExtension(z));
                        if (File.Exists(Path.Combine(sibling, "collection.json"))) continue; // already picked up unzipped
                        string j = ExtractZip(z, workDir, warnings);
                        if (j != null) result.Add(j);
                    }
                }
                else warnings.Add("Not found: " + p);
            }
            return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static string ExtractZip(string zip, string workDir, List<string> warnings)
        {
            try
            {
                string dest = Path.Combine(Path.Combine(workDir, "_extracted"), Path.GetFileNameWithoutExtension(zip));
                if (Directory.Exists(dest)) Directory.Delete(dest, true);
                Directory.CreateDirectory(dest);
                ZipFile.ExtractToDirectory(zip, dest);
                string[] found = Directory.GetFiles(dest, "collection.json", SearchOption.AllDirectories);
                if (found.Length == 0) { warnings.Add("No collection.json inside " + zip); return null; }
                return found[0];
            }
            catch (Exception ex)
            {
                warnings.Add("Could not extract " + zip + ": " + ex.Message);
                return null;
            }
        }
    }

    /// <summary>Downloads text and keeps a copy so the analyzer can also run offline later.</summary>
    internal sealed class WebCache
    {
        private readonly string dir;
        private readonly bool offline;
        private readonly int maxAgeHours;
        public readonly List<string> Notes = new List<string>();
        public readonly Dictionary<string, string> Sources = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public WebCache(string dir, bool offline, int maxAgeHours)
        {
            this.dir = dir;
            this.offline = offline;
            this.maxAgeHours = maxAgeHours;
            try { Directory.CreateDirectory(dir); } catch { }
        }

        public string Get(string name, params string[] urls)
        {
            string cacheFile = Path.Combine(dir, name);
            if (!offline)
            {
                if (File.Exists(cacheFile) && (DateTime.Now - File.GetLastWriteTime(cacheFile)).TotalHours < maxAgeHours)
                {
                    Sources[name] = "cache (downloaded " + File.GetLastWriteTime(cacheFile).ToString("yyyy-MM-dd HH:mm") + ")";
                    return File.ReadAllText(cacheFile);
                }
                foreach (string url in urls)
                {
                    if (string.IsNullOrEmpty(url)) continue;
                    try
                    {
                        string text = Download(url);
                        try { File.WriteAllText(cacheFile, text, new UTF8Encoding(false)); } catch { }
                        Sources[name] = "live download " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + " from " + url;
                        return text;
                    }
                    catch (Exception ex)
                    {
                        Notes.Add("Download failed for " + url + ": " + ex.Message);
                    }
                }
            }
            if (File.Exists(cacheFile))
            {
                string stamp = File.GetLastWriteTime(cacheFile).ToString("yyyy-MM-dd HH:mm");
                Sources[name] = "cached copy from " + stamp + " (live download not used)";
                Notes.Add("Using cached copy of " + name + " from " + stamp);
                return File.ReadAllText(cacheFile);
            }
            Sources[name] = "unavailable";
            return null;
        }

        private static string Download(string url)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.UserAgent = "UpdateHealthKit/" + Program.Version;
            req.Timeout = 30000;
            req.ReadWriteTimeout = 60000;
            req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            req.UseDefaultCredentials = true;
            if (req.Proxy != null) req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                return sr.ReadToEnd();
            }
        }
    }
}

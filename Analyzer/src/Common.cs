// UpdateHealthKit analyzer - JSON helpers, version helpers, severities, error-code lookup.
// C# 5 compatible.

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace UpdateHealthKit
{
    /// <summary>Loose, null-safe navigation over JavaScriptSerializer output (Dictionary/object[]).</summary>
    internal static class J
    {
        public static object Load(string path)
        {
            return Parse(File.ReadAllText(path));
        }

        public static object Parse(string text)
        {
            var s = new JavaScriptSerializer();
            s.MaxJsonLength = int.MaxValue;
            s.RecursionLimit = 512;
            return s.DeserializeObject(text);
        }

        public static string Serialize(object o)
        {
            var s = new JavaScriptSerializer();
            s.MaxJsonLength = int.MaxValue;
            s.RecursionLimit = 512;
            return s.Serialize(o);
        }

        /// <summary>Direct key lookup (case-insensitive fallback). Use for keys that contain dots.</summary>
        public static object Key(object o, string key)
        {
            var d = o as IDictionary<string, object>;
            if (d == null || key == null) return null;
            object v;
            if (d.TryGetValue(key, out v)) return v;
            foreach (var kv in d)
                if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) return kv.Value;
            return null;
        }

        /// <summary>Dotted path lookup, e.g. "Sccm.UpdateSource.ContentLocation".</summary>
        public static object Get(object o, string path)
        {
            if (path == null) return o;
            object cur = o;
            foreach (string part in path.Split('.'))
            {
                cur = Key(cur, part);
                if (cur == null) return null;
            }
            return cur;
        }

        public static string S(object o, string path)
        {
            object v = Get(o, path);
            if (v == null) return null;
            if (v is DateTime) return ((DateTime)v).ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            if (v is bool) return (bool)v ? "True" : "False";
            if (v is IDictionary<string, object> || (v is IEnumerable && !(v is string))) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            return s;
        }

        public static long? L(object o, string path)
        {
            object v = Get(o, path);
            if (v == null) return null;
            if (v is int) return (int)v;
            if (v is long) return (long)v;
            if (v is decimal) return (long)(decimal)v;
            if (v is double) return (long)(double)v;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture);
            long r;
            if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out r)) return r;
            double d;
            if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return (long)d;
            return null;
        }

        public static int? I(object o, string path)
        {
            long? l = L(o, path);
            if (!l.HasValue) return null;
            if (l.Value > int.MaxValue || l.Value < int.MinValue) return null;
            return (int)l.Value;
        }

        public static double? D(object o, string path)
        {
            object v = Get(o, path);
            if (v == null) return null;
            if (v is decimal) return (double)(decimal)v;
            if (v is int) return (int)v;
            if (v is long) return (long)v;
            if (v is double) return (double)v;
            double d;
            if (double.TryParse(Convert.ToString(v, CultureInfo.InvariantCulture), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d;
            return null;
        }

        public static bool B(object o, string path)
        {
            bool? b = BN(o, path);
            return b.HasValue && b.Value;
        }

        public static bool? BN(object o, string path)
        {
            object v = Get(o, path);
            if (v == null) return null;
            if (v is bool) return (bool)v;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture).Trim();
            if (s == "1" || s.Equals("true", StringComparison.OrdinalIgnoreCase)) return true;
            if (s == "0" || s.Equals("false", StringComparison.OrdinalIgnoreCase)) return false;
            return null;
        }

        public static List<object> A(object o, string path)
        {
            object v = Get(o, path);
            var list = new List<object>();
            if (v == null) return list;
            if (v is string || v is IDictionary<string, object>) { list.Add(v); return list; }
            var e = v as IEnumerable;
            if (e != null) { foreach (object x in e) if (x != null) list.Add(x); return list; }
            list.Add(v);
            return list;
        }

        public static IDictionary<string, object> Dict(object o, string path)
        {
            return Get(o, path) as IDictionary<string, object>;
        }

        public static DateTime? T(object o, string path)
        {
            object v = Get(o, path);
            if (v is DateTime) return ((DateTime)v).ToLocalTime();
            return ParseDate(v == null ? null : Convert.ToString(v, CultureInfo.InvariantCulture));
        }

        public static DateTime? ParseDate(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            var m = Regex.Match(s, @"Date\((-?\d+)");
            if (m.Success)
                return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)).ToLocalTime();
            DateTimeOffset dto;
            if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out dto)) return dto.LocalDateTime;
            DateTime dt;
            if (DateTime.TryParse(s, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out dt)) return dt;
            return null;
        }

        public static string Fmt(DateTime? d)
        {
            return d.HasValue ? d.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) : null;
        }

        public static string FmtDay(DateTime? d)
        {
            return d.HasValue ? d.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : null;
        }

        /// <summary>Indents compact JSON for readability.</summary>
        public static string Pretty(string json)
        {
            var sb = new StringBuilder(json.Length + json.Length / 4);
            int indent = 0;
            bool inString = false;
            for (int i = 0; i < json.Length; i++)
            {
                char c = json[i];
                if (inString)
                {
                    sb.Append(c);
                    if (c == '\\' && i + 1 < json.Length) { sb.Append(json[++i]); continue; }
                    if (c == '"') inString = false;
                    continue;
                }
                switch (c)
                {
                    case '"': inString = true; sb.Append(c); break;
                    case '{':
                    case '[':
                        sb.Append(c);
                        indent++;
                        sb.Append('\n').Append(' ', indent * 2);
                        break;
                    case '}':
                    case ']':
                        indent = Math.Max(0, indent - 1);
                        sb.Append('\n').Append(' ', indent * 2).Append(c);
                        break;
                    case ',':
                        sb.Append(c).Append('\n').Append(' ', indent * 2);
                        break;
                    case ':':
                        sb.Append(": ");
                        break;
                    default:
                        if (!char.IsWhiteSpace(c)) sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }

    internal static class Sev
    {
        public const string Critical = "Critical";
        public const string High = "High";
        public const string Medium = "Medium";
        public const string Low = "Low";
        public const string Info = "Info";
        public const string OK = "OK";

        public static int Rank(string s)
        {
            switch (s)
            {
                case Critical: return 0;
                case High: return 1;
                case Medium: return 2;
                case Low: return 3;
                case Info: return 4;
                default: return 5;
            }
        }

        public static string Normalize(string s)
        {
            if (string.IsNullOrEmpty(s)) return Info;
            foreach (string x in new[] { Critical, High, Medium, Low, Info, OK })
                if (string.Equals(x, s, StringComparison.OrdinalIgnoreCase)) return x;
            return Info;
        }
    }

    internal static class Ver
    {
        public static Version Parse(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            var m = Regex.Match(s, @"^\s*(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?");
            if (!m.Success) return null;
            try
            {
                int a = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                int b = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
                int c = m.Groups[3].Success ? int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture) : 0;
                int d = m.Groups[4].Success ? int.Parse(m.Groups[4].Value, CultureInfo.InvariantCulture) : 0;
                return new Version(a, b, c, d);
            }
            catch { return null; }
        }

        public static bool IsPreview(string s)
        {
            return s != null && s.IndexOf('-') >= 0;
        }

        /// <summary>Compares x to y; preview builds sort below the release with the same numbers.</summary>
        public static int Compare(string x, string y)
        {
            Version a = Parse(x), b = Parse(y);
            if (a == null && b == null) return 0;
            if (a == null) return -1;
            if (b == null) return 1;
            int c = a.CompareTo(b);
            if (c != 0) return c;
            bool pa = IsPreview(x), pb = IsPreview(y);
            if (pa && !pb) return -1;
            if (!pa && pb) return 1;
            return 0;
        }

        public static string Max(IEnumerable<string> versions)
        {
            string best = null;
            foreach (string v in versions)
            {
                if (string.IsNullOrEmpty(v)) continue;
                if (best == null || Compare(v, best) > 0) best = v;
            }
            return best;
        }

        public static string Channel(string version)
        {
            Version v = Parse(version);
            return v == null ? null : v.Major + "." + v.Minor;
        }
    }

    internal static class ErrorCodes
    {
        private static readonly Dictionary<uint, string> Known = new Dictionary<uint, string>
        {
            // Windows Update Agent
            { 0x80240022, "WU_E_ALL_UPDATES_FAILED: every update in the operation failed" },
            { 0x8024000B, "WU_E_CALL_CANCELLED: operation cancelled (often a restart or service stop mid-job)" },
            { 0x80240017, "WU_E_NOT_APPLICABLE: update not applicable to this device" },
            { 0x8024001E, "WU_E_SERVICE_STOP: the Windows Update service stopped" },
            { 0x8024002E, "WU_E_WU_DISABLED: access to an unmanaged server is not allowed (policy)" },
            { 0x80240FFF, "WU_E_UNEXPECTED: unexpected WUA error" },
            { 0x80244007, "WU_E_PT_SOAPCLIENT_SOAPFAULT: SOAP fault from WSUS (often needs WSUS cleanup/reindex or client re-sync)" },
            { 0x80244010, "WU_E_PT_EXCEEDED_MAX_SERVER_TRIPS: too many round trips to WSUS (large metadata / superseded updates)" },
            { 0x80244017, "WU_E_PT_HTTP_STATUS_DENIED: HTTP 401 from WSUS (authentication)" },
            { 0x80244018, "WU_E_PT_HTTP_STATUS_FORBIDDEN: HTTP 403 from WSUS (proxy or permissions)" },
            { 0x80244019, "WU_E_PT_HTTP_STATUS_NOT_FOUND: HTTP 404 from WSUS (wrong URL/port or IIS site down)" },
            { 0x8024401C, "WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT: WSUS request timed out" },
            { 0x8024401F, "WU_E_PT_HTTP_STATUS_SERVER_ERROR: HTTP 500 from WSUS" },
            { 0x80244021, "WU_E_PT_HTTP_STATUS_BAD_GATEWAY: HTTP 502 (proxy/gateway)" },
            { 0x80244022, "WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL: HTTP 503 - WSUS app pool on the SUP stopped/overloaded" },
            { 0x8024402C, "WU_E_PT_WINHTTP_NAME_NOT_RESOLVED: cannot resolve the WSUS/proxy name (DNS or proxy settings)" },
            { 0x8024402F, "WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS: external cab processing had errors" },
            { 0x80246007, "WU_E_DM_NOTDOWNLOADED: update not downloaded" },
            { 0x80246008, "WU_E_DM_FAILTOCONNECTTOBITS: could not connect to BITS" },
            { 0x8024200B, "WU_E_UH_INSTALLERFAILURE: the update installer failed" },
            { 0x80242016, "WU_E_UH_POSTREBOOTUNEXPECTEDSTATE: unexpected state after reboot" },
            { 0x8024500C, "WU_E_REDIRECTOR_CONNECT_POLICY: connection to Windows Update blocked by policy" },
            // WinINet / WinHTTP
            { 0x80072EE2, "ERROR_INTERNET_TIMEOUT: connection timed out (firewall/proxy/server down)" },
            { 0x80072EE7, "ERROR_INTERNET_NAME_NOT_RESOLVED: server name could not be resolved" },
            { 0x80072EFD, "ERROR_INTERNET_CANNOT_CONNECT: cannot connect to the server" },
            { 0x80072EFE, "ERROR_INTERNET_CONNECTION_ABORTED: connection aborted" },
            { 0x80072F8F, "ERROR_INTERNET_SECURE_FAILURE: TLS/certificate failure (check clock, TLS settings, cert chain)" },
            // Servicing / Win32
            { 0x80070005, "E_ACCESSDENIED: access denied" },
            { 0x8007000E, "E_OUTOFMEMORY: out of memory" },
            { 0x80070070, "ERROR_DISK_FULL: not enough disk space" },
            { 0x80070422, "ERROR_SERVICE_DISABLED: a required service is disabled" },
            { 0x80070643, "ERROR_INSTALL_FAILURE: fatal error during installation" },
            { 0x80070652, "ERROR_INSTALL_ALREADY_RUNNING: another installation is in progress" },
            { 0x800704EC, "ERROR_ACCESS_DISABLED_BY_POLICY: program blocked by group policy (AppLocker/SRP)" },
            { 0x800711C7, "ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION: blocked by Windows Defender Application Control" },
            { 0x80073712, "ERROR_SXS_COMPONENT_STORE_CORRUPT: component store corrupt (run DISM /RestoreHealth)" },
            { 0x800F081F, "CBS_E_SOURCE_MISSING: source files not found (DISM needs a /Source)" },
            { 0x800F0922, "CBS_E_INSTALLERS_FAILED: servicing failed (often EFI/recovery partition space or VPN)" },
            { 0x800F0831, "CBS_E_STORE_CORRUPTION: a prerequisite package is missing (store corruption)" },
            { 0x800B0109, "CERT_E_UNTRUSTEDROOT: certificate chain ends in an untrusted root" },
            { 0x80004005, "E_FAIL: unspecified error (for WUA source errors check Registry.pol corruption)" },
            // WMI
            { 0x8004100E, "WBEM_E_INVALID_NAMESPACE: WMI namespace missing (CCM namespace broken)" },
            { 0x80041010, "WBEM_E_INVALID_CLASS: WMI class missing" },
            { 0x80041013, "WBEM_E_PROVIDER_LOAD_FAILURE: WMI provider failed to load" },
            // ConfigMgr
            { 0x87D00215, "Item not found / client certificate missing (ConfigMgr)" },
            { 0x87D00324, "The application was not detected after installation completed" },
            { 0x87D00607, "Content not found (no DP has the content for this boundary)" },
            { 0x87D00664, "Updates handler job was cancelled" },
            { 0x87D00668, "Software update still detected as actionable after apply" },
            { 0x87D00692, "Group policy conflict: a GPO overrides the SCCM WSUS server setting" },
            { 0x87D01106, "Failed to verify the executable or build its command line (missing file)" },
        };

        public static uint? ToCode(object v)
        {
            if (v == null) return null;
            string s = Convert.ToString(v, CultureInfo.InvariantCulture).Trim();
            if (s.Length == 0) return null;
            try
            {
                if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return Convert.ToUInt32(s.Substring(2), 16);
                long l;
                if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out l)) return unchecked((uint)l);
            }
            catch { }
            return null;
        }

        public static string Hex(object v)
        {
            uint? c = ToCode(v);
            return c.HasValue ? "0x" + c.Value.ToString("X8", CultureInfo.InvariantCulture) : null;
        }

        /// <summary>"0x80244022 WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL: ..." or null for 0/empty.</summary>
        public static string Describe(object v)
        {
            uint? code = ToCode(v);
            if (!code.HasValue || code.Value == 0) return null;
            string hex = "0x" + code.Value.ToString("X8", CultureInfo.InvariantCulture);
            string text;
            if (Known.TryGetValue(code.Value, out text)) return hex + " " + text;
            if ((code.Value & 0xFFFF0000) == 0x80070000)
            {
                try { return hex + " " + new Win32Exception((int)(code.Value & 0xFFFF)).Message; } catch { }
            }
            return hex;
        }

        public static IEnumerable<string> FindCodes(string text)
        {
            if (string.IsNullOrEmpty(text)) yield break;
            foreach (Match m in Regex.Matches(text, @"0x[0-9A-Fa-f]{8}"))
                yield return "0x" + m.Value.Substring(2).ToUpperInvariant();
        }
    }
}

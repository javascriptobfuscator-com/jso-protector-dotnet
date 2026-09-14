// .NET client for the JavaScript Obfuscator HTTP API.
//
// Mirrors the Protect() surface of the jso-protector npm CLI, the
// jso_protector Python package, and the jso-protector-go module so behavior
// stays in lockstep across runtimes.
//
// Uses HttpClient + System.Text.Json. Target: .NET Standard 2.0 (covers
// .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5/6/7/8+, Mono, Unity, Xamarin).

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace JsoProtector
{
    /// <summary>
    /// Outcome of a successful <see cref="JsoProtectorClient.ProtectAsync"/> call.
    /// </summary>
    public sealed class ProtectResult
    {
        /// <summary>Protected source keyed by input filename.</summary>
        public Dictionary<string, string> Files { get; } = new Dictionary<string, string>();

        /// <summary>Stable identifier for this protection run. Inject as a global into your runtime so crash reports carry the matching BuildId.</summary>
        public string? BuildId { get; set; }

        /// <summary>Short fingerprint over the protected output. Two consecutive obfuscations of identical input MUST produce different fingerprints when polymorphism is engaged.</summary>
        public string? PolymorphismFingerprint { get; set; }

        /// <summary>Full Report object — identifier maps, enabled options, compatibility findings, release metadata.</summary>
        public JsonElement? Report { get; set; }

        /// <summary>Complete raw response body. Use when a field hasn't been surfaced on this class yet.</summary>
        public JsonDocument? Raw { get; set; }
    }

    /// <summary>
    /// Thrown when the JSO API rejects a request or the response is malformed.
    /// The message is safe to log — API key / password values are never interpolated.
    /// </summary>
    public sealed class JsoProtectorException : Exception
    {
        public string? Type { get; }
        public string? ErrorCode { get; }

        public JsoProtectorException(string message, string? type = null, string? errorCode = null)
            : base(message)
        {
            Type = type;
            ErrorCode = errorCode;
        }
    }

    /// <summary>
    /// Options for a single protect() call. Defaults match the npm CLI / Python / Go clients.
    /// </summary>
    public sealed class ProtectOptions
    {
        /// <summary>Map of {filename: source}. At least one entry required.</summary>
        public Dictionary<string, string> Files { get; set; } = new Dictionary<string, string>();

        /// <summary>One of "standard", "balanced", "maximum". Default "balanced".</summary>
        public string Preset { get; set; } = "balanced";

        /// <summary>Pascal-case option overrides. Take precedence over preset defaults. Values: bool / string / number.</summary>
        public Dictionary<string, object?>? OptionOverrides { get; set; }

        /// <summary>Release label forwarded as ReleaseLabel on the API request. Use the commit SHA for CI runs.</summary>
        public string? Label { get; set; }

        /// <summary>Audit-log project name. Default "dotnet-session".</summary>
        public string ProjectName { get; set; } = "dotnet-session";

        /// <summary>
        /// Base64 API key from the JSO dashboard. Defaults to JSO_API_KEY /
        /// JAVASCRIPT_OBFUSCATOR_API_KEY environment variables when null/empty.
        /// </summary>
        public string? ApiKey { get; set; }

        /// <summary>
        /// Base64 API password from the dashboard. Defaults to JSO_API_PASSWORD /
        /// JAVASCRIPT_OBFUSCATOR_API_PASSWORD env vars when null/empty.
        /// </summary>
        public string? ApiPassword { get; set; }

        /// <summary>Endpoint override. Default = JsoProtectorClient.DefaultEndpoint.</summary>
        public string? Endpoint { get; set; }
    }

    /// <summary>
    /// Stateless client for the JavaScript Obfuscator HTTP API.
    ///
    /// Inject an <see cref="HttpClient"/> for IHttpClientFactory wire-up,
    /// timeout, retry policy, mock-server testing, etc. When null, a fresh
    /// HttpClient with a 180-second timeout is created per-call.
    /// </summary>
    public sealed class JsoProtectorClient
    {
        public const string DefaultEndpoint = "https://javascriptobfuscator.com/HttpApi.ashx";
        public const string Version = "0.1.0";

        public static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, bool>> Presets =
            new Dictionary<string, IReadOnlyDictionary<string, bool>>(StringComparer.OrdinalIgnoreCase)
            {
                ["standard"] = new Dictionary<string, bool>
                {
                    ["Compress"]             = true,
                    ["EncodeStrings"]        = true,
                    ["MoveStringsIntoArray"] = true,
                    ["NameMangling"]         = true,
                },
                ["balanced"] = new Dictionary<string, bool>
                {
                    ["Compress"]             = true,
                    ["EncodeStrings"]        = true,
                    ["EncryptStrings"]       = true,
                    ["MoveStringsIntoArray"] = true,
                    ["NameMangling"]         = true,
                    ["DeepObfuscate"]        = true,
                    ["FlatTransform"]        = true,
                    ["CodeTransposition"]    = true,
                },
                ["maximum"] = new Dictionary<string, bool>
                {
                    ["Compress"]             = true,
                    ["EncodeStrings"]        = true,
                    ["EncryptStrings"]       = true,
                    ["MoveStringsIntoArray"] = true,
                    ["NameMangling"]         = true,
                    ["DeepObfuscate"]        = true,
                    ["FlatTransform"]        = true,
                    ["CodeTransposition"]    = true,
                    ["ProtectMembers"]       = true,
                    ["RenameGlobals"]        = true,
                    ["MoveMembers"]          = true,
                    ["DeadCodeInsertion"]    = true,
                },
            };

        private readonly HttpClient? _injected;

        public JsoProtectorClient(HttpClient? httpClient = null)
        {
            _injected = httpClient;
        }

        public async Task<ProtectResult> ProtectAsync(ProtectOptions options, CancellationToken cancellation = default)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            var apiKey = ResolveCredential(options.ApiKey, "JSO_API_KEY", "JAVASCRIPT_OBFUSCATOR_API_KEY");
            var apiPwd = ResolveCredential(options.ApiPassword, "JSO_API_PASSWORD", "JAVASCRIPT_OBFUSCATOR_API_PASSWORD");
            if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiPwd))
            {
                throw new JsoProtectorException(
                    "JSO API credentials not configured. Set ProtectOptions.ApiKey/ApiPassword or export JSO_API_KEY / JSO_API_PASSWORD.");
            }
            if (options.Files == null || options.Files.Count == 0)
            {
                throw new JsoProtectorException("At least one file is required.");
            }

            var presetName = string.IsNullOrEmpty(options.Preset) ? "balanced" : options.Preset!.ToLowerInvariant();
            if (!Presets.TryGetValue(presetName, out var presetOpts))
            {
                throw new JsoProtectorException("Unknown preset \"" + options.Preset + "\".");
            }

            // Build payload by hand to control key order and the field set.
            using var bodyStream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(bodyStream))
            {
                writer.WriteStartObject();
                writer.WriteString("APIKey", apiKey);
                writer.WriteString("APIPwd", apiPwd);
                writer.WriteString("Name", string.IsNullOrEmpty(options.ProjectName) ? "dotnet-session" : options.ProjectName);
                if (!string.IsNullOrEmpty(options.Label))
                {
                    writer.WriteString("ReleaseLabel", options.Label);
                }
                writer.WriteStartArray("Items");
                foreach (var kvp in options.Files)
                {
                    writer.WriteStartObject();
                    writer.WriteString("FileName", kvp.Key);
                    writer.WriteString("FileCode", kvp.Value ?? string.Empty);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                // Preset defaults first; explicit overrides win.
                var merged = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var kvp in presetOpts)
                {
                    merged[kvp.Key] = kvp.Value;
                }
                if (options.OptionOverrides != null)
                {
                    foreach (var kvp in options.OptionOverrides)
                    {
                        merged[kvp.Key] = kvp.Value;
                    }
                }
                foreach (var kvp in merged)
                {
                    WriteOption(writer, kvp.Key, kvp.Value);
                }

                writer.WriteEndObject();
            }
            var bodyBytes = bodyStream.ToArray();

            var endpoint = string.IsNullOrEmpty(options.Endpoint) ? DefaultEndpoint : options.Endpoint!;
            var ownsClient = _injected == null;
            var client = _injected ?? new HttpClient { Timeout = TimeSpan.FromSeconds(180) };
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Headers.UserAgent.ParseAdd("jso-protector-dotnet/" + Version);
                req.Content = new ByteArrayContent(bodyBytes);
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("text/json");

                using var resp = await client.SendAsync(req, cancellation).ConfigureAwait(false);
                var respBody = await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);

                if ((int)resp.StatusCode < 200 || (int)resp.StatusCode >= 300)
                {
                    var snippet = Encoding.UTF8.GetString(respBody, 0, Math.Min(respBody.Length, 200));
                    throw new JsoProtectorException("HTTP " + (int)resp.StatusCode + ": " + snippet);
                }

                JsonDocument parsed;
                try
                {
                    parsed = JsonDocument.Parse(respBody);
                }
                catch (JsonException ex)
                {
                    throw new JsoProtectorException("Malformed JSON in response: " + ex.Message);
                }

                var root = parsed.RootElement;
                var type = root.TryGetProperty("Type", out var typeProp) ? typeProp.GetString() : null;
                if (!string.Equals(type, "Succeed", StringComparison.Ordinal))
                {
                    var message = root.TryGetProperty("Message", out var msgProp) ? msgProp.GetString() : null;
                    var errorCode = root.TryGetProperty("ErrorCode", out var codeProp) ? codeProp.GetString() : null;
                    parsed.Dispose();
                    throw new JsoProtectorException(message ?? errorCode ?? "API request failed", type, errorCode);
                }

                var result = new ProtectResult { Raw = parsed };
                if (root.TryGetProperty("Items", out var itemsArr) && itemsArr.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in itemsArr.EnumerateArray())
                    {
                        var name = item.TryGetProperty("FileName", out var nameProp) ? nameProp.GetString() : null;
                        var code = item.TryGetProperty("FileCode", out var codeProp2) ? codeProp2.GetString() : null;
                        if (!string.IsNullOrEmpty(name) && code != null)
                        {
                            result.Files[name!] = code;
                        }
                    }
                }
                if (result.Files.Count == 0)
                {
                    parsed.Dispose();
                    throw new JsoProtectorException("API response did not include any protected files.");
                }
                if (root.TryGetProperty("Report", out var reportProp))
                {
                    result.Report = reportProp.Clone();
                    if (reportProp.TryGetProperty("BuildId", out var buildIdProp))
                        result.BuildId = buildIdProp.GetString();
                    if (reportProp.TryGetProperty("PolymorphismFingerprint", out var fpProp))
                        result.PolymorphismFingerprint = fpProp.GetString();
                }
                return result;
            }
            finally
            {
                if (ownsClient) client.Dispose();
            }
        }

        private static void WriteOption(Utf8JsonWriter writer, string key, object? value)
        {
            switch (value)
            {
                case null:
                    writer.WriteNull(key);
                    break;
                case bool b:
                    writer.WriteBoolean(key, b);
                    break;
                case string s:
                    writer.WriteString(key, s);
                    break;
                case int i:
                    writer.WriteNumber(key, i);
                    break;
                case long l:
                    writer.WriteNumber(key, l);
                    break;
                case double d:
                    writer.WriteNumber(key, d);
                    break;
                default:
                    writer.WriteString(key, value.ToString() ?? string.Empty);
                    break;
            }
        }

        private static string ResolveCredential(string? supplied, params string[] envVars)
        {
            if (!string.IsNullOrWhiteSpace(supplied)) return supplied!.Trim();
            foreach (var name in envVars)
            {
                var v = Environment.GetEnvironmentVariable(name);
                if (!string.IsNullOrWhiteSpace(v)) return v!.Trim();
            }
            return string.Empty;
        }
    }
}

# JsoProtector — .NET client

.NET client for the [JavaScript Obfuscator](https://javascriptobfuscator.com/) HTTP API. Mirrors the `protect()` surface of the [npm `javascriptobfuscator-com` CLI](https://javascriptobfuscator.com/docs/npmcli.aspx), the [Python client](https://github.com/javascriptobfuscator-com/jso-protector-python), and the [Go client](https://github.com/javascriptobfuscator-com/jso-protector-go) so behavior stays in lockstep across runtimes.

Targets **.NET Standard 2.0** — runs on .NET Framework 4.6.1+, .NET Core 2.0+, .NET 5/6/7/8+, Mono, Unity, Xamarin.

## Install

```bash
dotnet add package JsoProtector
```

## Quick start

```csharp
using System.Collections.Generic;
using JsoProtector;

var client = new JsoProtectorClient();  // optionally pass an HttpClient

var result = await client.ProtectAsync(new ProtectOptions {
    Files = new Dictionary<string, string> {
        ["app.js"] = File.ReadAllText("dist/app.js")
    },
    Preset = "balanced",
    // ApiKey/ApiPassword default to JSO_API_KEY / JSO_API_PASSWORD env vars.
    Label = Environment.GetEnvironmentVariable("GIT_COMMIT"),
});

foreach (var (name, code) in result.Files) {
    File.WriteAllText($"dist-protected/{name}", code);
}
Console.WriteLine($"BuildId: {result.BuildId}");
Console.WriteLine($"Fingerprint: {result.PolymorphismFingerprint}");
```

## HttpClient injection

`JsoProtectorClient` accepts an `HttpClient` so it slots into `IHttpClientFactory` / Polly retry / timeout policy / mock-server tests. When you pass null, a fresh `HttpClient` with a 180-second timeout is created per-call and disposed afterward.

```csharp
services.AddHttpClient<JsoProtectorClient>(c => {
    c.Timeout = TimeSpan.FromMinutes(3);
});
```

## Credentials

Reads `JSO_API_KEY` / `JSO_API_PASSWORD` (or the long-form `JAVASCRIPT_OBFUSCATOR_API_KEY` / `JAVASCRIPT_OBFUSCATOR_API_PASSWORD`) from the environment before falling back to `ProtectOptions.ApiKey` / `ProtectOptions.ApiPassword`. Use env vars on shared / CI machines.

## Presets

| Preset | Notes |
|---|---|
| `standard` | Core string encoding, string-array move, name mangling, compression. |
| `balanced` | Adds string encryption, deep obfuscation, flat transform, code transposition. |
| `maximum` | Adds member rename, global rename, member move, dead-code insertion. |

For fine-grained control, set `OptionOverrides`:

```csharp
OptionOverrides = new Dictionary<string, object?> {
    ["LockDate"] = true,
    ["LockDomain"] = true,
    ["LockDomainList"] = "example.com",
}
```

Explicit overrides win over preset defaults.

## Result

`ProtectResult` exposes:

| Property | Type | Notes |
|---|---|---|
| `Files` | `Dictionary<string, string>` | Protected source by input filename. |
| `BuildId` | `string?` | Stable identifier for this run. |
| `PolymorphismFingerprint` | `string?` | Short SHA-256-derived fingerprint. |
| `Report` | `JsonElement?` | Full Report — identifier maps, enabled options, compatibility findings, release metadata. |
| `Raw` | `JsonDocument?` | Full raw response. Caller owns the lifetime (returned `JsonDocument` should be disposed). |

## Error handling

```csharp
try {
    var result = await client.ProtectAsync(options);
} catch (JsoProtectorException ex) {
    // ex.Message is safe to log — API key/password never interpolated.
    Console.Error.WriteLine($"JSO failed: Type={ex.Type} ErrorCode={ex.ErrorCode} {ex.Message}");
}
```

## Watermarking — anti-piracy / dispute proof

`JsoProtector.Watermark` embeds an HMAC-SHA256-signed marker into source before submission to the obfuscation API. The obfuscator's `KeepComment` option preserves the marker through every transform, so the watermark survives in the protected output. Holders of the secret can verify; everyone else sees an opaque comment block.

```csharp
using JsoProtector;

// Stamp during build:
string source = File.ReadAllText("dist/app.js");
string stamped = Watermark.InjectInto(source, tag: "release-2026-Q3",
                                       key: Environment.GetEnvironmentVariable("JSO_WATERMARK_KEY")!);
// Then send stamped through your normal ProtectAsync flow, ensuring
// KeepComment is on in the options so the marker rides through.

// Verify a protected artifact later:
var r = Watermark.Verify(
    File.ReadAllText("dist-protected/app.js"),
    Environment.GetEnvironmentVariable("JSO_WATERMARK_KEY"));
if (r.Valid)
    Console.WriteLine($"Valid build, tag={r.Tag}");
else if (r.Present)
    Console.WriteLine($"Watermark present (tag={r.Tag}) but signature does NOT match the supplied key.");
else
    Console.WriteLine("No watermark in this file.");
```

Wire format is identical to the Node (`packages/jso-protector/watermark.js`) and Python (`jso_protector.watermark`) clients — an artifact stamped by any of the three verifies under any of the others. Tests in `JsoProtector.Tests/WatermarkTests.cs` include cross-language verification with the Node implementation (silently skipped when `node` isn't on PATH). Spec: <https://javascriptobfuscator.com/docs/wireformat.aspx#watermark>.

Lookup-only mode (no key supplied) extracts the embedded tag without validating — useful for forensic inspection of leaked artifacts where the secret shouldn't ship to the investigator. Constant-time HMAC compare via a byte-XOR-accumulate that defeats prefix-length timing leaks.

## Tests

```bash
dotnet test
```

xUnit + a CapturingHandler-based `HttpMessageHandler` mock; no network calls.

## License

UNLICENSED. Provided as a free companion to the JSO service.

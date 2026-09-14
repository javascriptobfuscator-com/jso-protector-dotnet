# Changelog

All notable changes to the `JsoProtector` .NET package.

## [Unreleased]

### Added — `JsoProtector.Watermark` (2026-05-28)

- New static class that mirrors the wire format of
  `packages/jso-protector/watermark.js` (Node) and
  `jso_protector.watermark` (Python). An artifact stamped by any of
  the three verifies under any of the others.
- API surface: `Watermark.SignTag(tag, key)`,
  `Watermark.BuildHeader(tag, key)`,
  `Watermark.InjectInto(source, tag, key)`,
  `Watermark.Verify(protectedSource, key)`,
  `Watermark.VerifyResult` readonly struct,
  `Watermark.Marker` constant.
- Targets `netstandard2.0` — same broad-reach target as the rest of
  the package. Consumable from .NET Framework 4.6.1+, .NET Core 2.0+,
  .NET 5/6/7/8+, Mono, Xamarin, Unity. No new package dependencies.
- Manual base64url encode/decode helpers (no stdlib helper exists in
  netstandard2.0 for the url-safe variant; rolled into the package
  rather than adding a 3rd-party dependency).
- Constant-time signature comparison via byte-XOR-accumulate over
  UTF-8 representations of both signatures — defeats prefix-length
  timing leaks.
- Unicode tags (multi-byte UTF-8) round-trip through base64url.
- Lookup-only mode (null or empty key) extracts the tag without
  validating — useful for forensic inspection of leaked artifacts
  where the HMAC secret shouldn't ship to the investigator.
- Cross-language verification tests in
  `JsoProtector.Tests/WatermarkTests.cs` spawn the Node
  `watermark.js` module via `System.Diagnostics.Process` and verify
  .NET-stamped → Node-validated and Node-stamped → .NET-validated in
  both directions. Tests degrade gracefully (silently skip) when
  `node` isn't on PATH so the suite still passes on .NET-only
  runners.
- Coverage: 10 new xUnit test cases. Full suite: 18 / 18 passing.

Wire format spec: <https://javascriptobfuscator.com/docs/wireformat.aspx#watermark>

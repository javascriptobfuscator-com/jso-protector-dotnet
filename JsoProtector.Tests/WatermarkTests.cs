using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using JsoProtector;
using Xunit;

namespace JsoProtector.Tests
{
    /// <summary>
    /// Tests for the watermark wire format. Two layers:
    /// <list type="bullet">
    /// <item>Direct API behavior: sign, inject, verify, lookup-only, wrong-key, missing-marker, unicode tags.</item>
    /// <item>Cross-language verification via the Node implementation: stamp in .NET, verify in Node, and vice versa.</item>
    /// </list>
    /// </summary>
    public class WatermarkTests
    {
        [Fact]
        public void SignTag_Deterministic_AndKeyBound()
        {
            string a = Watermark.SignTag("release-42", "secret-key");
            string b = Watermark.SignTag("release-42", "secret-key");
            string c = Watermark.SignTag("release-42", "different-key");
            Assert.Equal(a, b);
            Assert.NotEqual(a, c);
        }

        [Fact]
        public void SignTag_Rejects_MissingInputs()
        {
            Assert.Throws<ArgumentException>(() => Watermark.SignTag("", "k"));
            Assert.Throws<ArgumentException>(() => Watermark.SignTag("t", ""));
        }

        [Fact]
        public void InjectThenVerify_HappyPath()
        {
            string src = "var x = 1; console.log(x);";
            string stamped = Watermark.InjectInto(src, "license-XYZ", "shh");
            Assert.StartsWith("/*! __jso_watermark_v1", stamped);
            var r = Watermark.Verify(stamped, "shh");
            Assert.True(r.Present);
            Assert.True(r.Valid);
            Assert.Equal("license-XYZ", r.Tag);
        }

        [Fact]
        public void WrongKey_FailsVerification()
        {
            string stamped = Watermark.InjectInto("var x;", "tag", "right-key");
            var r = Watermark.Verify(stamped, "wrong-key");
            Assert.True(r.Present);
            Assert.False(r.Valid);
        }

        [Fact]
        public void LookupOnlyMode_ReturnsTagWithoutValidating()
        {
            string stamped = Watermark.InjectInto("var x;", "release-99", "k");
            var r = Watermark.Verify(stamped, null);
            Assert.True(r.Present);
            Assert.Equal("release-99", r.Tag);
            Assert.False(r.Valid);
        }

        [Fact]
        public void CleanFile_ReturnsPresentFalse()
        {
            var r = Watermark.Verify("var x = 1;", "k");
            Assert.False(r.Present);
            Assert.Contains("not found", r.Error ?? "");
        }

        [Fact]
        public void MarkerSurvives_SurroundingCode()
        {
            string stamped = Watermark.InjectInto("function f(){return 1;}", "tag-A", "k");
            string fakeProtected = stamped + "\nvar _0xa1b2 = ['foo'];\n";
            var r = Watermark.Verify(fakeProtected, "k");
            Assert.True(r.Valid);
            Assert.Equal("tag-A", r.Tag);
        }

        [Fact]
        public void UnicodeTag_RoundTripsViaBase64Url()
        {
            string tag = "リリース-2026-Q3-α";
            string stamped = Watermark.InjectInto("var x;", tag, "k");
            var r = Watermark.Verify(stamped, "k");
            Assert.Equal(tag, r.Tag);
            Assert.True(r.Valid);
        }

        // -------- cross-language verification with the Node module --------

        private static string LocateNodeWatermarkModule()
        {
            // Walk upward from the test's bin directory looking for the
            // package root. We could hardcode a relative path but it's
            // fragile to project structure changes; the search is bounded
            // and fast.
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 10 && dir != null; i++)
            {
                string candidate = Path.Combine(dir, "..", "..", "jso-protector", "watermark.js");
                candidate = Path.GetFullPath(candidate);
                if (File.Exists(candidate)) return candidate;
                string parent = Path.GetDirectoryName(dir)!;
                if (parent == dir) break;
                dir = parent;
            }
            return string.Empty;
        }

        private static bool NodeAvailable()
        {
            try
            {
                var psi = new ProcessStartInfo("node", "--version")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                using var p = Process.Start(psi);
                if (p == null) return false;
                p.WaitForExit(5000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        [Fact]
        public void DotNet_CanVerifyNodeStampedArtifact()
        {
            if (!NodeAvailable()) return;     // skip when Node isn't on PATH
            string modulePath = LocateNodeWatermarkModule();
            if (string.IsNullOrEmpty(modulePath)) return;

            // Stamp in Node, verify in .NET.
            string script =
                $"const wm=require({JsonStringLiteral(modulePath)});" +
                "process.stdout.write(wm.injectInto(\"var x = 1;\", \"release-from-node\", \"shared-key\"));";
            var psi = new ProcessStartInfo("node", $"-e \"{script.Replace("\"", "\\\"")}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            string stamped = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Assert.Equal(0, p.ExitCode);

            var r = Watermark.Verify(stamped, "shared-key");
            Assert.True(r.Valid, "Node-stamped artifact must verify under .NET");
            Assert.Equal("release-from-node", r.Tag);
        }

        [Fact]
        public void Node_CanVerifyDotNetStampedArtifact()
        {
            if (!NodeAvailable()) return;
            string modulePath = LocateNodeWatermarkModule();
            if (string.IsNullOrEmpty(modulePath)) return;

            // Stamp in .NET, pipe to Node, verify there.
            string stamped = Watermark.InjectInto("var x = 1;", "release-from-dotnet", "shared-key");
            string script =
                $"const wm=require({JsonStringLiteral(modulePath)});" +
                "let buf=\"\";" +
                "process.stdin.on(\"data\",c=>buf+=c);" +
                "process.stdin.on(\"end\",()=>{" +
                "  const r=wm.verify(buf,\"shared-key\");" +
                "  process.stdout.write(JSON.stringify(r));" +
                "});";
            var psi = new ProcessStartInfo("node", $"-e \"{script.Replace("\"", "\\\"")}\"")
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            p.StandardInput.Write(stamped);
            p.StandardInput.Close();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Assert.Equal(0, p.ExitCode);
            Assert.Contains("\"valid\":true", output);
            Assert.Contains("release-from-dotnet", output);
        }

        // Emit a JS-safe string literal for the require() path. JS uses
        // forward slashes happily; we still wrap in JSON.stringify-like
        // double quotes with backslash escaping.
        private static string JsonStringLiteral(string s)
        {
            return "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }
    }
}

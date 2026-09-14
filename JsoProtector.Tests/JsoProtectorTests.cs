using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using JsoProtector;
using Xunit;

namespace JsoProtector.Tests
{
    public class JsoProtectorTests
    {
        /// <summary>
        /// Captures every outgoing request body and returns a canned JSON response.
        /// Keeps tests offline (no httptest, no real network).
        /// </summary>
        private sealed class CapturingHandler : HttpMessageHandler
        {
            public string? CapturedBody;
            public string ResponseBody;
            public HttpStatusCode StatusCode;

            public CapturingHandler(string responseBody, HttpStatusCode status = HttpStatusCode.OK)
            {
                ResponseBody = responseBody;
                StatusCode = status;
            }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                CapturedBody = request.Content != null
                    ? await request.Content.ReadAsStringAsync()
                    : null;
                return new HttpResponseMessage(StatusCode)
                {
                    Content = new StringContent(ResponseBody, Encoding.UTF8, "text/json")
                };
            }
        }

        private static JsoProtectorClient Make(CapturingHandler handler) =>
            new JsoProtectorClient(new HttpClient(handler));

        [Fact]
        public async Task Label_propagates_as_ReleaseLabel()
        {
            var handler = new CapturingHandler("""
                {
                    "Type": "Succeed",
                    "Items": [{"FileName": "app.js", "FileCode": "PROTECTED;"}],
                    "Report": {"BuildId": "rel-1", "PolymorphismFingerprint": "abc123"}
                }
                """);
            var client = Make(handler);

            var result = await client.ProtectAsync(new ProtectOptions
            {
                ApiKey = "k",
                ApiPassword = "p",
                Files = new Dictionary<string, string> { ["app.js"] = "let x = 1;" },
                Preset = "balanced",
                Label = "ci-build-7f3a",
            });

            Assert.NotNull(handler.CapturedBody);
            using var doc = JsonDocument.Parse(handler.CapturedBody!);
            Assert.Equal("ci-build-7f3a", doc.RootElement.GetProperty("ReleaseLabel").GetString());
            Assert.Equal("k", doc.RootElement.GetProperty("APIKey").GetString());
            Assert.Equal("p", doc.RootElement.GetProperty("APIPwd").GetString());
            Assert.True(doc.RootElement.GetProperty("FlatTransform").GetBoolean());
            Assert.Equal("rel-1", result.BuildId);
            Assert.Equal("abc123", result.PolymorphismFingerprint);
            Assert.Equal("PROTECTED;", result.Files["app.js"]);
        }

        [Fact]
        public async Task OptionOverrides_win_over_preset_defaults()
        {
            var handler = new CapturingHandler("""
                {"Type": "Succeed", "Items": [{"FileName": "x.js", "FileCode": "OK;"}]}
                """);
            var client = Make(handler);

            await client.ProtectAsync(new ProtectOptions
            {
                ApiKey = "k",
                ApiPassword = "p",
                Files = new Dictionary<string, string> { ["x.js"] = "let y = 2;" },
                Preset = "balanced",
                OptionOverrides = new Dictionary<string, object?>
                {
                    ["FlatTransform"] = false,
                    ["LockDomain"] = true,
                    ["LockDomainList"] = "example.com",
                },
            });

            Assert.NotNull(handler.CapturedBody);
            using var doc = JsonDocument.Parse(handler.CapturedBody!);
            // Balanced default was true; explicit override wins.
            Assert.False(doc.RootElement.GetProperty("FlatTransform").GetBoolean());
            Assert.True(doc.RootElement.GetProperty("LockDomain").GetBoolean());
            Assert.Equal("example.com", doc.RootElement.GetProperty("LockDomainList").GetString());
        }

        [Fact]
        public async Task Env_var_fallback_for_credentials()
        {
            var originalKey = Environment.GetEnvironmentVariable("JSO_API_KEY");
            var originalPwd = Environment.GetEnvironmentVariable("JSO_API_PASSWORD");
            try
            {
                Environment.SetEnvironmentVariable("JSO_API_KEY", "env-key");
                Environment.SetEnvironmentVariable("JSO_API_PASSWORD", "env-pwd");
                var handler = new CapturingHandler("""
                    {"Type": "Succeed", "Items": [{"FileName": "a.js", "FileCode": "OK;"}]}
                    """);
                var client = Make(handler);

                await client.ProtectAsync(new ProtectOptions
                {
                    Files = new Dictionary<string, string> { ["a.js"] = "let z = 3;" },
                });

                Assert.NotNull(handler.CapturedBody);
                using var doc = JsonDocument.Parse(handler.CapturedBody!);
                Assert.Equal("env-key", doc.RootElement.GetProperty("APIKey").GetString());
                Assert.Equal("env-pwd", doc.RootElement.GetProperty("APIPwd").GetString());
            }
            finally
            {
                Environment.SetEnvironmentVariable("JSO_API_KEY", originalKey);
                Environment.SetEnvironmentVariable("JSO_API_PASSWORD", originalPwd);
            }
        }

        [Fact]
        public async Task Missing_credentials_throws()
        {
            var originalKey = Environment.GetEnvironmentVariable("JSO_API_KEY");
            var originalPwd = Environment.GetEnvironmentVariable("JSO_API_PASSWORD");
            var originalLong1 = Environment.GetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_KEY");
            var originalLong2 = Environment.GetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_PASSWORD");
            try
            {
                Environment.SetEnvironmentVariable("JSO_API_KEY", null);
                Environment.SetEnvironmentVariable("JSO_API_PASSWORD", null);
                Environment.SetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_KEY", null);
                Environment.SetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_PASSWORD", null);

                var client = new JsoProtectorClient();
                var ex = await Assert.ThrowsAsync<JsoProtectorException>(() => client.ProtectAsync(new ProtectOptions
                {
                    Files = new Dictionary<string, string> { ["a.js"] = "x" },
                }));
                Assert.Contains("credentials", ex.Message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                Environment.SetEnvironmentVariable("JSO_API_KEY", originalKey);
                Environment.SetEnvironmentVariable("JSO_API_PASSWORD", originalPwd);
                Environment.SetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_KEY", originalLong1);
                Environment.SetEnvironmentVariable("JAVASCRIPT_OBFUSCATOR_API_PASSWORD", originalLong2);
            }
        }

        [Fact]
        public async Task Unknown_preset_throws()
        {
            var client = new JsoProtectorClient();
            var ex = await Assert.ThrowsAsync<JsoProtectorException>(() => client.ProtectAsync(new ProtectOptions
            {
                ApiKey = "k",
                ApiPassword = "p",
                Files = new Dictionary<string, string> { ["a.js"] = "x" },
                Preset = "elephant",
            }));
            Assert.Contains("preset", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("elephant", ex.Message);
        }

        [Fact]
        public async Task Empty_files_throws()
        {
            var client = new JsoProtectorClient();
            var ex = await Assert.ThrowsAsync<JsoProtectorException>(() => client.ProtectAsync(new ProtectOptions
            {
                ApiKey = "k",
                ApiPassword = "p",
                Files = new Dictionary<string, string>(),
            }));
            Assert.Contains("file", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Non_Succeed_Type_throws_with_message_and_code()
        {
            var handler = new CapturingHandler("""
                {"Type": "Error", "Message": "Invalid API key", "ErrorCode": "AUTH_FAIL"}
                """);
            var client = Make(handler);

            var ex = await Assert.ThrowsAsync<JsoProtectorException>(() => client.ProtectAsync(new ProtectOptions
            {
                ApiKey = "k",
                ApiPassword = "p",
                Files = new Dictionary<string, string> { ["a.js"] = "x" },
            }));
            Assert.Equal("Invalid API key", ex.Message);
            Assert.Equal("Error", ex.Type);
            Assert.Equal("AUTH_FAIL", ex.ErrorCode);
        }

        [Fact]
        public void Preset_table_has_expected_entries()
        {
            Assert.Contains("standard", JsoProtectorClient.Presets.Keys);
            Assert.Contains("balanced", JsoProtectorClient.Presets.Keys);
            Assert.Contains("maximum", JsoProtectorClient.Presets.Keys);
            Assert.True(JsoProtectorClient.Presets["maximum"].Count > JsoProtectorClient.Presets["standard"].Count,
                "maximum preset should define more options than standard");
        }
    }
}

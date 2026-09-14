using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace JsoProtector
{
    /// <summary>
    /// Cryptographic watermarking for protected JavaScript output.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Mirror of <c>packages/jso-protector/watermark.js</c> and
    /// <c>jso_protector/watermark.py</c>. The wire format is identical
    /// across all three implementations so an artifact stamped by any
    /// client verifies under any other.
    /// </para>
    /// <para>
    /// Format (versioned so we can evolve without breaking old artifacts):
    /// </para>
    /// <code>
    /// /*! __jso_watermark_v1
    ///  * tag: &lt;base64url&gt;
    ///  * sig: &lt;base64url HMAC-SHA256(tag, key)&gt;
    ///  */
    /// </code>
    /// <para>
    /// The block is injected at the top of source before submission to
    /// the JSO obfuscation API. The obfuscator's <c>KeepComment</c>
    /// option preserves it verbatim through every transform — string
    /// arrays, control-flow flattening, dead code, etc. — so the marker
    /// survives intact in the protected output.
    /// </para>
    /// <para>
    /// Verifiers can re-derive the HMAC over the embedded tag and
    /// compare against the embedded signature in constant time. The
    /// signing key never leaves the customer's CI environment; only
    /// holders of the secret can produce or validate watermarks.
    /// </para>
    /// </remarks>
    public static class Watermark
    {
        /// <summary>
        /// Versioned marker token. Constant across all client
        /// implementations — never rename without bumping the version
        /// number (e.g. <c>__jso_watermark_v2</c>).
        /// </summary>
        public const string Marker = "__jso_watermark_v1";

        // Pattern must match the JS / Python implementations byte-for-byte.
        // Compiled once at type load; thread-safe.
        private static readonly Regex MarkerPattern = new Regex(
            @"/\*!?\s*__jso_watermark_v1\s+" +
            @"\*\s*tag:\s*([A-Za-z0-9_-]+)\s+" +
            @"\*\s*sig:\s*([A-Za-z0-9_-]+)\s*" +
            @"\*/",
            RegexOptions.Compiled);

        /// <summary>
        /// Result of a watermark verification.
        /// </summary>
        public readonly struct VerifyResult
        {
            /// <summary>True iff a watermark marker block was found in the input.</summary>
            public bool Present { get; }
            /// <summary>The decoded tag string. Empty when <see cref="Present"/> is false.</summary>
            public string Tag { get; }
            /// <summary>The embedded base64url signature.</summary>
            public string Signature { get; }
            /// <summary>True iff HMAC(tag, key) matches the embedded signature in constant time. Always false when no key is provided or no marker is present.</summary>
            public bool Valid { get; }
            /// <summary>Human-readable failure reason, or null on success.</summary>
            public string? Error { get; }

            public VerifyResult(bool present, string tag, string signature, bool valid, string? error)
            {
                Present = present;
                Tag = tag;
                Signature = signature;
                Valid = valid;
                Error = error;
            }
        }

        /// <summary>
        /// Compute the canonical base64url HMAC-SHA256 over <paramref name="tag"/> using <paramref name="key"/>.
        /// </summary>
        /// <exception cref="ArgumentException">Either argument is null or empty.</exception>
        public static string SignTag(string tag, string key)
        {
            if (string.IsNullOrEmpty(tag))
                throw new ArgumentException("watermark: tag is required", nameof(tag));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("watermark: key is required", nameof(key));

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            byte[] digest = hmac.ComputeHash(Encoding.UTF8.GetBytes(tag));
            return Base64UrlEncode(digest);
        }

        /// <summary>
        /// Build the header-comment block. Caller prepends to source.
        /// </summary>
        public static string BuildHeader(string tag, string key)
        {
            string tagB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(tag));
            string sigB64 = SignTag(tag, key);
            var sb = new StringBuilder();
            sb.Append("/*! ").Append(Marker).Append('\n');
            sb.Append(" * tag: ").Append(tagB64).Append('\n');
            sb.Append(" * sig: ").Append(sigB64).Append('\n');
            sb.Append(" */\n");
            return sb.ToString();
        }

        /// <summary>
        /// Return <paramref name="source"/> with a watermark header prepended.
        /// </summary>
        public static string InjectInto(string source, string tag, string key)
        {
            return BuildHeader(tag, key) + (source ?? string.Empty);
        }

        /// <summary>
        /// Scan <paramref name="protectedSource"/> for the watermark marker.
        /// </summary>
        /// <param name="protectedSource">A protected JavaScript file (or any text suspected to contain a watermark).</param>
        /// <param name="key">
        /// HMAC secret. When provided, runs a constant-time compare to validate the signature.
        /// When null or empty, returns the parsed tag without validating (lookup-only mode).
        /// </param>
        public static VerifyResult Verify(string? protectedSource, string? key)
        {
            string src = protectedSource ?? string.Empty;
            Match m = MarkerPattern.Match(src);
            if (!m.Success)
            {
                return new VerifyResult(
                    present: false, tag: "", signature: "", valid: false,
                    error: "watermark: marker not found in input");
            }
            string tagB64 = m.Groups[1].Value;
            string sigB64 = m.Groups[2].Value;
            string tag;
            try
            {
                tag = Encoding.UTF8.GetString(Base64UrlDecode(tagB64));
            }
            catch (FormatException e)
            {
                return new VerifyResult(
                    present: true, tag: "", signature: sigB64, valid: false,
                    error: "watermark: tag is not valid base64url utf-8 (" + e.Message + ")");
            }

            if (string.IsNullOrEmpty(key))
            {
                // Lookup-only mode: return the tag, don't validate.
                return new VerifyResult(present: true, tag: tag, signature: sigB64, valid: false, error: null);
            }

            string expected = SignTag(tag, key!);
            bool valid = ConstantTimeEquals(expected, sigB64);
            return new VerifyResult(present: true, tag: tag, signature: sigB64, valid: valid, error: null);
        }

        // --- helpers ------------------------------------------------------

        // Base64URL (RFC 4648 §5) without padding. .NET's built-in Base64
        // uses '+' / '/' / '=' which we have to translate. There is no
        // stdlib helper for url-safe variant pre-net5 in netstandard2.0,
        // so we do it manually — keeps the package single-file.
        internal static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        internal static byte[] Base64UrlDecode(string s)
        {
            string padded = s.Replace('-', '+').Replace('_', '/');
            int pad = (4 - padded.Length % 4) % 4;
            return Convert.FromBase64String(padded + new string('=', pad));
        }

        // Constant-time string compare. Avoids leaking the prefix length
        // of a wrong signature via timing — important for any verifier
        // that's exposed publicly (web form, webhook). Comparison is
        // byte-wise on UTF-8 representations; since both inputs are
        // base64url they are ASCII so encoding is unambiguous.
        private static bool ConstantTimeEquals(string a, string b)
        {
            byte[] aBytes = Encoding.UTF8.GetBytes(a);
            byte[] bBytes = Encoding.UTF8.GetBytes(b);
            int max = Math.Max(aBytes.Length, bBytes.Length);
            int diff = aBytes.Length ^ bBytes.Length;
            for (int i = 0; i < max; i++)
            {
                byte av = i < aBytes.Length ? aBytes[i] : (byte)0;
                byte bv = i < bBytes.Length ? bBytes[i] : (byte)0;
                diff |= av ^ bv;
            }
            return diff == 0;
        }
    }
}

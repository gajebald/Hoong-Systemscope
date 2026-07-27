using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace HoongSystemScope.Core.Security;

/// <summary>
/// Bounds the opaque blobs that occasionally appear inside command lines.
/// </summary>
/// <remarks>
/// <para>
/// The obvious case is <c>powershell -EncodedCommand &lt;base64&gt;</c>, where
/// the payload can be tens of kilobytes. Dropping it outright would destroy the
/// single most useful indicator on the entry; keeping it in full bloats every
/// report and risks carrying secrets into a file the user then shares.
/// </para>
/// <para>
/// The compromise: keep a bounded prefix so the finding stays verifiable, and
/// append the full length plus a SHA-256 of the original blob so two reports
/// can still be compared byte-for-byte on that value.
/// </para>
/// </remarks>
public static class CommandLineRedactor
{
    /// <summary>Blobs longer than this are truncated.</summary>
    public const int MaximumTokenLength = 96;

    /// <summary>Number of leading characters kept from a truncated blob.</summary>
    public const int RetainedPrefixLength = 48;

    /// <summary>Truncates long opaque tokens in a command line.</summary>
    /// <param name="commandLine">The raw command line, or null.</param>
    /// <returns>The command line with over-long tokens bounded.</returns>
    public static string? Redact(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
        {
            return commandLine;
        }

        if (commandLine.Length <= MaximumTokenLength)
        {
            return commandLine;
        }

        var builder = new StringBuilder(commandLine.Length);
        var start = 0;
        var changed = false;

        while (start <= commandLine.Length)
        {
            var end = commandLine.IndexOf(' ', start);
            if (end < 0)
            {
                end = commandLine.Length;
            }

            var token = commandLine[start..end];

            if (token.Length > MaximumTokenLength && LooksOpaque(token))
            {
                builder.Append(Truncate(token));
                changed = true;
            }
            else
            {
                builder.Append(token);
            }

            if (end == commandLine.Length)
            {
                break;
            }

            builder.Append(' ');
            start = end + 1;
        }

        return changed ? builder.ToString() : commandLine;
    }

    /// <summary>
    /// True when a token looks like an encoded blob rather than a path: long,
    /// without separators, and made up of base64 or hexadecimal characters.
    /// </summary>
    private static bool LooksOpaque(string token)
    {
        if (token.Contains('\\', StringComparison.Ordinal) ||
            token.Contains('/', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in token)
        {
            var isBase64 = char.IsAsciiLetterOrDigit(c) || c is '+' or '=' or '_' or '-';
            if (!isBase64)
            {
                return false;
            }
        }

        return true;
    }

    private static string Truncate(string token)
    {
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)))
            .ToLowerInvariant();

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{token[..RetainedPrefixLength]}…[truncated: {token.Length} chars, sha256={digest[..16]}]");
    }
}

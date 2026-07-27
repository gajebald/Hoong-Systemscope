using System.Security.Cryptography;
using System.Text;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Core.Text;

/// <summary>
/// Computes the stable identity of a <see cref="ScanEntry"/>.
/// </summary>
/// <remarks>
/// The identity is derived from category, location and name only. Command
/// lines, hashes and signature states are excluded on purpose: an autostart
/// entry whose target binary was swapped out has to keep its identity so the
/// baseline comparison can report it as <em>modified</em> rather than as one
/// removal plus one addition. That distinction is the whole point of comparing
/// two scans.
/// </remarks>
public static class EntryIdentity
{
    /// <summary>Number of base64url characters kept from the digest.</summary>
    private const int IdLength = 22;

    /// <summary>Computes the identity for the given coordinates.</summary>
    /// <param name="category">Category of the entry.</param>
    /// <param name="location">Full source location, for example a registry key path.</param>
    /// <param name="name">Name of the entry within that location.</param>
    public static string Compute(ScanCategory category, string location, string name)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(name);

        var material = string.Concat(
            category.ToString(),
            "\u001f",
            PathFacts.Normalize(location),
            "\u001f",
            name.Trim().ToUpperInvariant());

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(material));

        return Convert.ToBase64String(digest)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=')[..IdLength];
    }
}

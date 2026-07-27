using System.Globalization;
using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Layered service providers and name space providers in the Winsock catalog.
/// </summary>
/// <remarks>
/// An LSP sits in the socket call path of every application that uses Winsock.
/// The mechanism is deprecated but still honoured, and a hostile provider there
/// sees all unencrypted traffic on the machine, so the catalog is worth
/// enumerating even though most machines only carry the Microsoft defaults.
/// </remarks>
public sealed class WinsockProviderCollector : CollectorBase
{
    private const string Protocol64Path =
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64";

    private const string Protocol32Path =
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries";

    private const string NameSpacePath =
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries";

    /// <inheritdoc />
    public override string Id => "winsock";

    /// <inheritdoc />
    public override string Description => "Winsock layered service providers and name space providers.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.WinsockProvider;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var catalogPath in new[] { Protocol64Path, Protocol32Path, NameSpacePath })
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var catalog = TryOpenKey(context, RegistryHiveKind.LocalMachine, catalogPath);
            if (catalog is null)
            {
                continue;
            }

            foreach (var entryName in TryGetSubKeyNames(context, catalog))
            {
                using var entry = TryOpenSubKey(context, catalog, entryName);
                if (entry is null)
                {
                    continue;
                }

                var libraryPath = entry.GetValue("LibraryPath")?.AsString();
                var displayString = entry.GetValue("DisplayString")?.AsString()
                                    ?? entry.GetValue("ProtocolName")?.AsString();

                // The protocol catalog stores the provider name inside a binary
                // structure; without a LibraryPath there is nothing to inspect.
                if (string.IsNullOrWhiteSpace(libraryPath))
                {
                    continue;
                }

                yield return CreateEntry(
                    context,
                    ScanCategory.WinsockProvider,
                    displayString is { Length: > 0 } ? displayString : entryName,
                    catalog.Path,
                    explicitExecutablePath: libraryPath,
                    isEnabled: true,
                    metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["winsock.catalogEntry"] = entryName,
                        ["winsock.catalog"] = catalogPath.Contains("NameSpace", StringComparison.OrdinalIgnoreCase)
                            ? "NameSpace"
                            : "Protocol",
                    });
            }
        }
    }

    /// <summary>Renders a catalog entry index for display.</summary>
    internal static string DescribeIndex(int index) => index.ToString(CultureInfo.InvariantCulture);
}

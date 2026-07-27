using System.Globalization;
using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Non-default entries of the <c>hosts</c> file.
/// </summary>
/// <remarks>
/// Redirecting a name locally is a cheap way to block security updates or to
/// point a browser at a different server. Loopback mappings are the normal case
/// and are reported as informational; anything pointing at a real address is
/// what deserves attention.
/// </remarks>
public sealed class HostsFileCollector : CollectorBase
{
    private static readonly char[] FieldSeparators = [' ', '\t'];

    /// <inheritdoc />
    public override string Id => "hosts";

    /// <inheritdoc />
    public override string Description => "Name to address mappings configured in the hosts file.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.HostsFile;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        var path = context.Environment.HostsFilePath;
        var content = context.FileSystem.ReadAllText(path);

        if (content is null)
        {
            if (context.FileSystem.FileExists(path))
            {
                context.Diagnostics.Report(new ScanError
                {
                    CollectorId = Id,
                    Severity = ScanErrorSeverity.Warning,
                    Message = $"The hosts file at '{path}' exists but could not be read.",
                    Location = path,
                });
            }

            yield break;
        }

        var lines = content.Split('\n');

        for (var index = 0; index < lines.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var line = lines[index].Trim().TrimEnd('\r');

            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            var comment = line.IndexOf('#', StringComparison.Ordinal);
            if (comment >= 0)
            {
                line = line[..comment].Trim();
            }

            var parts = line.Split(FieldSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                continue;
            }

            var address = parts[0];

            foreach (var hostName in parts.Skip(1))
            {
                yield return CreateEntry(
                    context,
                    ScanCategory.HostsFile,
                    hostName,
                    path,
                    commandLine: null,
                    explicitExecutablePath: null,
                    isEnabled: true,
                    metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    {
                        [MetadataKeys.HostsAddress] = address,
                        [MetadataKeys.HostsLine] = (index + 1).ToString(CultureInfo.InvariantCulture),
                        ["hosts.isLoopback"] = IsLoopback(address) ? "true" : "false",
                    });
            }
        }
    }

    /// <summary>True for the addresses that merely block a name rather than redirect it.</summary>
    internal static bool IsLoopback(string address) =>
        address is "127.0.0.1" or "0.0.0.0" or "::1" or "::";
}

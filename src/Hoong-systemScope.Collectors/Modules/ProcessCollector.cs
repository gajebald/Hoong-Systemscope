using System.Globalization;
using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Currently running processes.
/// </summary>
/// <remarks>
/// A process is not a persistence point, so these entries are context rather
/// than findings. They matter because an autostart entry pointing at a missing
/// file plus a running process from the same directory tells a different story
/// than either fact alone.
/// </remarks>
public sealed class ProcessCollector : CollectorBase
{
    /// <inheritdoc />
    public override string Id => "processes";

    /// <inheritdoc />
    public override string Description => "Running processes with their image path, command line and parent.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.Process;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var process in context.Processes.Enumerate(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeys.ProcessId] = process.ProcessId.ToString(CultureInfo.InvariantCulture),
            };

            if (process.ParentProcessId is { } parentId)
            {
                metadata[MetadataKeys.ParentProcessId] = parentId.ToString(CultureInfo.InvariantCulture);
            }

            if (process.ParentName is { Length: > 0 })
            {
                metadata[MetadataKeys.ParentProcessName] = process.ParentName;
            }

            // The identity has to include the process id: two instances of the
            // same executable are two distinct entries.
            var name = string.Create(CultureInfo.InvariantCulture, $"{process.Name} ({process.ProcessId})");

            yield return CreateEntry(
                context,
                ScanCategory.Process,
                name,
                "Running processes",
                explicitExecutablePath: process.ExecutablePath,
                explicitArguments: null,
                userName: process.UserName,
                isEnabled: true,
                metadata: metadata) with
            {
                CommandLine = Core.Security.CommandLineRedactor.Redact(process.CommandLine),
            };
        }
    }
}

using System.Globalization;
using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Win32 services and, in its driver variant, kernel and file system drivers.
/// </summary>
/// <remarks>
/// One class serves both categories because they live in the same database and
/// differ only in their type flag. <see cref="DriverCollector"/> is the thin
/// subclass that flips the filter.
/// </remarks>
public class ServiceCollector : CollectorBase
{
    /// <inheritdoc />
    public override string Id => "services";

    /// <inheritdoc />
    public override string Description => "Win32 services with start type, account and image path.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.Service;

    /// <inheritdoc />
    public override bool RequiresElevation => true;

    /// <summary>Which kind of service database entry this collector reports.</summary>
    protected virtual ServiceKind TargetKind => ServiceKind.Service;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var service in context.Services.Enumerate(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (service.Kind != TargetKind)
            {
                continue;
            }

            var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeys.ServiceStartMode] = service.StartMode.ToString(),
                [MetadataKeys.Description] = service.Description,
            };

            if (service.IsRunning is { } running)
            {
                metadata[MetadataKeys.ServiceRunning] = running ? "true" : "false";
            }

            if (service.Group is { Length: > 0 })
            {
                metadata[MetadataKeys.ServiceGroup] = service.Group;
            }

            // A shared-host service is implemented by a DLL. svchost.exe itself
            // is Microsoft-signed, so the DLL is the part actually worth
            // inspecting.
            if (service.ServiceDll is { Length: > 0 })
            {
                metadata[MetadataKeys.ServiceDll] = service.ServiceDll;
            }

            yield return CreateEntry(
                context,
                Category,
                service.ServiceName,
                @"HKLM\SYSTEM\CurrentControlSet\Services",
                commandLine: service.ImagePath,
                userName: service.Account,
                isEnabled: service.StartMode != ServiceStartMode.Disabled,
                metadata: metadata) with
            {
                FileDescription = service.DisplayName,
            };
        }
    }

    /// <summary>Renders a start mode for display.</summary>
    protected static string Describe(ServiceStartMode mode) =>
        mode.ToString().ToUpper(CultureInfo.InvariantCulture);
}

/// <summary>Kernel mode and file system drivers.</summary>
public sealed class DriverCollector : ServiceCollector
{
    /// <inheritdoc />
    public override string Id => "drivers";

    /// <inheritdoc />
    public override string Description => "Kernel mode and file system drivers registered in the service database.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.Driver;

    /// <inheritdoc />
    protected override ServiceKind TargetKind => ServiceKind.Driver;
}

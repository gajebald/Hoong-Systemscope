using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// The classic <c>Run</c> family of registry keys.
/// </summary>
/// <remarks>
/// Still the single most common persistence point on Windows. Every location
/// is read in both the 64 and the 32 bit view, and with
/// <see cref="ScanOptions.IncludeAllUsers"/> also for every other user whose
/// hive happens to be loaded.
/// </remarks>
public sealed class RegistryRunCollector : CollectorBase
{
    private sealed record RunLocation(
        RegistryHiveKind Hive,
        string Path,
        ScanCategory Category,
        bool IsPerUser);

    private static readonly RunLocation[] Locations =
    [
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ScanCategory.RegistryRun, false),
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", ScanCategory.RegistryRunOnce, false),
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", ScanCategory.RegistryRunOnce, false),
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", ScanCategory.RegistryRun, false),
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", ScanCategory.RegistryRunOnce, false),
        new(RegistryHiveKind.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", ScanCategory.RegistryRun, false),
        new(RegistryHiveKind.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ScanCategory.RegistryRun, true),
        new(RegistryHiveKind.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", ScanCategory.RegistryRunOnce, true),
        new(RegistryHiveKind.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", ScanCategory.RegistryRunOnce, true),
        new(RegistryHiveKind.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", ScanCategory.RegistryRun, true),
        new(RegistryHiveKind.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", ScanCategory.RegistryRun, true),
    ];

    /// <inheritdoc />
    public override string Id => "registry-run";

    /// <inheritdoc />
    public override string Description => "Run, RunOnce and RunServices keys under HKLM and the user hives.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.RegistryRun;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var location in Locations)
        {
            foreach (var view in GetViews(context))
            {
                cancellationToken.ThrowIfCancellationRequested();

                foreach (var entry in ReadLocation(context, location.Hive, location.Path, location.Category, view, null))
                {
                    yield return entry;
                }
            }
        }

        if (!context.Options.IncludeAllUsers)
        {
            yield break;
        }

        foreach (var profile in context.Environment.GetUserProfiles())
        {
            if (!profile.IsHiveLoaded)
            {
                // Loading the hive would write to the machine. Report the gap
                // instead of creating one.
                context.Diagnostics.Report(new ScanError
                {
                    CollectorId = Id,
                    Severity = ScanErrorSeverity.Information,
                    Message = $"Profile '{profile.UserName ?? profile.Sid}' was skipped because its registry hive is not loaded. " +
                              "Hoong-systemScope does not mount hives, because that would modify the system.",
                    Location = $"HKEY_USERS\\{profile.Sid}",
                });
                continue;
            }

            foreach (var location in Locations.Where(l => l.IsPerUser))
            {
                foreach (var view in GetViews(context))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var path = $"{profile.Sid}\\{location.Path}";
                    foreach (var entry in ReadLocation(context, RegistryHiveKind.Users, path, location.Category, view, profile.Sid))
                    {
                        yield return entry;
                    }
                }
            }
        }
    }

    private IEnumerable<ScanEntry> ReadLocation(
        ScanContext context,
        RegistryHiveKind hive,
        string path,
        ScanCategory category,
        RegistryViewKind view,
        string? userSid)
    {
        using var key = TryOpenKey(context, hive, path, view);
        if (key is null)
        {
            yield break;
        }

        foreach (var valueName in key.GetValueNames())
        {
            var value = key.GetValue(valueName);
            var commandLine = value?.AsString();

            if (string.IsNullOrWhiteSpace(commandLine))
            {
                continue;
            }

            var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            {
                [MetadataKeys.RegistryView] = view.ToString(),
            };

            if (userSid is not null)
            {
                metadata[MetadataKeys.UserSid] = userSid;
            }

            yield return CreateEntry(
                context,
                category,
                string.IsNullOrEmpty(valueName) ? "(Default)" : valueName,
                key.Path,
                commandLine: commandLine,
                userName: userSid,
                isEnabled: true,
                metadata: metadata);
        }
    }
}

using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Security;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Programs and shortcuts placed in a Startup folder.
/// </summary>
/// <remarks>
/// Shortcuts are resolved to their target, because a <c>.lnk</c> file itself
/// carries no signature and no version resource. Judging the shortcut rather
/// than what it launches would make every entry here look equally opaque.
/// </remarks>
public sealed class StartupFolderCollector : CollectorBase
{
    /// <inheritdoc />
    public override string Id => "startup-folder";

    /// <inheritdoc />
    public override string Description => "Executables and shortcuts in the per-user and all-users Startup folders.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.StartupFolder;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        var folders = new List<string>();

        if (context.Environment.CurrentUserStartupFolder is { } userFolder)
        {
            folders.Add(userFolder);
        }

        if (context.Environment.CommonStartupFolder is { } commonFolder)
        {
            folders.Add(commonFolder);
        }

        if (context.Options.IncludeAllUsers)
        {
            foreach (var profile in context.Environment.GetUserProfiles())
            {
                if (profile.ProfilePath is { } profilePath)
                {
                    folders.Add(System.IO.Path.Combine(
                        profilePath,
                        @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
                }
            }
        }

        foreach (var folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var entry in ReadFolder(context, folder))
            {
                yield return entry;
            }
        }
    }

    private static IEnumerable<ScanEntry> ReadFolder(ScanContext context, string folder)
    {
        if (SensitiveLocations.IsDeniedPath(folder) || !context.FileSystem.DirectoryExists(folder))
        {
            yield break;
        }

        foreach (var file in context.FileSystem.EnumerateFiles(folder))
        {
            var fileName = PathFacts.GetFileName(file);

            // desktop.ini configures the folder's appearance and is not a
            // startup item.
            if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            string? executablePath = file;
            string? arguments = null;

            if (PathFacts.GetExtension(file).Equals(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var target = context.Shortcuts.Resolve(file);

                if (target?.TargetPath is { Length: > 0 } resolvedTarget)
                {
                    executablePath = resolvedTarget;
                    arguments = target.Arguments;
                    metadata[MetadataKeys.ShortcutTarget] = resolvedTarget;
                }
                else
                {
                    // A shortcut whose target cannot be resolved is itself worth
                    // reporting; leaving it out would hide a broken or crafted link.
                    metadata[MetadataKeys.ShortcutTarget] = null;
                    executablePath = null;
                }
            }

            yield return CreateEntry(
                context,
                ScanCategory.StartupFolder,
                fileName,
                folder,
                commandLine: null,
                explicitExecutablePath: executablePath,
                explicitArguments: arguments,
                isEnabled: true,
                metadata: metadata);
        }
    }
}

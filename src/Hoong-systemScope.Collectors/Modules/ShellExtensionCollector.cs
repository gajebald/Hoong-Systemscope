using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Shell extensions and browser helper objects.
/// </summary>
/// <remarks>
/// These are registered as a class identifier, not as a path. The path lives in
/// the <c>InProcServer32</c> key of the matching CLSID, so every entry needs a
/// second lookup before there is anything worth hashing or verifying.
/// </remarks>
public sealed class ShellExtensionCollector : CollectorBase
{
    private const string ApprovedPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";

    private const string BrowserHelperObjectsPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";

    private static readonly string[] HandlerRoots =
    [
        @"*\shellex\ContextMenuHandlers",
        @"Directory\shellex\ContextMenuHandlers",
        @"Directory\Background\shellex\ContextMenuHandlers",
        @"Folder\shellex\ContextMenuHandlers",
        @"AllFilesystemObjects\shellex\ContextMenuHandlers",
    ];

    /// <inheritdoc />
    public override string Id => "shell-extensions";

    /// <inheritdoc />
    public override string Description =>
        "Approved shell extensions, context menu handlers and browser helper objects.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.ShellExtension;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var view in GetViews(context))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var approved = TryOpenKey(context, RegistryHiveKind.LocalMachine, ApprovedPath, view);
            if (approved is not null)
            {
                foreach (var clsid in approved.GetValueNames())
                {
                    var label = approved.GetValue(clsid)?.AsString();

                    yield return CreateComEntry(
                        context, view, ScanCategory.ShellExtension,
                        label is { Length: > 0 } ? label : clsid, clsid, approved.Path);
                }
            }

            using var browserHelpers = TryOpenKey(context, RegistryHiveKind.LocalMachine, BrowserHelperObjectsPath, view);
            if (browserHelpers is not null)
            {
                foreach (var clsid in TryGetSubKeyNames(context, browserHelpers))
                {
                    yield return CreateComEntry(
                        context, view, ScanCategory.BrowserHelperObject, clsid, clsid, browserHelpers.Path);
                }
            }

            foreach (var root in HandlerRoots)
            {
                cancellationToken.ThrowIfCancellationRequested();

                using var handlers = TryOpenKey(context, RegistryHiveKind.ClassesRoot, root, view);
                if (handlers is null)
                {
                    continue;
                }

                foreach (var handlerName in TryGetSubKeyNames(context, handlers))
                {
                    using var handler = TryOpenSubKey(context, handlers, handlerName);

                    // The default value of the handler key holds the CLSID.
                    var clsid = handler?.GetValue(string.Empty)?.AsString();
                    if (string.IsNullOrWhiteSpace(clsid))
                    {
                        continue;
                    }

                    yield return CreateComEntry(
                        context, view, ScanCategory.ShellExtension, handlerName, clsid, handlers.Path);
                }
            }
        }
    }

    private ScanEntry CreateComEntry(
        ScanContext context,
        RegistryViewKind view,
        ScanCategory category,
        string name,
        string classId,
        string location)
    {
        var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            [MetadataKeys.RegistryView] = view.ToString(),
            [MetadataKeys.ClassId] = classId,
        };

        var server = ResolveInProcServer(context, classId, view, metadata);

        return CreateEntry(
            context,
            category,
            name,
            location,
            explicitExecutablePath: server,
            isEnabled: true,
            metadata: metadata);
    }

    /// <summary>Looks up the DLL registered for a class identifier.</summary>
    private string? ResolveInProcServer(
        ScanContext context,
        string classId,
        RegistryViewKind view,
        Dictionary<string, string?> metadata)
    {
        using var server = TryOpenKey(context, RegistryHiveKind.ClassesRoot, $@"CLSID\{classId}\InProcServer32", view);
        if (server is null)
        {
            return null;
        }

        var path = server.GetValue(string.Empty)?.AsString();
        var threadingModel = server.GetValue("ThreadingModel")?.AsString();

        if (threadingModel is { Length: > 0 })
        {
            metadata[MetadataKeys.ThreadingModel] = threadingModel;
        }

        return string.IsNullOrWhiteSpace(path) ? null : path;
    }
}

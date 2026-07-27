using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// Image File Execution Options debugger hijacks.
/// </summary>
/// <remarks>
/// Setting <c>Debugger</c> under an IFEO key makes Windows launch that program
/// instead of the named executable, with the original path handed over as an
/// argument. It is a legitimate debugging feature and a very effective hijack:
/// pointing <c>sethc.exe</c> at <c>cmd.exe</c> is the classic sticky-keys
/// backdoor. The related <c>GlobalFlag</c> and <c>ReportingMode</c> silent
/// process exit monitors are covered as well.
/// </remarks>
public sealed class ImageFileExecutionOptionsCollector : CollectorBase
{
    private const string IfeoPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    private const string SilentExitPath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

    /// <inheritdoc />
    public override string Id => "ifeo";

    /// <inheritdoc />
    public override string Description => "Image File Execution Options debuggers and silent process exit monitors.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.ImageFileExecutionOptions;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var view in GetViews(context))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var ifeo = TryOpenKey(context, RegistryHiveKind.LocalMachine, IfeoPath, view);
            if (ifeo is not null)
            {
                foreach (var imageName in TryGetSubKeyNames(context, ifeo))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    using var image = TryOpenSubKey(context, ifeo, imageName);
                    var debugger = image?.GetValue("Debugger")?.AsString();

                    // The vast majority of IFEO keys only carry mitigation
                    // policy flags. Only a Debugger value redirects execution.
                    if (string.IsNullOrWhiteSpace(debugger))
                    {
                        continue;
                    }

                    yield return CreateEntry(
                        context,
                        ScanCategory.ImageFileExecutionOptions,
                        imageName,
                        ifeo.Path,
                        commandLine: debugger,
                        isEnabled: true,
                        metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                        {
                            [MetadataKeys.RegistryView] = view.ToString(),
                            ["ifeo.hijackedImage"] = imageName,
                            ["ifeo.kind"] = "Debugger",
                        });
                }
            }

            using var silentExit = TryOpenKey(context, RegistryHiveKind.LocalMachine, SilentExitPath, view);
            if (silentExit is null)
            {
                continue;
            }

            foreach (var imageName in TryGetSubKeyNames(context, silentExit))
            {
                using var image = TryOpenSubKey(context, silentExit, imageName);
                var monitor = image?.GetValue("MonitorProcess")?.AsString();

                if (string.IsNullOrWhiteSpace(monitor))
                {
                    continue;
                }

                yield return CreateEntry(
                    context,
                    ScanCategory.ImageFileExecutionOptions,
                    imageName,
                    silentExit.Path,
                    commandLine: monitor,
                    isEnabled: true,
                    metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    {
                        [MetadataKeys.RegistryView] = view.ToString(),
                        ["ifeo.hijackedImage"] = imageName,
                        ["ifeo.kind"] = "SilentProcessExit",
                    });
            }
        }
    }
}

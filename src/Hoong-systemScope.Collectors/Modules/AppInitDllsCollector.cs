using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// <c>AppInit_DLLs</c> and <c>AppCertDlls</c>.
/// </summary>
/// <remarks>
/// Both mechanisms load a library into other processes: AppInit_DLLs into every
/// process that links user32, AppCertDlls into every process that creates a
/// child. Either is a system-wide injection point and is almost always empty on
/// a healthy machine, which makes any entry here worth surfacing.
/// </remarks>
public sealed class AppInitDllsCollector : CollectorBase
{
    private static readonly char[] ListSeparators = [' ', ','];

    private const string WindowsPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string AppCertPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls";

    /// <inheritdoc />
    public override string Id => "appinit-dlls";

    /// <inheritdoc />
    public override string Description => "AppInit_DLLs and AppCertDlls, both of which inject libraries into other processes.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.AppInitDll;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var view in GetViews(context))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var windows = TryOpenKey(context, RegistryHiveKind.LocalMachine, WindowsPath, view);
            if (windows is not null)
            {
                var raw = windows.GetValue("AppInit_DLLs")?.AsString();
                var loadEnabled = windows.GetValue("LoadAppInit_DLLs")?.AsInt32();

                // The value list stays populated even when loading is switched
                // off, so the switch has to travel with the entry.
                foreach (var dll in SplitList(raw))
                {
                    yield return CreateEntry(
                        context,
                        ScanCategory.AppInitDll,
                        dll,
                        windows.Path,
                        explicitExecutablePath: dll,
                        isEnabled: loadEnabled is null or not 0,
                        metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                        {
                            [MetadataKeys.RegistryView] = view.ToString(),
                            ["appInit.loadEnabled"] = loadEnabled is null ? null : (loadEnabled != 0).ToString(),
                            ["appInit.valueName"] = "AppInit_DLLs",
                        });
                }
            }

            using var appCert = TryOpenKey(context, RegistryHiveKind.LocalMachine, AppCertPath, view);
            if (appCert is null)
            {
                continue;
            }

            foreach (var valueName in appCert.GetValueNames())
            {
                var dll = appCert.GetValue(valueName)?.AsString();
                if (string.IsNullOrWhiteSpace(dll))
                {
                    continue;
                }

                yield return CreateEntry(
                    context,
                    ScanCategory.AppInitDll,
                    valueName,
                    appCert.Path,
                    explicitExecutablePath: dll,
                    isEnabled: true,
                    metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    {
                        [MetadataKeys.RegistryView] = view.ToString(),
                        ["appInit.valueName"] = "AppCertDlls",
                    });
            }
        }
    }

    private static IEnumerable<string> SplitList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            yield break;
        }

        // The value holds several libraries separated by spaces or commas.
        foreach (var part in raw.Split(ListSeparators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            yield return part.Trim('"');
        }
    }
}

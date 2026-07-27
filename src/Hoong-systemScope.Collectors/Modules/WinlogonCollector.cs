using System.Runtime.CompilerServices;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Collectors.Modules;

/// <summary>
/// The Winlogon hooks, which run before or instead of the shell.
/// </summary>
/// <remarks>
/// <c>Userinit</c> and <c>Shell</c> have well-known default values. Appending a
/// second program to <c>Userinit</c> is a long-standing persistence trick that
/// keeps the login working and is therefore easy to miss, so the collector
/// records the expected value alongside the actual one.
/// </remarks>
public sealed class WinlogonCollector : CollectorBase
{
    private const string WinlogonPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static readonly (string ValueName, string ExpectedDefault)[] MonitoredValues =
    [
        ("Userinit", @"C:\Windows\system32\userinit.exe,"),
        ("Shell", "explorer.exe"),
        ("Taskman", ""),
        ("AppSetup", ""),
        ("GinaDLL", ""),
        ("UIHost", "logonui.exe"),
        ("VmApplet", "SystemPropertiesPerformance.exe /pagefile"),
    ];

    /// <inheritdoc />
    public override string Id => "winlogon";

    /// <inheritdoc />
    public override string Description => "Winlogon hooks: Userinit, Shell, Taskman, GinaDLL and the Notify handlers.";

    /// <inheritdoc />
    public override ScanCategory Category => ScanCategory.WinlogonHook;

    /// <inheritdoc />
    public override async IAsyncEnumerable<ScanEntry> CollectAsync(
        ScanContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();

        foreach (var view in GetViews(context))
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var key = TryOpenKey(context, RegistryHiveKind.LocalMachine, WinlogonPath, view);
            if (key is null)
            {
                continue;
            }

            foreach (var (valueName, expectedDefault) in MonitoredValues)
            {
                var value = key.GetValue(valueName)?.AsString();
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                var metadata = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                {
                    [MetadataKeys.RegistryView] = view.ToString(),
                    ["winlogon.expectedDefault"] = expectedDefault.Length == 0 ? null : expectedDefault,
                    ["winlogon.isDefault"] = IsDefaultValue(value, expectedDefault) ? "true" : "false",
                };

                yield return CreateEntry(
                    context,
                    ScanCategory.WinlogonHook,
                    valueName,
                    key.Path,
                    commandLine: value.TrimEnd(','),
                    isEnabled: true,
                    metadata: metadata);
            }

            // The Notify subkeys load a DLL into winlogon.exe at logon.
            using var notify = TryOpenSubKey(context, key, "Notify");
            if (notify is null)
            {
                continue;
            }

            foreach (var name in TryGetSubKeyNames(context, notify))
            {
                using var handler = TryOpenSubKey(context, notify, name);
                var dll = handler?.GetValue("DllName")?.AsString();

                if (string.IsNullOrWhiteSpace(dll))
                {
                    continue;
                }

                yield return CreateEntry(
                    context,
                    ScanCategory.WinlogonHook,
                    $"Notify\\{name}",
                    notify.Path,
                    explicitExecutablePath: dll,
                    isEnabled: true,
                    metadata: new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    {
                        [MetadataKeys.RegistryView] = view.ToString(),
                    });
            }
        }
    }

    private static bool IsDefaultValue(string actual, string expectedDefault) =>
        expectedDefault.Length > 0 &&
        actual.Trim().TrimEnd(',').Equals(expectedDefault.TrimEnd(','), StringComparison.OrdinalIgnoreCase);
}

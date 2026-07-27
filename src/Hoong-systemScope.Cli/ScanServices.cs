using System.Runtime.Versioning;
using HoongSystemScope.Analysis;
using HoongSystemScope.Collectors;
using HoongSystemScope.Collectors.Modules;
using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Export;
using HoongSystemScope.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace HoongSystemScope.Cli;

/// <summary>
/// The composition root.
/// </summary>
/// <remarks>
/// This is the only place where the platform-independent half of the tool is
/// bound to the Windows half. Everything above Core talks to abstractions, so
/// swapping this registration is all a future WPF or WinUI front end has to do.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class ScanServices
{
    /// <summary>Registers everything needed to run a scan.</summary>
    public static IServiceCollection AddHoongSystemScope(this IServiceCollection services, LogLevel logLevel)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddLogging(builder => builder
            .SetMinimumLevel(logLevel)
            .AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace));

        // Windows implementations of the Core abstractions.
        services.AddSingleton<IRegistryReader, WindowsRegistryReader>();
        services.AddSingleton<IFileSystemProbe, WindowsFileSystemProbe>();
        services.AddSingleton<IFileMetadataProvider, WindowsFileMetadataProvider>();
        services.AddSingleton<IHashProvider, Sha256HashProvider>();
        services.AddSingleton<ISignatureVerifier, AuthenticodeSignatureVerifier>();
        services.AddSingleton<IServiceCatalog, RegistryServiceCatalog>();
        services.AddSingleton<IScheduledTaskProvider, TaskSchedulerProvider>();
        services.AddSingleton<IProcessProvider, WindowsProcessProvider>();
        services.AddSingleton<IShortcutResolver, WindowsShortcutResolver>();
        services.AddSingleton<IEnvironmentProbe, WindowsEnvironmentProbe>();
        services.AddSingleton<ISystemClock>(SystemClock.Instance);

        // Collectors, in the order they appear in the report.
        services.AddSingleton<IScanCollector, RegistryRunCollector>();
        services.AddSingleton<IScanCollector, StartupFolderCollector>();
        services.AddSingleton<IScanCollector, ServiceCollector>();
        services.AddSingleton<IScanCollector, DriverCollector>();
        services.AddSingleton<IScanCollector, ScheduledTaskCollector>();
        services.AddSingleton<IScanCollector, WinlogonCollector>();
        services.AddSingleton<IScanCollector, AppInitDllsCollector>();
        services.AddSingleton<IScanCollector, ImageFileExecutionOptionsCollector>();
        services.AddSingleton<IScanCollector, ShellExtensionCollector>();
        services.AddSingleton<IScanCollector, WinsockProviderCollector>();
        services.AddSingleton<IScanCollector, HostsFileCollector>();
        services.AddSingleton<IScanCollector, ProcessCollector>();

        services.AddSingleton<ScanOrchestrator>();
        services.AddSingleton(_ => RiskEngine.CreateDefault());
        services.AddSingleton<BaselineComparer>();

        services.AddSingleton<IReportWriter, JsonReportWriter>();
        services.AddSingleton<IReportWriter, TextReportWriter>();
        services.AddSingleton<IReportWriter, CsvReportWriter>();

        return services;
    }
}

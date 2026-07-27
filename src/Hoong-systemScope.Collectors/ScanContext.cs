using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Collectors;

/// <summary>
/// Everything a collector is allowed to touch.
/// </summary>
/// <remarks>
/// A collector receives no ambient access to the machine: whatever is not on
/// this context does not exist for it. That is what keeps the collectors
/// platform independent and, more importantly, what keeps their reach
/// auditable.
/// </remarks>
public sealed class ScanContext
{
    /// <summary>Creates a context.</summary>
    public ScanContext(
        ScanOptions options,
        IRegistryReader registry,
        IFileSystemProbe fileSystem,
        IEnvironmentProbe environment,
        IServiceCatalog services,
        IScheduledTaskProvider scheduledTasks,
        IProcessProvider processes,
        IShortcutResolver shortcuts,
        ISystemClock clock,
        ICollectorDiagnostics diagnostics)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(fileSystem);
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(scheduledTasks);
        ArgumentNullException.ThrowIfNull(processes);
        ArgumentNullException.ThrowIfNull(shortcuts);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(diagnostics);

        Options = options;
        Registry = registry;
        FileSystem = fileSystem;
        Environment = environment;
        Services = services;
        ScheduledTasks = scheduledTasks;
        Processes = processes;
        Shortcuts = shortcuts;
        Clock = clock;
        Diagnostics = diagnostics;
        CommandLines = new CommandLineParser(fileSystem, environment);
    }

    /// <summary>What the caller asked for.</summary>
    public ScanOptions Options { get; }

    /// <summary>Read-only registry access.</summary>
    public IRegistryReader Registry { get; }

    /// <summary>Read-only file system access.</summary>
    public IFileSystemProbe FileSystem { get; }

    /// <summary>Machine facts and environment expansion.</summary>
    public IEnvironmentProbe Environment { get; }

    /// <summary>Service and driver database.</summary>
    public IServiceCatalog Services { get; }

    /// <summary>Task scheduler.</summary>
    public IScheduledTaskProvider ScheduledTasks { get; }

    /// <summary>Running processes.</summary>
    public IProcessProvider Processes { get; }

    /// <summary>Shell link resolution.</summary>
    public IShortcutResolver Shortcuts { get; }

    /// <summary>Time source.</summary>
    public ISystemClock Clock { get; }

    /// <summary>Where to report gaps and failures.</summary>
    public ICollectorDiagnostics Diagnostics { get; }

    /// <summary>Shared command line parser bound to this context's probes.</summary>
    public CommandLineParser CommandLines { get; }
}

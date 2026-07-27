namespace HoongSystemScope.Core.Models;

/// <summary>
/// Well-known keys used in <see cref="ScanEntry.Metadata"/>.
/// </summary>
/// <remarks>
/// Collectors write them, risk rules and exporters read them. They live in
/// Core so that all three sides share one definition without Analysis or
/// Export having to reference the collectors.
/// </remarks>
public static class MetadataKeys
{
    /// <summary>Set to <c>true</c> when the command line contained an unquoted path with spaces.</summary>
    public const string UnquotedPath = "unquotedPath";

    /// <summary>The library loaded by a rundll32 invocation.</summary>
    public const string Rundll32Target = "rundll32.target";

    /// <summary>The exported entry point a rundll32 invocation calls.</summary>
    public const string Rundll32EntryPoint = "rundll32.entryPoint";

    /// <summary>Registry view the entry was found in.</summary>
    public const string RegistryView = "registry.view";

    /// <summary>Configured start type of a service or driver.</summary>
    public const string ServiceStartMode = "service.startMode";

    /// <summary>Whether the service is currently running.</summary>
    public const string ServiceRunning = "service.running";

    /// <summary>Load order group of a service or driver.</summary>
    public const string ServiceGroup = "service.group";

    /// <summary>DLL implementing a shared-host service.</summary>
    public const string ServiceDll = "service.dll";

    /// <summary>Description recorded for a service or task.</summary>
    public const string Description = "description";

    /// <summary>Whether a scheduled task is flagged hidden.</summary>
    public const string TaskHidden = "task.hidden";

    /// <summary>Requested privilege level of a scheduled task.</summary>
    public const string TaskRunLevel = "task.runLevel";

    /// <summary>Summary of a scheduled task's triggers.</summary>
    public const string TaskTriggers = "task.triggers";

    /// <summary>Author recorded in a scheduled task definition.</summary>
    public const string TaskAuthor = "task.author";

    /// <summary>Number of actions a scheduled task performs.</summary>
    public const string TaskActionCount = "task.actionCount";

    /// <summary>Process identifier.</summary>
    public const string ProcessId = "process.id";

    /// <summary>Identifier of the parent process.</summary>
    public const string ParentProcessId = "process.parentId";

    /// <summary>Name of the parent process.</summary>
    public const string ParentProcessName = "process.parentName";

    /// <summary>Target a shortcut points at.</summary>
    public const string ShortcutTarget = "shortcut.target";

    /// <summary>The COM class identifier behind a shell extension or browser helper object.</summary>
    public const string ClassId = "com.clsid";

    /// <summary>Threading model declared by a COM in-process server.</summary>
    public const string ThreadingModel = "com.threadingModel";

    /// <summary>Address a hosts file entry maps to.</summary>
    public const string HostsAddress = "hosts.address";

    /// <summary>Line number a hosts file entry came from.</summary>
    public const string HostsLine = "hosts.line";

    /// <summary>The user profile an entry belongs to.</summary>
    public const string UserSid = "user.sid";
}

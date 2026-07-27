namespace HoongSystemScope.Core.Models;

/// <summary>
/// Classifies where a <see cref="ScanEntry"/> was found. The category drives
/// both the report grouping and several risk rules, so it is deliberately more
/// granular than a plain "autostart / service / task" split.
/// </summary>
public enum ScanCategory
{
    /// <summary>Fallback for entries that do not fit any known category.</summary>
    Other = 0,

    /// <summary>Classic <c>Run</c> keys under HKLM or HKCU.</summary>
    RegistryRun,

    /// <summary>One-shot <c>RunOnce</c> / <c>RunOnceEx</c> keys.</summary>
    RegistryRunOnce,

    /// <summary>Shortcuts and executables in a Startup folder.</summary>
    StartupFolder,

    /// <summary>Win32 service.</summary>
    Service,

    /// <summary>Kernel mode or file system driver.</summary>
    Driver,

    /// <summary>Entry of the Windows task scheduler.</summary>
    ScheduledTask,

    /// <summary>Currently running process.</summary>
    Process,

    /// <summary>Winlogon hooks such as <c>Userinit</c>, <c>Shell</c> or <c>Notify</c>.</summary>
    WinlogonHook,

    /// <summary><c>AppInit_DLLs</c> and <c>AppCertDlls</c>, both loaded into foreign processes.</summary>
    AppInitDll,

    /// <summary>Image File Execution Options debugger hijack.</summary>
    ImageFileExecutionOptions,

    /// <summary>Registered shell extension or context menu handler.</summary>
    ShellExtension,

    /// <summary>Browser Helper Object.</summary>
    BrowserHelperObject,

    /// <summary>Layered Service Provider or name space provider in the Winsock catalog.</summary>
    WinsockProvider,

    /// <summary>Non-default entry in the <c>hosts</c> file.</summary>
    HostsFile,
}

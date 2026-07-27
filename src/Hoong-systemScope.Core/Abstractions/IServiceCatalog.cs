namespace HoongSystemScope.Core.Abstractions;

/// <summary>How a service or driver is configured to start.</summary>
public enum ServiceStartMode
{
    /// <summary>Start type could not be determined.</summary>
    Unknown = 0,

    /// <summary>Loaded by the boot loader (drivers only).</summary>
    Boot,

    /// <summary>Started during kernel initialisation (drivers only).</summary>
    System,

    /// <summary>Started automatically at boot.</summary>
    Automatic,

    /// <summary>Started on demand.</summary>
    Manual,

    /// <summary>Never started.</summary>
    Disabled,
}

/// <summary>Whether an entry of the service database is a service or a driver.</summary>
public enum ServiceKind
{
    /// <summary>Type could not be determined.</summary>
    Unknown = 0,

    /// <summary>User mode Win32 service.</summary>
    Service,

    /// <summary>Kernel mode or file system driver.</summary>
    Driver,
}

/// <summary>One entry of the Windows service database.</summary>
public sealed record ServiceRecord
{
    /// <summary>Short service name, the key name below <c>CurrentControlSet\Services</c>.</summary>
    public required string ServiceName { get; init; }

    /// <summary>Display name, falling back to the service name.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Description text, when present.</summary>
    public string? Description { get; init; }

    /// <summary>Raw <c>ImagePath</c> value, still in its native form.</summary>
    public string? ImagePath { get; init; }

    /// <summary>Account the service runs as.</summary>
    public string? Account { get; init; }

    /// <summary>Service or driver.</summary>
    public ServiceKind Kind { get; init; }

    /// <summary>Configured start type.</summary>
    public ServiceStartMode StartMode { get; init; }

    /// <summary>True when the service is currently running, null when not determined.</summary>
    public bool? IsRunning { get; init; }

    /// <summary>Group the service belongs to, when set.</summary>
    public string? Group { get; init; }

    /// <summary>For svchost-hosted services: the DLL that actually implements the service.</summary>
    public string? ServiceDll { get; init; }
}

/// <summary>Enumerates services and drivers.</summary>
public interface IServiceCatalog
{
    /// <summary>Reads the service database. Entries that cannot be read are skipped.</summary>
    IEnumerable<ServiceRecord> Enumerate(CancellationToken cancellationToken);
}

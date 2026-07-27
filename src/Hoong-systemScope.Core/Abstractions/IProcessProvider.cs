namespace HoongSystemScope.Core.Abstractions;

/// <summary>A running process.</summary>
public sealed record ProcessRecord
{
    /// <summary>Process identifier.</summary>
    public required int ProcessId { get; init; }

    /// <summary>Process name without extension.</summary>
    public required string Name { get; init; }

    /// <summary>Full path of the executable, when it could be determined.</summary>
    public string? ExecutablePath { get; init; }

    /// <summary>Full command line, when it could be determined.</summary>
    public string? CommandLine { get; init; }

    /// <summary>Identifier of the parent process, when known.</summary>
    public int? ParentProcessId { get; init; }

    /// <summary>Name of the parent process, when known.</summary>
    public string? ParentName { get; init; }

    /// <summary>Owning account, when it could be determined.</summary>
    public string? UserName { get; init; }

    /// <summary>Process start time, when known.</summary>
    public DateTimeOffset? StartTimeUtc { get; init; }
}

/// <summary>Enumerates running processes.</summary>
public interface IProcessProvider
{
    /// <summary>
    /// Lists running processes. Processes that cannot be inspected, typically
    /// protected or higher-integrity ones, are returned with the fields that
    /// were readable rather than being dropped.
    /// </summary>
    IEnumerable<ProcessRecord> Enumerate(CancellationToken cancellationToken);
}

namespace HoongSystemScope.Core.Abstractions;

/// <summary>Supplies the current time. Exists so scans are deterministic under test.</summary>
public interface ISystemClock
{
    /// <summary>Current UTC time.</summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>The real clock.</summary>
public sealed class SystemClock : ISystemClock
{
    /// <summary>Shared instance.</summary>
    public static SystemClock Instance { get; } = new();

    /// <inheritdoc />
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

using System.Globalization;
using HoongSystemScope.Collectors;

namespace HoongSystemScope.Cli;

/// <summary>
/// Prints scan progress.
/// </summary>
/// <remarks>
/// Everything goes to standard error. Standard output carries the report, and
/// mixing progress into it would break the one thing a command line tool has to
/// get right: <c>hoong-systemscope scan --format json | jq</c> must work.
/// </remarks>
public sealed class ConsoleProgressReporter : IProgress<ScanProgress>
{
    private readonly TextWriter _writer;
    private readonly bool _enabled;

    /// <summary>Creates a reporter writing to the given stream.</summary>
    public ConsoleProgressReporter(TextWriter writer, bool enabled)
    {
        ArgumentNullException.ThrowIfNull(writer);

        _writer = writer;
        _enabled = enabled;
    }

    /// <inheritdoc />
    public void Report(ScanProgress value)
    {
        if (!_enabled || value is null)
        {
            return;
        }

        _writer.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"  [{value.CompletedCollectors}/{value.TotalCollectors}] {value.CollectorId}: {value.EntryCount} entries"));
    }
}

using HoongSystemScope.Core.Abstractions;

namespace HoongSystemScope.Core.Text;

/// <summary>
/// Splits the raw command lines stored in the registry and in the service
/// database into an executable and its arguments.
/// </summary>
/// <remarks>
/// <para>
/// This looks trivial and is not. Autostart values are free-form strings
/// written by installers over three decades: quoted and unquoted paths, paths
/// with spaces and no quotes at all, environment variable references, native
/// object manager prefixes, relative driver paths, and entries whose target no
/// longer exists.
/// </para>
/// <para>
/// For an unquoted path with spaces the parser resolves the same way Windows
/// itself does, shortest prefix first. That is deliberate: when the shortest
/// match is not the intended program, the difference *is* the finding, and
/// <see cref="ParsedCommandLine.HasUnquotedPathWithSpaces"/> carries it to the
/// risk engine.
/// </para>
/// </remarks>
public sealed class CommandLineParser
{
    private readonly IFileSystemProbe _fileSystem;
    private readonly IEnvironmentProbe _environment;

    /// <summary>Creates a parser bound to a file system and an environment.</summary>
    public CommandLineParser(IFileSystemProbe fileSystem, IEnvironmentProbe environment)
    {
        ArgumentNullException.ThrowIfNull(fileSystem);
        ArgumentNullException.ThrowIfNull(environment);

        _fileSystem = fileSystem;
        _environment = environment;
    }

    /// <summary>Splits a raw command line.</summary>
    /// <param name="commandLine">The raw value, or null.</param>
    public ParsedCommandLine Parse(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return ParsedCommandLine.Empty;
        }

        var value = _environment.ExpandEnvironmentVariables(commandLine.Trim());
        value = PathFacts.NormalizeNativePath(value, _environment.WindowsDirectory) ?? value;
        value = value.Trim();

        if (value.Length == 0)
        {
            return ParsedCommandLine.Empty;
        }

        return value[0] is '"' or '\''
            ? ParseQuoted(value)
            : ParseUnquoted(value);
    }

    /// <summary>
    /// Splits a command line using quoting rules alone, without touching the
    /// file system. Used where no probe is available, for example when parsing
    /// a scheduled task action that already carries a separate argument field.
    /// </summary>
    public static ParsedCommandLine ParseSyntaxOnly(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return ParsedCommandLine.Empty;
        }

        var value = commandLine.Trim();

        if (value[0] is '"' or '\'')
        {
            return ParseQuoted(value);
        }

        var firstSpace = value.IndexOf(' ', StringComparison.Ordinal);
        return firstSpace < 0
            ? new ParsedCommandLine { ExecutablePath = value }
            : new ParsedCommandLine
            {
                ExecutablePath = value[..firstSpace],
                Arguments = NullIfBlank(value[(firstSpace + 1)..]),
                HasUnquotedPathWithSpaces = false,
            };
    }

    /// <summary>
    /// Extracts the DLL a <c>rundll32</c> invocation targets.
    /// </summary>
    /// <remarks>
    /// <c>rundll32.exe</c> is signed by Microsoft and lives in System32, so
    /// judging the entry by its executable alone would rate every rundll32
    /// autostart as harmless. What matters is the DLL it loads.
    /// </remarks>
    /// <param name="executablePath">The resolved executable.</param>
    /// <param name="arguments">The resolved arguments.</param>
    /// <param name="dllPath">The targeted DLL, when one was found.</param>
    /// <param name="entryPoint">The exported entry point, when one was given.</param>
    /// <returns>True when <paramref name="executablePath"/> is rundll32 and a DLL was extracted.</returns>
    public static bool TryGetRundll32Target(
        string? executablePath,
        string? arguments,
        out string? dllPath,
        out string? entryPoint)
    {
        dllPath = null;
        entryPoint = null;

        if (string.IsNullOrWhiteSpace(executablePath) || string.IsNullOrWhiteSpace(arguments))
        {
            return false;
        }

        if (!PathFacts.GetFileName(executablePath).Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var target = arguments.Trim();
        if (target.Length == 0)
        {
            return false;
        }

        if (target[0] is '"')
        {
            var closing = target.IndexOf('"', 1);
            if (closing < 0)
            {
                return false;
            }

            dllPath = target[1..closing];
            var rest = target[(closing + 1)..].TrimStart(',', ' ');
            entryPoint = NullIfBlank(rest);
            return true;
        }

        // rundll32 takes "path.dll,EntryPoint arguments". The comma binds tighter
        // than the space, so split on it first.
        var comma = target.IndexOf(',', StringComparison.Ordinal);
        if (comma >= 0)
        {
            dllPath = target[..comma].Trim();
            entryPoint = NullIfBlank(target[(comma + 1)..].Trim());
            return dllPath.Length > 0;
        }

        var space = target.IndexOf(' ', StringComparison.Ordinal);
        dllPath = space < 0 ? target : target[..space];
        return dllPath.Length > 0;
    }

    private static ParsedCommandLine ParseQuoted(string value)
    {
        var quote = value[0];
        var closing = value.IndexOf(quote, 1);

        if (closing < 0)
        {
            // Unterminated quote: treat everything after it as the executable.
            return new ParsedCommandLine
            {
                ExecutablePath = NullIfBlank(value[1..]),
                WasQuoted = true,
            };
        }

        return new ParsedCommandLine
        {
            ExecutablePath = NullIfBlank(value[1..closing]),
            Arguments = NullIfBlank(value[(closing + 1)..]),
            WasQuoted = true,
        };
    }

    private ParsedCommandLine ParseUnquoted(string value)
    {
        var firstSpace = value.IndexOf(' ', StringComparison.Ordinal);
        if (firstSpace < 0)
        {
            return new ParsedCommandLine { ExecutablePath = value };
        }

        // The prefix ending at the first executable extension is what the
        // author of the entry meant to run. It is not necessarily what Windows
        // launches, and the gap between the two is the whole point of the
        // unquoted-path finding below.
        var intendedEnd = FindSplitByExtension(value);
        var intendedPath = intendedEnd > 0 ? value[..intendedEnd] : null;

        // Walk the space-delimited prefixes shortest first, exactly like the
        // Windows loader does, and stop at the first one that is a real file.
        var searchStart = 0;
        while (true)
        {
            var space = value.IndexOf(' ', searchStart);
            if (space < 0)
            {
                break;
            }

            var candidate = value[..space];
            if (TryAcceptCandidate(candidate, out var resolved))
            {
                return new ParsedCommandLine
                {
                    ExecutablePath = resolved,
                    Arguments = NullIfBlank(value[(space + 1)..]),
                    HasUnquotedPathWithSpaces = ContainsSpace(intendedPath ?? resolved),
                };
            }

            searchStart = space + 1;
        }

        // The whole string may itself be the executable.
        if (TryAcceptCandidate(value, out var whole))
        {
            return new ParsedCommandLine
            {
                ExecutablePath = whole,
                HasUnquotedPathWithSpaces = ContainsSpace(whole),
            };
        }

        // Nothing exists on disk. Fall back to the extension boundary, so a
        // broken autostart entry still reports a meaningful target instead of a
        // truncated one.
        if (intendedPath is not null)
        {
            return new ParsedCommandLine
            {
                ExecutablePath = intendedPath,
                Arguments = NullIfBlank(value[intendedEnd..]),
                HasUnquotedPathWithSpaces = ContainsSpace(intendedPath),
            };
        }

        return new ParsedCommandLine
        {
            ExecutablePath = value[..firstSpace],
            Arguments = NullIfBlank(value[(firstSpace + 1)..]),
        };
    }

    private static bool ContainsSpace(string? value) =>
        value is not null && value.Contains(' ', StringComparison.Ordinal);

    private bool TryAcceptCandidate(string candidate, out string? resolved)
    {
        resolved = null;

        if (candidate.Length == 0)
        {
            return false;
        }

        if (_fileSystem.FileExists(candidate))
        {
            resolved = candidate;
            return true;
        }

        // "C:\Tools\foo" with the extension omitted is a legal command line.
        if (PathFacts.GetExtension(candidate).Length == 0 && _fileSystem.FileExists(candidate + ".exe"))
        {
            resolved = candidate + ".exe";
            return true;
        }

        return false;
    }

    /// <summary>
    /// Finds the end of the first token that carries an executable extension.
    /// The <em>first</em> match wins so that an argument such as
    /// <c>--log=trace.exe</c> cannot pull the split past the real program.
    /// </summary>
    private static int FindSplitByExtension(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '.')
            {
                continue;
            }

            var end = value.IndexOf(' ', index);
            if (end < 0)
            {
                end = value.Length;
            }

            if (PathFacts.HasExecutableExtension("x" + value[index..end]))
            {
                return end;
            }
        }

        return -1;
    }

    private static string? NullIfBlank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

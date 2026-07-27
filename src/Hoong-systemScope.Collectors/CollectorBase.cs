using HoongSystemScope.Core.Abstractions;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Core.Security;
using HoongSystemScope.Core.Text;

namespace HoongSystemScope.Collectors;

/// <summary>
/// Shared plumbing for collectors: entry construction, registry traversal that
/// survives missing privileges, and the sensitive-location guard.
/// </summary>
public abstract class CollectorBase : IScanCollector
{
    /// <inheritdoc />
    public abstract string Id { get; }

    /// <inheritdoc />
    public abstract string Description { get; }

    /// <inheritdoc />
    public abstract ScanCategory Category { get; }

    /// <inheritdoc />
    public virtual bool RequiresElevation => false;

    /// <inheritdoc />
    public abstract IAsyncEnumerable<ScanEntry> CollectAsync(ScanContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Builds an entry, deriving the identity and applying command line
    /// redaction and parsing in one place so every collector behaves the same.
    /// </summary>
    protected static ScanEntry CreateEntry(
        ScanContext context,
        ScanCategory category,
        string name,
        string location,
        string? commandLine = null,
        string? explicitExecutablePath = null,
        string? explicitArguments = null,
        string? userName = null,
        bool? isEnabled = null,
        IReadOnlyDictionary<string, string?>? metadata = null)
    {
        string? executablePath = explicitExecutablePath;
        string? arguments = explicitArguments;
        var extras = metadata is null
            ? new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string?>(metadata, StringComparer.OrdinalIgnoreCase);

        if (executablePath is null && commandLine is not null)
        {
            var parsed = context.CommandLines.Parse(commandLine);
            executablePath = parsed.ExecutablePath;
            arguments = parsed.Arguments;

            if (parsed.HasUnquotedPathWithSpaces)
            {
                extras[MetadataKeys.UnquotedPath] = "true";
            }
        }
        else if (executablePath is not null)
        {
            executablePath = context.Environment.ExpandEnvironmentVariables(executablePath);
            executablePath = PathFacts.NormalizeNativePath(executablePath, context.Environment.WindowsDirectory)
                             ?? executablePath;
        }

        // rundll32 is Microsoft-signed and lives in System32, so judging the
        // entry by its executable alone would clear every rundll32 autostart.
        // Record the library it loads; the risk engine scores that instead.
        if (CommandLineParser.TryGetRundll32Target(executablePath, arguments, out var dll, out var entryPoint))
        {
            extras[MetadataKeys.Rundll32Target] = dll;

            if (entryPoint is not null)
            {
                extras[MetadataKeys.Rundll32EntryPoint] = entryPoint;
            }
        }

        return new ScanEntry
        {
            Id = EntryIdentity.Compute(category, location, name),
            Category = category,
            Name = name,
            Location = location,
            CommandLine = CommandLineRedactor.Redact(commandLine),
            ExecutablePath = executablePath,
            Arguments = CommandLineRedactor.Redact(arguments),
            UserName = userName,
            IsEnabled = isEnabled,
            FileExists = executablePath is null ? null : context.FileSystem.FileExists(executablePath),
            SignatureStatus = SignatureStatus.NotChecked,
            Metadata = extras,
            CollectedAtUtc = context.Clock.UtcNow,
        };
    }

    /// <summary>
    /// Opens a registry key, turning an access failure into a diagnostic rather
    /// than an exception, and refusing anything on the sensitive-location deny
    /// list.
    /// </summary>
    protected IRegistryKey? TryOpenKey(
        ScanContext context,
        RegistryHiveKind hive,
        string path,
        RegistryViewKind view = RegistryViewKind.Default)
    {
        if (SensitiveLocations.IsDeniedRegistryPath(path))
        {
            return null;
        }

        try
        {
            return context.Registry.OpenKey(hive, path, view);
        }
        catch (UnauthorizedAccessException ex)
        {
            ReportAccessDenied(context, $"{hive}\\{path}", ex);
            return null;
        }
        catch (System.Security.SecurityException ex)
        {
            ReportAccessDenied(context, $"{hive}\\{path}", ex);
            return null;
        }
        catch (IOException ex)
        {
            context.Diagnostics.Report(new ScanError
            {
                CollectorId = Id,
                Severity = ScanErrorSeverity.Warning,
                Message = $"Could not read '{hive}\\{path}': {ex.Message}",
                Location = $"{hive}\\{path}",
                ExceptionType = ex.GetType().Name,
            });
            return null;
        }
    }

    /// <summary>Opens a subkey, converting access failures into diagnostics.</summary>
    protected IRegistryKey? TryOpenSubKey(ScanContext context, IRegistryKey parent, string name)
    {
        try
        {
            return parent.OpenSubKey(name);
        }
        catch (UnauthorizedAccessException ex)
        {
            ReportAccessDenied(context, $"{parent.Path}\\{name}", ex);
            return null;
        }
        catch (System.Security.SecurityException ex)
        {
            ReportAccessDenied(context, $"{parent.Path}\\{name}", ex);
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    /// <summary>Reads subkey names, returning an empty list when the key is unreadable.</summary>
    protected IReadOnlyList<string> TryGetSubKeyNames(ScanContext context, IRegistryKey key)
    {
        try
        {
            return key.GetSubKeyNames();
        }
        catch (UnauthorizedAccessException ex)
        {
            ReportAccessDenied(context, key.Path, ex);
            return [];
        }
        catch (System.Security.SecurityException ex)
        {
            ReportAccessDenied(context, key.Path, ex);
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    /// <summary>
    /// The registry views a scan should visit. On a 64 bit machine a 32 bit
    /// installer writes into WOW6432Node, so reading only one view hides a
    /// large share of a typical machine's autostart entries.
    /// </summary>
    protected static IReadOnlyList<RegistryViewKind> GetViews(ScanContext context) =>
        context.Registry.SupportsWow64Views
            ? [RegistryViewKind.Registry64, RegistryViewKind.Registry32]
            : [RegistryViewKind.Default];

    /// <summary>Records that a location existed but could not be read.</summary>
    protected void ReportAccessDenied(ScanContext context, string location, Exception exception) =>
        context.Diagnostics.Report(new ScanError
        {
            CollectorId = Id,
            Severity = ScanErrorSeverity.Warning,
            Message = context.Environment.GetMachineInfo().IsElevated
                ? $"Access to '{location}' was denied even though the scan is elevated."
                : $"Access to '{location}' was denied. Run elevated to include it.",
            Location = location,
            ExceptionType = exception.GetType().Name,
        });
}

using System.CommandLine;
using System.Globalization;
using System.Runtime.Versioning;
using HoongSystemScope.Analysis;
using HoongSystemScope.App;
using HoongSystemScope.Cli;
using HoongSystemScope.Core.Models;
using HoongSystemScope.Export;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var root = CommandFactory.CreateRootCommand();

return await root.Parse(args).InvokeAsync(new InvocationConfiguration
{
    // Errors belong on standard error so a piped report stays clean.
    Output = Console.Out,
    Error = Console.Error,
}).ConfigureAwait(false);

namespace HoongSystemScope.Cli
{
    /// <summary>Builds the command line surface.</summary>
    [SupportedOSPlatform("windows")]
    internal static class CommandFactory
    {
        internal static RootCommand CreateRootCommand()
        {
            var root = new RootCommand(
                "Hoong-systemScope - a read-only Windows diagnostic tool for autostart entries, " +
                "services, drivers, scheduled tasks and processes.");

            root.Add(CreateScanCommand());
            root.Add(CreateCompareCommand());
            root.Add(CreateReportCommand());
            root.Add(CreateListCollectorsCommand());

            return root;
        }

        private static Command CreateScanCommand()
        {
            var categories = new Option<ScanCategory[]>("--categories", "-c")
            {
                Description = "Limit the scan to these categories. Omit to scan everything.",
                AllowMultipleArgumentsPerToken = true,
            };

            var allUsers = new Option<bool>("--all-users")
            {
                Description =
                    "Also inspect other users' hives. Only profiles whose hive is already loaded are read; " +
                    "Hoong-systemScope never mounts one, because that would modify the system.",
            };

            var noHash = new Option<bool>("--no-hash")
            {
                Description = "Skip SHA-256 computation. Much faster, but files cannot be compared across machines.",
            };

            var noSignature = new Option<bool>("--no-signature")
            {
                Description = "Skip Authenticode verification. Much faster, but signature findings disappear.",
            };

            var minimumRisk = new Option<RiskLevel>("--min-risk")
            {
                Description = "Drop entries below this risk level from the report.",
                DefaultValueFactory = _ => RiskLevel.Informational,
            };

            var format = new Option<ReportFormat>("--format", "-f")
            {
                Description = "Output format.",
                DefaultValueFactory = _ => ReportFormat.Text,
            };

            var output = new Option<FileInfo?>("--output", "-o")
            {
                Description = "Write the report to this file instead of standard output.",
            };

            var baseline = new Option<FileInfo?>("--baseline", "-b")
            {
                Description = "Compare the scan against this earlier scan and report the differences instead.",
            };

            var quiet = new Option<bool>("--quiet", "-q")
            {
                Description = "Suppress progress output.",
            };

            var verbosity = new Option<LogLevel>("--verbosity", "-v")
            {
                Description = "Log level for diagnostics on standard error.",
                DefaultValueFactory = _ => LogLevel.Warning,
            };

            var command = new Command("scan", "Inspect this machine and produce a report.")
            {
                categories, allUsers, noHash, noSignature, minimumRisk,
                format, output, baseline, quiet, verbosity,
            };

            command.SetAction(async (parseResult, cancellationToken) =>
            {
                var options = new ScanOptions
                {
                    Categories = new HashSet<ScanCategory>(parseResult.GetValue(categories) ?? []),
                    IncludeAllUsers = parseResult.GetValue(allUsers),
                    ComputeHashes = !parseResult.GetValue(noHash),
                    VerifySignatures = !parseResult.GetValue(noSignature),
                    MinimumRiskLevel = parseResult.GetValue(minimumRisk),
                };

                return await RunScanAsync(
                    options,
                    parseResult.GetValue(format),
                    parseResult.GetValue(output),
                    parseResult.GetValue(baseline),
                    parseResult.GetValue(quiet),
                    parseResult.GetValue(verbosity),
                    cancellationToken).ConfigureAwait(false);
            });

            return command;
        }

        private static Command CreateCompareCommand()
        {
            var left = new Option<FileInfo>("--left", "-l")
            {
                Description = "The earlier scan.",
                Required = true,
            };

            var right = new Option<FileInfo>("--right", "-r")
            {
                Description = "The later scan.",
                Required = true,
            };

            var format = new Option<ReportFormat>("--format", "-f")
            {
                Description = "Output format.",
                DefaultValueFactory = _ => ReportFormat.Text,
            };

            var output = new Option<FileInfo?>("--output", "-o")
            {
                Description = "Write the comparison to this file instead of standard output.",
            };

            var command = new Command("compare", "Compare two saved scans.")
            {
                left, right, format, output,
            };

            command.SetAction(async (parseResult, cancellationToken) =>
            {
                try
                {
                    var baseline = await BaselineStore
                        .LoadAsync(parseResult.GetRequiredValue(left).FullName, cancellationToken)
                        .ConfigureAwait(false);

                    var current = await BaselineStore
                        .LoadAsync(parseResult.GetRequiredValue(right).FullName, cancellationToken)
                        .ConfigureAwait(false);

                    var diff = new BaselineComparer().Compare(baseline, current);

                    using var provider = CreateProvider(LogLevel.Warning);
                    var rendered = new ScanRunner(provider).Render(diff, parseResult.GetValue(format));

                    await EmitAsync(rendered, parseResult.GetValue(output), cancellationToken).ConfigureAwait(false);

                    return diff.IsEmpty ? ExitCodes.Success : ExitCodes.FindingsAboveThreshold;
                }
                catch (Exception ex) when (ex is FileNotFoundException or InvalidDataException)
                {
                    await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
                    return ExitCodes.UsageError;
                }
            });

            return command;
        }

        private static Command CreateReportCommand()
        {
            var input = new Option<FileInfo>("--input", "-i")
            {
                Description = "A scan previously saved as JSON.",
                Required = true,
            };

            var format = new Option<ReportFormat>("--format", "-f")
            {
                Description = "Output format.",
                DefaultValueFactory = _ => ReportFormat.Text,
            };

            var output = new Option<FileInfo?>("--output", "-o")
            {
                Description = "Write the report to this file instead of standard output.",
            };

            var command = new Command("report", "Re-render a saved scan in another format.")
            {
                input, format, output,
            };

            command.SetAction(async (parseResult, cancellationToken) =>
            {
                try
                {
                    var result = await BaselineStore
                        .LoadAsync(parseResult.GetRequiredValue(input).FullName, cancellationToken)
                        .ConfigureAwait(false);

                    using var provider = CreateProvider(LogLevel.Warning);
                    var rendered = new ScanRunner(provider).Render(result, parseResult.GetValue(format));
                    await EmitAsync(rendered, parseResult.GetValue(output), cancellationToken).ConfigureAwait(false);

                    return ExitCodes.Success;
                }
                catch (Exception ex) when (ex is FileNotFoundException or InvalidDataException)
                {
                    await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
                    return ExitCodes.UsageError;
                }
            });

            return command;
        }

        private static Command CreateListCollectorsCommand()
        {
            var command = new Command("list-collectors", "List the available scanner modules.");

            command.SetAction(parseResult =>
            {
                using var provider = CreateProvider(LogLevel.Warning);
                var orchestrator = provider.GetRequiredService<Collectors.ScanOrchestrator>();

                foreach (var collector in orchestrator.Collectors)
                {
                    var elevation = collector.RequiresElevation ? "  (needs elevation for full coverage)" : string.Empty;

                    Console.WriteLine(string.Create(
                        CultureInfo.InvariantCulture,
                        $"{collector.Id,-24} {collector.Category,-28} {collector.Description}{elevation}"));
                }

                return ExitCodes.Success;
            });

            return command;
        }

        private static async Task<int> RunScanAsync(
            ScanOptions options,
            ReportFormat format,
            FileInfo? output,
            FileInfo? baselinePath,
            bool quiet,
            LogLevel verbosity,
            CancellationToken cancellationToken)
        {
            using var provider = CreateProvider(verbosity);
            var runner = new ScanRunner(provider);

            // Progress goes to standard error so that piping the report works.
            var progress = new ConsoleProgressReporter(Console.Error, enabled: !quiet);

            try
            {
                var result = await runner.ScanAsync(options, progress, cancellationToken).ConfigureAwait(false);

                string rendered;
                var hasChanges = false;

                if (baselinePath is not null)
                {
                    var baseline = await BaselineStore
                        .LoadAsync(baselinePath.FullName, cancellationToken)
                        .ConfigureAwait(false);

                    var diff = new BaselineComparer().Compare(baseline, result);
                    rendered = runner.Render(diff, format);
                    hasChanges = !diff.IsEmpty;
                }
                else
                {
                    rendered = runner.Render(result, format);
                }

                await EmitAsync(rendered, output, cancellationToken).ConfigureAwait(false);

                if (result.IsPartial)
                {
                    return ExitCodes.PartialResults;
                }

                if (baselinePath is not null)
                {
                    return hasChanges ? ExitCodes.FindingsAboveThreshold : ExitCodes.Success;
                }

                // Anything the risk engine did not rate as merely informational
                // is what a script would want to act on.
                return result.Entries.Any(e => e.RiskLevel > RiskLevel.Informational)
                    ? ExitCodes.FindingsAboveThreshold
                    : ExitCodes.Success;
            }
            catch (OperationCanceledException)
            {
                await Console.Error.WriteLineAsync("Scan cancelled.").ConfigureAwait(false);
                return ExitCodes.Cancelled;
            }
            catch (Exception ex) when (ex is FileNotFoundException or InvalidDataException)
            {
                await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
                return ExitCodes.UsageError;
            }
#pragma warning disable CA1031 // The entry point reports failures as an exit code rather than a crash dump.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                await Console.Error.WriteLineAsync($"The scan failed: {ex.Message}").ConfigureAwait(false);
                return ExitCodes.FatalError;
            }
        }

        private static async Task EmitAsync(string content, FileInfo? output, CancellationToken cancellationToken)
        {
            if (output is null)
            {
                await Console.Out.WriteAsync(content.AsMemory(), cancellationToken).ConfigureAwait(false);
                return;
            }

            output.Directory?.Create();
            await File.WriteAllTextAsync(output.FullName, content, cancellationToken).ConfigureAwait(false);

            await Console.Error
                .WriteLineAsync($"Report written to {output.FullName}")
                .ConfigureAwait(false);
        }

        private static ServiceProvider CreateProvider(LogLevel verbosity) =>
            new ServiceCollection().AddHoongSystemScope(verbosity).BuildServiceProvider();
    }
}

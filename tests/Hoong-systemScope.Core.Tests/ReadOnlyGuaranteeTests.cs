using System.Text;
using System.Text.RegularExpressions;

namespace HoongSystemScope.Core.Tests;

/// <summary>
/// Turns the project's central promises into a build failure rather than a
/// paragraph in a readme.
/// </summary>
/// <remarks>
/// <para>
/// Hoong-systemScope claims three things: it never modifies the machine it
/// inspects, it never launches anything it finds, and it works entirely
/// offline. Those are exactly the properties that quietly erode as a codebase
/// grows — one convenience call to <c>Process.Start</c> to read a version, one
/// telemetry ping, and the guarantee is gone while the readme still asserts it.
/// </para>
/// <para>
/// This suite scans the source of every project and fails the build if a
/// forbidden API appears. It is a lexical check, not a semantic one: reflection
/// or a P/Invoke declared under another name would slip past. That is an
/// accepted limit. Its job is to make a regression loud and deliberate rather
/// than accidental.
/// </para>
/// </remarks>
public sealed class ReadOnlyGuaranteeTests
{
    /// <summary>
    /// APIs that would let the tool execute something it discovered. Banned
    /// everywhere, without exception.
    /// </summary>
    private static readonly string[] ExecutionApis =
    [
        "Process.Start",
        "ProcessStartInfo",
        "ShellExecute",
        "CreateProcess",
        "WinExec",
        "System.Diagnostics.Process.Start",
    ];

    /// <summary>
    /// Networking APIs. Banned everywhere: the tool has no online feature, so
    /// any outbound call is either telemetry or an exfiltration path.
    /// </summary>
    private static readonly string[] NetworkApis =
    [
        "HttpClient",
        "WebClient",
        "HttpWebRequest",
        "WebRequest",
        "HttpListener",
        "System.Net.Sockets",
        "TcpClient",
        "UdpClient",
        "new Socket",
        "Dns.GetHost",
    ];

    /// <summary>
    /// APIs that change the inspected system. Banned in the projects that touch
    /// the machine; the report writers legitimately create files and are
    /// exempted from this set only.
    /// </summary>
    private static readonly string[] MutationApis =
    [
        "File.Delete",
        "File.WriteAll",
        "File.AppendAll",
        "File.Create",
        "File.Move",
        "File.Copy",
        "File.Replace",
        "File.SetAttributes",
        "Directory.Delete",
        "Directory.CreateDirectory",
        "Directory.Move",
        "FileMode.Create",
        "FileMode.Append",
        "FileMode.Truncate",
        "FileAccess.Write",
        "FileAccess.ReadWrite",
        "new StreamWriter",
        "SetValue(",
        "DeleteValue",
        "DeleteSubKey",
        "CreateSubKey",
        "RegSetValue",
        "RegCreateKey",
        "RegDeleteKey",
        "RegDeleteValue",
        ".Kill(",
        "ServiceController",
        "RegistryKeyPermissionCheck.ReadWriteSubTree",
        "RegistryRights.WriteKey",
        "RegistryRights.SetValue",
    ];

    public static TheoryData<string> AllProjects =>
    [
        "Hoong-systemScope.Core",
        "Hoong-systemScope.Collectors",
        "Hoong-systemScope.Analysis",
        "Hoong-systemScope.Export",
        "Hoong-systemScope.Windows",
        "Hoong-systemScope.ViewModels",
        "Hoong-systemScope.App",
        "Hoong-systemScope.Wpf",
        "Hoong-systemScope.Cli",
    ];

    /// <summary>
    /// Projects that inspect the machine. These may not write anything, not
    /// even a temporary file.
    /// </summary>
    public static TheoryData<string> InspectionProjects =>
    [
        "Hoong-systemScope.Core",
        "Hoong-systemScope.Collectors",
        "Hoong-systemScope.Analysis",
        "Hoong-systemScope.Windows",
        "Hoong-systemScope.App",
    ];

    [Theory]
    [MemberData(nameof(AllProjects))]
    public void No_project_can_execute_a_discovered_program(string project) =>
        AssertNoForbiddenApi(project, ExecutionApis, "may not launch anything it discovers");

    [Theory]
    [MemberData(nameof(AllProjects))]
    public void No_project_can_reach_the_network(string project) =>
        AssertNoForbiddenApi(project, NetworkApis, "must work entirely offline");

    [Theory]
    [MemberData(nameof(InspectionProjects))]
    public void The_inspecting_projects_cannot_modify_the_system(string project) =>
        AssertNoForbiddenApi(project, MutationApis, "must leave the inspected system unchanged");

    [Fact]
    public void The_registry_abstraction_exposes_no_write_operation()
    {
        // Read-only registry access is a property of the type system here, not
        // a runtime flag someone could flip.
        var source = ReadSourceFile("Hoong-systemScope.Core", "Abstractions/IRegistryReader.cs");

        foreach (var forbidden in new[] { "SetValue", "DeleteValue", "DeleteSubKey", "CreateSubKey", "WriteValue" })
        {
            Assert.DoesNotContain(forbidden, StripComments(source), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_source_tree_was_actually_found()
    {
        // Guards against the scan silently passing because it looked at an
        // empty directory.
        var files = EnumerateSourceFiles("Hoong-systemScope.Core").ToList();

        Assert.NotEmpty(files);
        Assert.Contains(files, f => f.EndsWith("ScanEntry.cs", StringComparison.Ordinal));
    }

    private static void AssertNoForbiddenApi(string project, IReadOnlyList<string> forbiddenApis, string rationale)
    {
        var violations = new List<string>();

        foreach (var file in EnumerateSourceFiles(project))
        {
            var lines = StripComments(File.ReadAllText(file)).Split('\n');

            for (var index = 0; index < lines.Length; index++)
            {
                foreach (var api in forbiddenApis)
                {
                    if (lines[index].Contains(api, StringComparison.Ordinal))
                    {
                        violations.Add($"{Path.GetFileName(file)}:{index + 1} uses '{api}'");
                    }
                }
            }
        }

        if (violations.Count > 0)
        {
            var message = new StringBuilder()
                .Append(project)
                .Append(' ')
                .Append(rationale)
                .AppendLine(", but the following calls were found:")
                .AppendJoin(Environment.NewLine, violations)
                .ToString();

            Assert.Fail(message);
        }
    }

    private static IEnumerable<string> EnumerateSourceFiles(string project)
    {
        var directory = Path.Combine(FindRepositoryRoot(), "src", project);

        if (!Directory.Exists(directory))
        {
            return [];
        }

        return Directory
            .EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
    }

    private static string ReadSourceFile(string project, string relativePath) =>
        File.ReadAllText(Path.Combine(FindRepositoryRoot(), "src", project, relativePath.Replace('/', Path.DirectorySeparatorChar)));

    /// <summary>
    /// Removes comments so that documenting a forbidden call — as this very
    /// file does — does not trip the scan.
    /// </summary>
    private static string StripComments(string source)
    {
        var withoutBlocks = Regex.Replace(source, @"/\*.*?\*/", string.Empty, RegexOptions.Singleline, TimeSpan.FromSeconds(5));
        var builder = new StringBuilder(withoutBlocks.Length);

        foreach (var line in withoutBlocks.Split('\n'))
        {
            var trimmed = line.TrimStart();

            if (trimmed.StartsWith("//", StringComparison.Ordinal) ||
                trimmed.StartsWith("///", StringComparison.Ordinal) ||
                trimmed.StartsWith('*'))
            {
                builder.Append('\n');
                continue;
            }

            var comment = line.IndexOf("//", StringComparison.Ordinal);
            builder.Append(comment >= 0 ? line[..comment] : line).Append('\n');
        }

        return builder.ToString();
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Hoong-systemScope.sln")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            $"Could not locate the repository root above '{AppContext.BaseDirectory}'.");
    }
}

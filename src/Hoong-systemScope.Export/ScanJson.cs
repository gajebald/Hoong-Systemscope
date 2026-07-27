using System.Text.Json;
using System.Text.Json.Serialization;
using HoongSystemScope.Core.Models;

namespace HoongSystemScope.Export;

/// <summary>
/// The JSON contract of Hoong-systemScope.
/// </summary>
/// <remarks>
/// JSON is the only format that round-trips: it is both the machine readable
/// report and the baseline file. The options are chosen for diffability —
/// indented, enums as names rather than numbers, nulls kept so a field that
/// disappeared is visible as a change rather than as an absence.
/// </remarks>
public static class ScanJson
{
    /// <summary>Serializer options shared by every reader and writer.</summary>
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,

            // Numeric enum values would make a report unreadable and would
            // silently change meaning if a value were ever inserted into the
            // middle of an enum.
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        };

        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    /// <summary>Serializes a scan result.</summary>
    public static string Serialize(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(result, Options);
    }

    /// <summary>Serializes a baseline comparison.</summary>
    public static string Serialize(BaselineDiff diff)
    {
        ArgumentNullException.ThrowIfNull(diff);
        return JsonSerializer.Serialize(diff, Options);
    }

    /// <summary>
    /// Reads a scan result, rejecting a schema version this build does not
    /// understand rather than silently mis-reading it.
    /// </summary>
    /// <exception cref="InvalidDataException">The content is not a readable scan result.</exception>
    public static ScanResult Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);

        ScanResult? result;

        try
        {
            result = JsonSerializer.Deserialize<ScanResult>(json, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The file is not a valid Hoong-systemScope scan: {ex.Message}", ex);
        }

        if (result is null)
        {
            throw new InvalidDataException("The file does not contain a scan result.");
        }

        if (result.SchemaVersion > ScanResult.CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"The scan uses schema version {result.SchemaVersion}, but this build understands at most " +
                $"{ScanResult.CurrentSchemaVersion}. Use a newer Hoong-systemScope to read it.");
        }

        return result;
    }
}

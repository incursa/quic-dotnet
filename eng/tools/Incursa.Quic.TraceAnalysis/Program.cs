// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;

namespace Incursa.Quic.TraceAnalysis;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 2;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static int Main(string[] args)
    {
        try
        {
            var options = ParseOptions(args);
            if (options.ShowHelp)
            {
                WriteUsage(Console.Out);
                return 0;
            }

            if (string.IsNullOrWhiteSpace(options.TracePath))
            {
                Console.Error.WriteLine("Missing required --trace <path> argument.");
                WriteUsage(Console.Error);
                return InvalidArgumentsExitCode;
            }

            var tracePath = Path.GetFullPath(options.TracePath);
            if (!File.Exists(tracePath))
            {
                Console.Error.WriteLine("Trace file was not found: {0}", tracePath);
                return InvalidArgumentsExitCode;
            }

            var outputRoot = Path.GetFullPath(
                string.IsNullOrWhiteSpace(options.OutputRoot)
                    ? Path.Combine(Path.GetDirectoryName(tracePath) ?? Environment.CurrentDirectory, "exception-attribution")
                    : options.OutputRoot);

            Directory.CreateDirectory(outputRoot);

            var summary = AnalyzeTrace(tracePath, outputRoot, options);
            var jsonPath = Path.Combine(outputRoot, "exception-attribution.json");
            var markdownPath = Path.Combine(outputRoot, "exception-attribution.md");
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(summary, SerializerOptions));
            File.WriteAllText(markdownPath, RenderMarkdown(summary));

            Console.WriteLine(jsonPath);
            Console.WriteLine(markdownPath);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static ExceptionTraceSummary AnalyzeTrace(string tracePath, string outputRoot, CommandOptions commandOptions)
    {
        using var conversionLog = new StringWriter(CultureInfo.InvariantCulture);
        var traceLogOptions = new TraceLogOptions
        {
            ConversionLog = conversionLog,
            ContinueOnError = true,
            KeepAllEvents = true,
        };

        var traceLogPath = ResolveTraceLogPath(tracePath, outputRoot, traceLogOptions);
        using var traceLog = new TraceLog(traceLogPath);
        var groups = new Dictionary<ExceptionGroupKey, ExceptionTraceGroup>();
        var totalExceptions = 0;

        foreach (var exception in traceLog.Events.ByEventType<ExceptionTraceData>())
        {
            totalExceptions++;
            var frames = GetStackFrames(traceLog, exception, commandOptions.MaxFrames);
            var stackTopFrame = frames.Count > 0 ? frames[0] : "<no-managed-stack>";
            var firstProjectFrame = FindFirstProjectFrame(frames, commandOptions.ProjectFramePrefixes);
            var attributionFrame = firstProjectFrame ?? FindFirstNonRuntimeFrame(frames) ?? stackTopFrame;
            var key = new ExceptionGroupKey(
                Normalize(exception.ExceptionType, "<unknown-exception-type>"),
                Normalize(exception.ExceptionMessage, string.Empty),
                attributionFrame);

            if (!groups.TryGetValue(key, out var group))
            {
                group = new ExceptionTraceGroup
                {
                    ExceptionType = key.ExceptionType,
                    ExceptionMessage = key.ExceptionMessage,
                    StackTopFrame = stackTopFrame,
                    AttributionFrame = key.AttributionFrame,
                    FirstProjectFrame = firstProjectFrame,
                    SampleFrames = frames,
                    SampleEvents = [],
                };
                groups.Add(key, group);
            }

            group.Count++;
            if (string.IsNullOrWhiteSpace(group.FirstProjectFrame) && !string.IsNullOrWhiteSpace(firstProjectFrame))
            {
                group.FirstProjectFrame = firstProjectFrame;
            }

            if (group.SampleEvents.Count < commandOptions.SampleEventsPerGroup)
            {
                group.SampleEvents.Add(new ExceptionTraceEventSample
                {
                    ProcessId = exception.ProcessID,
                    ProcessName = exception.ProcessName,
                    ThreadId = exception.ThreadID,
                    RelativeMilliseconds = exception.TimeStampRelativeMSec,
                    TimeStampUtc = exception.TimeStamp.ToUniversalTime(),
                });
            }
        }

        var orderedGroups = groups.Values
            .OrderByDescending(group => group.Count)
            .ThenBy(group => group.ExceptionType, StringComparer.Ordinal)
            .ThenBy(group => group.ExceptionMessage, StringComparer.Ordinal)
            .ThenBy(group => group.AttributionFrame, StringComparer.Ordinal)
            .Take(commandOptions.Top)
            .ToArray();

        return new ExceptionTraceSummary
        {
            SchemaVersion = "incursa.quic.exception-attribution.v1",
            GeneratedAtUtc = DateTimeOffset.UtcNow,
            TracePath = tracePath,
            TraceSha256 = ComputeSha256(tracePath),
            OutputRoot = outputRoot,
            EventCount = traceLog.EventCount,
            EventsLost = traceLog.EventsLost,
            HasCallStacks = traceLog.HasCallStacks,
            TotalExceptions = totalExceptions,
            TotalGroups = groups.Count,
            IncludedGroups = orderedGroups.Length,
            ProjectFramePrefixes = commandOptions.ProjectFramePrefixes,
            ConversionLog = conversionLog.ToString(),
            Groups = orderedGroups,
        };
    }

    private static string ResolveTraceLogPath(string tracePath, string outputRoot, TraceLogOptions traceLogOptions)
    {
        if (string.Equals(Path.GetExtension(tracePath), ".etlx", StringComparison.OrdinalIgnoreCase))
        {
            return tracePath;
        }

        var traceLogPath = Path.Combine(outputRoot, Path.GetFileNameWithoutExtension(tracePath) + ".etlx");
        var extension = Path.GetExtension(tracePath);
        if (string.Equals(extension, ".nettrace", StringComparison.OrdinalIgnoreCase))
        {
            return TraceLog.CreateFromEventPipeDataFile(tracePath, traceLogPath, traceLogOptions);
        }

        return TraceLog.CreateFromEventTraceLogFile(tracePath, traceLogPath, traceLogOptions, new TraceEventDispatcherOptions());
    }

    private static List<string> GetStackFrames(TraceLog traceLog, TraceEvent traceEvent, int maxFrames)
    {
        var frames = new List<string>();
        var callStack = traceLog.GetCallStackForEvent(traceEvent);
        while (callStack is not null && frames.Count < maxFrames)
        {
            var frameName = Normalize(callStack.CodeAddress?.FullMethodName, string.Empty);
            if (!string.IsNullOrWhiteSpace(frameName))
            {
                frames.Add(frameName);
            }

            callStack = callStack.Caller;
        }

        return frames;
    }

    private static string? FindFirstProjectFrame(IReadOnlyList<string> frames, IReadOnlyList<string> prefixes)
    {
        foreach (var frame in frames)
        {
            foreach (var prefix in prefixes)
            {
                if (frame.StartsWith(prefix, StringComparison.Ordinal) ||
                    frame.Contains("." + prefix, StringComparison.Ordinal))
                {
                    return frame;
                }
            }
        }

        return null;
    }

    private static string? FindFirstNonRuntimeFrame(IReadOnlyList<string> frames)
    {
        foreach (var frame in frames)
        {
            if (!frame.StartsWith("System.", StringComparison.Ordinal) &&
                !frame.StartsWith("Microsoft.", StringComparison.Ordinal) &&
                !frame.StartsWith("Internal.", StringComparison.Ordinal))
            {
                return frame;
            }
        }

        return null;
    }

    private static string RenderMarkdown(ExceptionTraceSummary summary)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# QUIC Exception Attribution");
        builder.AppendLine();
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Generated UTC: `{summary.GeneratedAtUtc:O}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Trace: `{summary.TracePath}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Trace SHA-256: `{summary.TraceSha256}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Events: `{summary.EventCount}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Events lost: `{summary.EventsLost}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Has call stacks: `{summary.HasCallStacks}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Total exceptions: `{summary.TotalExceptions}`");
        builder.AppendLine(CultureInfo.InvariantCulture, $"- Total groups: `{summary.TotalGroups}`");
        builder.AppendLine();
        builder.AppendLine("## Groups");
        builder.AppendLine();
        builder.AppendLine("| Count | Exception type | Message | Attribution frame | Stack top frame | First project frame |");
        builder.AppendLine("| ---: | --- | --- | --- | --- | --- |");

        foreach (var group in summary.Groups)
        {
            builder.Append("| ");
            builder.Append(group.Count.ToString(CultureInfo.InvariantCulture));
            builder.Append(" | ");
            builder.Append(EscapeMarkdownCell(group.ExceptionType));
            builder.Append(" | ");
            builder.Append(EscapeMarkdownCell(group.ExceptionMessage));
            builder.Append(" | ");
            builder.Append(EscapeMarkdownCell(group.AttributionFrame));
            builder.Append(" | ");
            builder.Append(EscapeMarkdownCell(group.StackTopFrame));
            builder.Append(" | ");
            builder.Append(EscapeMarkdownCell(group.FirstProjectFrame ?? string.Empty));
            builder.AppendLine(" |");
        }

        return builder.ToString();
    }

    private static string EscapeMarkdownCell(string value)
    {
        return value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("|", "\\|", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(stream, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Normalize(string? value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    }

    private static CommandOptions ParseOptions(string[] args)
    {
        var options = new CommandOptions();
        for (var index = 0; index < args.Length; index++)
        {
            var arg = args[index];
            switch (arg)
            {
                case "-h":
                case "--help":
                    options.ShowHelp = true;
                    break;
                case "--trace":
                    options.TracePath = ReadValue(args, ref index, arg);
                    break;
                case "--output":
                    options.OutputRoot = ReadValue(args, ref index, arg);
                    break;
                case "--top":
                    options.Top = int.Parse(ReadValue(args, ref index, arg), CultureInfo.InvariantCulture);
                    break;
                case "--max-frames":
                    options.MaxFrames = int.Parse(ReadValue(args, ref index, arg), CultureInfo.InvariantCulture);
                    break;
                case "--sample-events":
                    options.SampleEventsPerGroup = int.Parse(ReadValue(args, ref index, arg), CultureInfo.InvariantCulture);
                    break;
                case "--project-frame-prefix":
                    options.ProjectFramePrefixes.Add(ReadValue(args, ref index, arg));
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {arg}");
            }
        }

        if (options.Top < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(args), "--top must be at least 1.");
        }

        if (options.MaxFrames < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(args), "--max-frames must be at least 1.");
        }

        if (options.SampleEventsPerGroup < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(args), "--sample-events must not be negative.");
        }

        if (options.ProjectFramePrefixes.Count == 0)
        {
            options.ProjectFramePrefixes.Add("Incursa.");
        }

        return options;
    }

    private static string ReadValue(string[] args, ref int index, string option)
    {
        index++;
        if (index >= args.Length)
        {
            throw new ArgumentException($"{option} requires a value.");
        }

        return args[index];
    }

    private static void WriteUsage(TextWriter writer)
    {
        writer.WriteLine("Usage:");
        writer.WriteLine("  dotnet run --project eng/tools/Incursa.Quic.TraceAnalysis -- --trace <trace.nettrace> [--output <dir>]");
        writer.WriteLine();
        writer.WriteLine("Options:");
        writer.WriteLine("  --trace <path>                 Required .nettrace file.");
        writer.WriteLine("  --output <dir>                 Output directory. Defaults beside the trace.");
        writer.WriteLine("  --top <n>                      Number of groups to include. Default 50.");
        writer.WriteLine("  --max-frames <n>               Sample stack frame depth. Default 32.");
        writer.WriteLine("  --sample-events <n>            Sample event count per group. Default 3.");
        writer.WriteLine("  --project-frame-prefix <text>  Prefix used to identify first project frame. Repeatable.");
    }
}

internal sealed class CommandOptions
{
    public bool ShowHelp { get; set; }

    public string? TracePath { get; set; }

    public string? OutputRoot { get; set; }

    public int Top { get; set; } = 50;

    public int MaxFrames { get; set; } = 32;

    public int SampleEventsPerGroup { get; set; } = 3;

    public List<string> ProjectFramePrefixes { get; } = [];
}

internal sealed class ExceptionTraceSummary
{
    public string SchemaVersion { get; set; } = string.Empty;

    public DateTimeOffset GeneratedAtUtc { get; set; }

    public string TracePath { get; set; } = string.Empty;

    public string TraceSha256 { get; set; } = string.Empty;

    public string OutputRoot { get; set; } = string.Empty;

    public int EventCount { get; set; }

    public int EventsLost { get; set; }

    public bool HasCallStacks { get; set; }

    public int TotalExceptions { get; set; }

    public int TotalGroups { get; set; }

    public int IncludedGroups { get; set; }

    public IReadOnlyList<string> ProjectFramePrefixes { get; set; } = [];

    public string ConversionLog { get; set; } = string.Empty;

    public IReadOnlyList<ExceptionTraceGroup> Groups { get; set; } = [];
}

internal sealed class ExceptionTraceGroup
{
    public int Count { get; set; }

    public string ExceptionType { get; set; } = string.Empty;

    public string ExceptionMessage { get; set; } = string.Empty;

    public string StackTopFrame { get; set; } = string.Empty;

    public string AttributionFrame { get; set; } = string.Empty;

    public string? FirstProjectFrame { get; set; }

    public IReadOnlyList<string> SampleFrames { get; set; } = [];

    public List<ExceptionTraceEventSample> SampleEvents { get; set; } = [];
}

internal sealed class ExceptionTraceEventSample
{
    public int ProcessId { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public int ThreadId { get; set; }

    public double RelativeMilliseconds { get; set; }

    public DateTime TimeStampUtc { get; set; }
}

internal readonly record struct ExceptionGroupKey(
    string ExceptionType,
    string ExceptionMessage,
    string AttributionFrame);

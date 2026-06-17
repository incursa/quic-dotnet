// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text;
using Xunit.Abstractions;

namespace Incursa.Quic.Tests;

public sealed class ProtocolLabPerformanceBridgeTests
{
    private readonly ITestOutputHelper _output;

    public ProtocolLabPerformanceBridgeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [ProtocolLabPerformanceFact]
    [Trait("Category", "Performance")]
    [Trait("BenchmarkHarness", "ProtocolLab")]
    public async Task Focused_protocol_lab_quic_transport_benchmark_runs_in_source_mode()
    {
        var repoRoot = FindRepoRoot();
        var protocolLabRoot = FindProtocolLabRoot(repoRoot);
        var protocolLabExecutionRoot = FindProtocolLabExecutionRoot(protocolLabRoot);
        var runIdPrefix = $"xunit-protocol-lab-perf-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}";
        var runId = $"{runIdPrefix}-quic-transport-v1-comparison";
        var runArtifactPath = Path.Combine(protocolLabExecutionRoot, ".artifacts", "runs", runId);
        var publicationArtifactPath = Path.Combine(protocolLabExecutionRoot, ".artifacts", "publication", runId);

        _output.WriteLine($"ProtocolLab root: {protocolLabRoot}");
        _output.WriteLine($"ProtocolLab execution root: {protocolLabExecutionRoot}");
        _output.WriteLine($"Run artifacts: {runArtifactPath}");
        _output.WriteLine($"Publication artifacts: {publicationArtifactPath}");

        var scriptPath = Path.Combine(repoRoot, "scripts", "perf", "Invoke-ProtocolLabLocalQuicBenchmark.ps1");
        var result = await RunProcessAsync(
            "pwsh",
            repoRoot,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            scriptPath,
            "-ProtocolLabRoot",
            protocolLabRoot,
            "-ProtocolLabExecutionRoot",
            protocolLabExecutionRoot,
            "-UseProjectReferences",
            "-Suite",
            "quic-transport-v1-comparison",
            "-Implementation",
            "incursa-raw-quic-adapter-v1",
            "-Scenario",
            "quic.transport.multiplex.100x64kb",
            "-WorkflowProfile",
            "Quick",
            "-RunIdPrefix",
            runIdPrefix,
            "-DurationSeconds",
            "1",
            "-WarmupSeconds",
            "1",
            "-Repetitions",
            "1",
            "-Connections",
            "1",
            "-StreamsPerConnection",
            "1",
            "-FailOnError");

        _output.WriteLine(result.Output);

        Assert.True(result.ExitCode == 0, $"ProtocolLab helper exited {result.ExitCode}.{Environment.NewLine}{result.Output}");
        Assert.True(Directory.Exists(runArtifactPath), $"Expected run artifact path was not created: {runArtifactPath}");
    }

    private static async Task<ProcessResult> RunProcessAsync(string fileName, string workingDirectory, params string[] arguments)
    {
        using Process process = new();
        process.StartInfo = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        process.StartInfo.Environment["DOTNET_NOLOGO"] = "1";

        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        StringBuilder output = new();
        process.OutputDataReceived += (_, args) =>
        {
            if (args.Data is not null)
            {
                output.AppendLine(args.Data);
            }
        };
        process.ErrorDataReceived += (_, args) =>
        {
            if (args.Data is not null)
            {
                output.AppendLine(args.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync();

        return new ProcessResult(process.ExitCode, output.ToString());
    }

    private static string FindProtocolLabRoot(string repoRoot)
    {
        var environmentRoot = Environment.GetEnvironmentVariable("PROTOCOL_LAB_ROOT");
        if (!string.IsNullOrWhiteSpace(environmentRoot) && Directory.Exists(environmentRoot))
        {
            return Path.GetFullPath(environmentRoot);
        }

        var siblingRoot = Path.Combine(Directory.GetParent(repoRoot)!.FullName, "protocol-lab");
        if (Directory.Exists(siblingRoot))
        {
            return Path.GetFullPath(siblingRoot);
        }

        const string defaultRoot = @"C:\shared\src\incursa\protocol-lab";
        if (Directory.Exists(defaultRoot))
        {
            return defaultRoot;
        }

        throw new DirectoryNotFoundException("ProtocolLab root was not found. Set PROTOCOL_LAB_ROOT to the protocol-lab checkout.");
    }

    private static string FindProtocolLabExecutionRoot(string protocolLabRoot)
    {
        var environmentRoot = Environment.GetEnvironmentVariable("PROTOCOL_LAB_EXECUTION_ROOT");
        if (!string.IsNullOrWhiteSpace(environmentRoot) && Directory.Exists(environmentRoot))
        {
            return Path.GetFullPath(environmentRoot);
        }

        var siblingRoot = Path.Combine(Directory.GetParent(protocolLabRoot)!.FullName, "protocol-lab-internal");
        if (Directory.Exists(siblingRoot))
        {
            return Path.GetFullPath(siblingRoot);
        }

        if (File.Exists(Path.Combine(protocolLabRoot, "scripts", "benchmarking", "Invoke-ProtocolLabBenchmarkSet.ps1")))
        {
            return protocolLabRoot;
        }

        throw new DirectoryNotFoundException("ProtocolLab execution root was not found. Set PROTOCOL_LAB_EXECUTION_ROOT to the protocol-lab-internal checkout.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "scripts", "perf", "Invoke-ProtocolLabLocalQuicBenchmark.ps1")) &&
                File.Exists(Path.Combine(directory.FullName, "Incursa.Quic.slnx")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate quic-dotnet repository root.");
    }

    private sealed record ProcessResult(int ExitCode, string Output);
}

public sealed class ProtocolLabPerformanceFactAttribute : FactAttribute
{
    public ProtocolLabPerformanceFactAttribute()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("INCURSA_RUN_PROTOCOLLAB_PERF"), "1", StringComparison.Ordinal))
        {
            Skip = "Set INCURSA_RUN_PROTOCOLLAB_PERF=1 to run the ProtocolLab performance bridge.";
        }
    }
}

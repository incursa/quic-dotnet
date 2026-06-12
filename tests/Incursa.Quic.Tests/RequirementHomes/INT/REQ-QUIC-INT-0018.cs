// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Linq;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
[Requirement("REQ-QUIC-INT-0018")]
public sealed class REQ_QUIC_INT_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DryRunPublishesTheDocumentedNonHttp3InventoryAndClassifiesRebindingCellsAsSupportedAfterLiveProof()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-DryRun",
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "client",
            "-ImplementationSlot",
            "chrome",
            "-PeerImplementationSlots",
            "quic-go,msquic",
            "-TestCases",
            "longrtt,multiplexing,versionnegotiation,zerortt,amplificationlimit,blackhole,transferloss,ipv6,rebind-port,rebind-addr,connectionmigration,handshakecorruption,transfercorruption");

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("client", GetPlanValue(output, "Local role"));
        Assert.Equal("chrome", GetPlanValue(output, "Local implementation slot"));
        Assert.Equal("quic-go,msquic", GetPlanValue(output, "Peer implementation slots"));
        Assert.Equal("chrome", GetPlanValue(output, "Runner client implementations"));
        Assert.Equal("quic-go,msquic", GetPlanValue(output, "Runner server implementations"));
        Assert.Equal("longrtt,multiplexing,versionnegotiation,zerortt,amplificationlimit,blackhole,transferloss,ipv6,rebind-port,rebind-addr,connectionmigration,handshakecorruption,transfercorruption", GetPlanValue(output, "Test cases"));
        Assert.Equal("longrtt,multiplexing,versionnegotiation,zerortt,amplificationlimit,blackhole,transferloss,ipv6,rebind-port,rebind-addr,connectionmigration,handshakecorruption,transfercorruption", GetPlanValue(output, "Runner test cases"));
        Assert.Equal("22", GetPlanValue(output, "Inventory testcase count"));
        Assert.Equal(Path.GetFullPath(fixture.ArtifactsRoot), GetPlanValue(output, "Artifact root"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Equal("handshake,transfer,http3,longrtt,multiplexing,retry,multiconnect,versionnegotiation,chacha20,transfercorruption,keyupdate,resumption,zerortt,amplificationlimit,blackhole,transferloss,ipv6,v2,rebind-port,rebind-addr,connectionmigration", GetPlanValue(output, "Supported/executed"));
        Assert.Equal("handshakecorruption", GetPlanValue(output, "Prerequisite-blocked"));
        Assert.Equal("(none)", GetPlanValue(output, "Intentionally unsupported"));
        Assert.Equal("(none)", GetPlanValue(output, "Not mappable"));
        Assert.StartsWith(Path.GetFullPath(fixture.ArtifactsRoot), runRoot, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("client-chrome", runRoot, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("longrtt -> supported-executed (runner: longrtt)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("multiplexing -> supported-executed (runner: multiplexing)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("zerortt -> supported-executed (runner: zerortt)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("amplificationlimit -> supported-executed (runner: amplificationlimit)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("blackhole -> supported-executed (runner: blackhole)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("transferloss -> supported-executed (runner: transferloss)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ipv6 -> supported-executed (runner: ipv6)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> supported-executed (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rebind-port -> supported-executed (runner: rebind-port)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rebind-addr -> supported-executed (runner: rebind-addr)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("handshakecorruption -> prerequisite-blocked (runner: handshakecorruption)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("transfercorruption -> supported-executed (runner: transfercorruption)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fresh quic-go/chrome runner proof", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("multiconnect-derived corruption flow", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FRAME_ENCODING_ERROR/unknown frame evidence", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("three observed server paths", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("handshake-backed harness path", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Requires client-host socket rebinding lifecycle support before inventory promotion", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("v2 -> prerequisite-blocked", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("buffered request-line reads", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hosted Linux proof success", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Plan-only mode completed without Docker build, runner checkout validation, or runner launch.", output, StringComparison.OrdinalIgnoreCase);
        Assert.True(string.IsNullOrEmpty(result.Stderr));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    private static string GetPlanValue(string output, string label)
    {
        string prefix = $"{label}:";
        string? line = output
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(candidate => candidate.TrimStart().StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(line);
        int colonIndex = line!.IndexOf(':');
        Assert.True(colonIndex >= 0, $"Expected a '{label}' line in the plan output.\n{output}");
        return line[(colonIndex + 1)..].Trim();
    }

    private sealed class InteropRunnerScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-interop-runner-int-0018");
        private readonly string powerShellExecutable;
        private readonly string toolRoot;

        public InteropRunnerScriptFixture()
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop-runner");
            ArtifactsRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "artifacts", "interop-runner");
            toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(RunnerRoot);
            Directory.CreateDirectory(toolRoot);

            CreateCommandStubs(toolRoot);
            CreateRunnerRegistry(RunnerRoot);

            powerShellExecutable = ResolvePowerShellExecutable();
            ScriptPath = FindScriptPath();
            RepoRoot = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(ScriptPath)!, "..", ".."));
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public string ScriptPath { get; }

        public async Task<ScriptRunResult> RunAsync(params string[] arguments)
        {
            ProcessStartInfo startInfo = new(powerShellExecutable)
            {
                WorkingDirectory = RepoRoot,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(ScriptPath);

            foreach (string argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            string existingPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            startInfo.Environment["PATH"] = $"{toolRoot}{Path.PathSeparator}{existingPath}";

            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Unable to start the interop runner helper script.");

            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();

            Task exitTask = process.WaitForExitAsync();
            Task completed = await Task.WhenAny(exitTask, Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
            if (completed != exitTask)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best-effort cleanup only.
                }

                throw new TimeoutException(
                    $"The interop runner helper script did not exit within 30 seconds.\nSTDOUT:\n{await stdoutTask.ConfigureAwait(false)}\nSTDERR:\n{await stderrTask.ConfigureAwait(false)}");
            }

            await exitTask.ConfigureAwait(false);

            return new ScriptRunResult(
                process.ExitCode,
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false),
                string.Empty);
        }

        public void Dispose()
        {
            tempDirectoryFixture.Dispose();
        }

        private static void CreateCommandStubs(string toolRoot)
        {
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(
                    Path.Combine(toolRoot, "docker.cmd"),
                    """
                    @echo off
                    exit /b 99
                    """);
            }
            else
            {
                string dockerStubPath = Path.Combine(toolRoot, "docker");
                File.WriteAllText(
                    dockerStubPath,
                    """
                    #!/usr/bin/env sh
                    exit 99
                    """);

#pragma warning disable CA1416
                File.SetUnixFileMode(
                    dockerStubPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
            }
        }

        private static void CreateRunnerRegistry(string runnerRoot)
        {
            File.WriteAllText(
                Path.Combine(runnerRoot, "implementations_quic.json"),
                """
                {
                  "quic-go": {
                    "role": "both"
                  },
                  "msquic": {
                    "role": "both"
                  },
                  "chrome": {
                    "role": "client"
                  },
                  "nginx": {
                    "role": "server"
                  }
                }
                """);

            File.WriteAllText(Path.Combine(runnerRoot, "run.py"), "# placeholder runner script\n");
        }

        private static string ResolvePowerShellExecutable()
        {
            string[] candidates = OperatingSystem.IsWindows()
                ? ["pwsh.exe", "pwsh", "powershell.exe", "powershell"]
                : ["pwsh", "pwsh.exe"];

            foreach (string candidate in candidates)
            {
                string? resolved = ResolveExecutableOnPath(candidate);
                if (resolved is not null)
                {
                    return resolved;
                }
            }

            throw new InvalidOperationException("Unable to locate a PowerShell executable on PATH.");
        }

        private static string? ResolveExecutableOnPath(string fileName)
        {
            if (Path.IsPathRooted(fileName) && File.Exists(fileName))
            {
                return fileName;
            }

            string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string candidate = Path.Combine(directory, fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }

        private static string FindScriptPath()
        {
            DirectoryInfo? current = new DirectoryInfo(AppContext.BaseDirectory);
            while (current is not null)
            {
                string candidate = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicInteropRunner.ps1");
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                current = current.Parent;
            }

            throw new InvalidOperationException("Unable to locate scripts/interop/Invoke-QuicInteropRunner.ps1.");
        }
    }

    private sealed class TempDirectoryFixture : IDisposable
    {
        public TempDirectoryFixture(string prefix)
        {
            RootDirectory = Path.Combine(Path.GetTempPath(), prefix, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(RootDirectory);
        }

        public string RootDirectory { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(RootDirectory))
                {
                    Directory.Delete(RootDirectory, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }
    }

    private sealed record ScriptRunResult(int ExitCode, string Stdout, string Stderr, string ExceptionMessage)
    {
        public string CombinedOutput => $"{Stdout}{Environment.NewLine}{Stderr}";
    }
}

using System.Diagnostics;

namespace Incursa.Quic.Tests;

[CollectionDefinition(nameof(InteropRunnerScriptDryRunTestsCollection), DisableParallelization = true)]
public sealed class InteropRunnerScriptDryRunTestsCollection
{
}

[Collection(nameof(InteropRunnerScriptDryRunTestsCollection))]
public sealed class InteropRunnerScriptDryRunTests
{
    [Theory]
    [MemberData(nameof(GetDryRunPlanCases))]
    public async Task DryRunPrintsTheExpectedPlanWithoutCreatingArtifactsOrInvokingDocker(
        string? localRole,
        string? implementationSlot,
        string? peerImplementationSlots,
        string? testCases,
        string expectedLocalImplementationSlot,
        string expectedPeerImplementationSlots,
        string expectedRunnerClientImplementations,
        string expectedRunnerServerImplementations,
        string expectedTestCases)
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                localRole,
                implementationSlot,
                peerImplementationSlots,
                testCases));

        string output = result.CombinedOutput;
        string expectedLocalRole = localRole ?? "both";
        string artifactRoot = Path.GetFullPath(Path.Combine(fixture.RepoRoot, "artifacts", "interop-runner"));
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner plan-only.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Plan-only mode completed without Docker build, runner checkout validation, or runner launch.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Path.GetFullPath(fixture.RepoRoot), GetPlanValue(output, "Repo root"));
        Assert.Equal(Path.GetFullPath(fixture.RunnerRoot), GetPlanValue(output, "Runner root"));
        Assert.Equal(expectedLocalRole, GetPlanValue(output, "Local role"));
        Assert.Equal(expectedLocalImplementationSlot, GetPlanValue(output, "Local implementation slot"));
        Assert.Equal(expectedPeerImplementationSlots, GetPlanValue(output, "Peer implementation slots"));
        Assert.Equal(expectedRunnerClientImplementations, GetPlanValue(output, "Runner client implementations"));
        Assert.Equal(expectedRunnerServerImplementations, GetPlanValue(output, "Runner server implementations"));
        Assert.Equal(expectedTestCases, GetPlanValue(output, "Test cases"));
        Assert.Equal(artifactRoot, GetPlanValue(output, "Artifact root"));
        Assert.StartsWith(artifactRoot, runRoot, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith($"{expectedLocalRole}-{expectedLocalImplementationSlot}", runRoot, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(Path.GetFullPath(Path.Combine(fixture.RepoRoot, "src", "Incursa.Quic.InteropHarness", "Dockerfile")), GetPlanValue(output, "Dockerfile"));
        Assert.Equal(Path.GetFullPath(Path.Combine(fixture.RunnerRoot, "run.py")), GetPlanValue(output, "Runner script"));
        Assert.Equal(Path.Combine(runRoot, "docker-build.log"), GetPlanValue(output, "Docker build log"));
        Assert.Equal(Path.Combine(runRoot, "invocation.txt"), GetPlanValue(output, "Invocation log"));
        Assert.Equal(Path.Combine(runRoot, "runner-report.json"), GetPlanValue(output, "Runner JSON"));
        Assert.Equal(Path.Combine(runRoot, "runner-report.md"), GetPlanValue(output, "Runner Markdown"));
        Assert.Equal(Path.Combine(runRoot, "runner.stderr.log"), GetPlanValue(output, "Runner stderr"));
        Assert.Equal(Path.Combine(runRoot, "runner-logs"), GetPlanValue(output, "Runner logs"));
        Assert.Equal(Path.Combine(runRoot, "artifact-tree.txt"), GetPlanValue(output, "Artifact tree"));
        Assert.Equal(Path.Combine(runRoot, "runner-shim.py"), GetPlanValue(output, "Runner shim"));
        Assert.Equal("13", GetPlanValue(output, "Inventory testcase count"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Equal("handshake,transfer,retry,multiconnect,versionnegotiation,keyupdate", GetPlanValue(output, "Supported/executed"));
        Assert.Equal(
            "chacha20,resumption,zerortt,v2,rebind-port,rebind-addr,connectionmigration",
            GetPlanValue(output, "Prerequisite-blocked"));
        Assert.Equal("(none)", GetPlanValue(output, "Intentionally unsupported"));
        Assert.Equal("(none)", GetPlanValue(output, "Not mappable"));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    [Fact]
    public async Task DryRunAcceptsDocumentedInventoryCellsAndKeepsThemExplicit()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                "client",
                "chrome",
                "quic-go,msquic",
                "versionnegotiation,chacha20,keyupdate,connectionmigration"));

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("versionnegotiation,chacha20,keyupdate,connectionmigration", GetPlanValue(output, "Test cases"));
        Assert.Equal("versionnegotiation,chacha20,keyupdate,connectionmigration", GetPlanValue(output, "Runner test cases"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("chacha20 -> prerequisite-blocked (runner: chacha20)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("keyupdate -> supported-executed (runner: keyupdate)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> prerequisite-blocked (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("chacha20 -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("resumption -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("keyupdate -> prerequisite-blocked", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    [Fact]
    public async Task DryRunAcceptsResumptionAsBlockedAndKeepsTheGreenCellsExplicit()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                "client",
                "chrome",
                "quic-go,msquic",
                "versionnegotiation,resumption,connectionmigration"));

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("versionnegotiation,resumption,connectionmigration", GetPlanValue(output, "Test cases"));
        Assert.Equal("versionnegotiation,resumption,connectionmigration", GetPlanValue(output, "Runner test cases"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("resumption -> prerequisite-blocked (runner: resumption)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> prerequisite-blocked (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("resumption -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    [Fact]
    public async Task DryRunAcceptsZerorttAsBlockedAndKeepsTheGreenCellsExplicit()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                "client",
                "chrome",
                "quic-go,msquic",
                "versionnegotiation,zerortt,connectionmigration"));

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("versionnegotiation,zerortt,connectionmigration", GetPlanValue(output, "Test cases"));
        Assert.Equal("versionnegotiation,zerortt,connectionmigration", GetPlanValue(output, "Runner test cases"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("zerortt -> prerequisite-blocked (runner: zerortt)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> prerequisite-blocked (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("zerortt -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    [Fact]
    public async Task DryRunAcceptsV2AsBlockedAndKeepsTheGreenCellsExplicit()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                "client",
                "chrome",
                "quic-go,msquic",
                "versionnegotiation,v2,connectionmigration"));

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("versionnegotiation,v2,connectionmigration", GetPlanValue(output, "Test cases"));
        Assert.Equal("versionnegotiation,v2,connectionmigration", GetPlanValue(output, "Runner test cases"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("v2 -> prerequisite-blocked (runner: v2)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> prerequisite-blocked (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("v2 -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    [Fact]
    public async Task DryRunAcceptsPathValidationCellsAsBlockedAndKeepsTheGreenCellsExplicit()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            CreateDryRunArguments(
                fixture.RepoRoot,
                "client",
                "chrome",
                "quic-go,msquic",
                "versionnegotiation,rebind-port,rebind-addr,connectionmigration"));

        string output = result.CombinedOutput;
        string runRoot = GetPlanValue(output, "Run root");

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Equal("versionnegotiation,rebind-port,rebind-addr,connectionmigration", GetPlanValue(output, "Test cases"));
        Assert.Equal("versionnegotiation,rebind-port,rebind-addr,connectionmigration", GetPlanValue(output, "Runner test cases"));
        Assert.Equal(Path.Combine(runRoot, "testcase-inventory.json"), GetPlanValue(output, "Inventory JSON"));
        Assert.Contains("Requested inventory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("versionnegotiation -> supported-executed (runner: versionnegotiation)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rebind-port -> prerequisite-blocked (runner: rebind-port)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("rebind-addr -> prerequisite-blocked (runner: rebind-addr)", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("connectionmigration -> prerequisite-blocked (runner: connectionmigration)", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rebind-port -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rebind-addr -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connectionmigration -> supported-executed", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
        Assert.False(File.Exists(fixture.DockerSentinelPath));
    }

    public static IEnumerable<object?[]> GetDryRunPlanCases()
    {
        yield return new object?[]
        {
            null,
            null,
            null,
            null,
            "quic-go",
            "quic-go,msquic",
            "quic-go",
            "quic-go",
            "handshake,retry,transfer",
        };

        yield return new object?[]
        {
            "client",
            null,
            null,
            null,
            "chrome",
            "quic-go,msquic",
            "chrome",
            "quic-go,msquic",
            "handshake,retry,transfer",
        };

        yield return new object?[]
        {
            "server",
            null,
            null,
            null,
            "nginx",
            "quic-go,msquic",
            "quic-go,msquic",
            "nginx",
            "handshake,retry,transfer",
        };

        yield return new object?[]
        {
            "client",
            null,
            "msquic,quic-go",
            "transfer,handshake",
            "chrome",
            "msquic,quic-go",
            "chrome",
            "msquic,quic-go",
            "transfer,handshake",
        };
    }

    private static string[] CreateDryRunArguments(
        string repoRoot,
        string? localRole,
        string? implementationSlot = null,
        string? peerImplementationSlots = null,
        string? testCases = null)
    {
        List<string> arguments =
        [
            "-DryRun",
            "-RepoRoot",
            repoRoot,
        ];

        if (localRole is not null)
        {
            arguments.Add("-LocalRole");
            arguments.Add(localRole);
        }

        if (implementationSlot is not null)
        {
            arguments.Add("-ImplementationSlot");
            arguments.Add(implementationSlot);
        }

        if (peerImplementationSlots is not null)
        {
            arguments.Add("-PeerImplementationSlots");
            arguments.Add(peerImplementationSlots);
        }

        if (testCases is not null)
        {
            arguments.Add("-TestCases");
            arguments.Add(testCases);
        }

        return [.. arguments];
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
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-interop-runner-script-dryrun");
        private readonly string powerShellExecutable;
        private readonly string toolRoot;

        public InteropRunnerScriptFixture()
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-interop-runner");
            ArtifactsRoot = Path.Combine(RepoRoot, "artifacts", "interop-runner");
            DockerSentinelPath = Path.Combine(tempDirectoryFixture.RootDirectory, "docker-invoked.txt");
            toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(RepoRoot);
            Directory.CreateDirectory(RunnerRoot);
            Directory.CreateDirectory(toolRoot);

            CreateCommandStubs(toolRoot, DockerSentinelPath);
            powerShellExecutable = ResolvePowerShellExecutable();
            ScriptPath = FindScriptPath();
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public string DockerSentinelPath { get; }

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

        private static void CreateCommandStubs(string toolRoot, string dockerSentinelPath)
        {
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(
                    Path.Combine(toolRoot, "docker.cmd"),
                    $"""
                    @echo off
                    echo docker invoked > "{dockerSentinelPath}"
                    exit /b 99
                    """);
            }
            else
            {
                string dockerStubPath = Path.Combine(toolRoot, "docker");
                File.WriteAllText(
                    dockerStubPath,
                    $"""
                    #!/usr/bin/env sh
                    printf '%s\n' 'docker invoked' > '{dockerSentinelPath}'
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

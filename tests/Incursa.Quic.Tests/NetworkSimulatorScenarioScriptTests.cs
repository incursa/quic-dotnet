using System.Diagnostics;
using System.Text.Json;

namespace Incursa.Quic.Tests;

[CollectionDefinition(nameof(NetworkSimulatorScenarioScriptTestsCollection), DisableParallelization = true)]
public sealed class NetworkSimulatorScenarioScriptTestsCollection
{
}

[Collection(nameof(NetworkSimulatorScenarioScriptTestsCollection))]
public sealed class NetworkSimulatorScenarioScriptTests
{
    [Fact]
    public async Task DryRunPrintsBaselineScenarioPlanWithoutCreatingArtifacts()
    {
        using NetworkSimulatorScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-DryRun",
            "-ScenarioId",
            "SIM-QUIC-BASE-0001");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Network simulator scenario plan.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Plan-only mode completed without simulator checkout validation or simulator launch.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("SIM-QUIC-BASE-0001", GetPlanValue(output, "Scenario id"));
        Assert.Equal("correctness", GetPlanValue(output, "Classification"));
        Assert.Equal("simple-p2p", GetPlanValue(output, "Upstream profile"));
        Assert.Equal("sim/scenarios/simple-p2p/README.md", GetPlanValue(output, "Upstream reference"));
        Assert.Equal("--delay=15ms --bandwidth=10Mbps --queue=25", GetPlanValue(output, "Parameters"));
        Assert.Equal("REQ-QUIC-INT-0026,REQ-QUIC-INT-0010", GetPlanValue(output, "Mapped requirements"));
        Assert.Equal("simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25", GetPlanValue(output, "Simulator command"));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    public async Task DryRunPrintsDroplistScenarioPlanWithMappedRecoveryRequirements()
    {
        using NetworkSimulatorScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-DryRun",
            "-ScenarioId",
            "SIM-QUIC-LOSS-0001",
            "-DropsToClient",
            "4,8",
            "-DropsToServer",
            "6");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.Equal("SIM-QUIC-LOSS-0001", GetPlanValue(output, "Scenario id"));
        Assert.Equal("droplist", GetPlanValue(output, "Upstream profile"));
        Assert.Equal("sim/scenarios/droplist/README.md", GetPlanValue(output, "Upstream reference"));
        Assert.Equal(
            "--delay=15ms --bandwidth=10Mbps --queue=25 --drops_to_client=4,8 --drops_to_server=6",
            GetPlanValue(output, "Parameters"));
        Assert.Equal(
            "REQ-QUIC-RFC9002-S3-0009,REQ-QUIC-RFC9002-S3-0010,REQ-QUIC-RFC9002-S6P2-0001,REQ-QUIC-RFC9002-S6P2P4-0001,REQ-QUIC-RFC9002-S6P2P4-0003",
            GetPlanValue(output, "Mapped requirements"));
        Assert.Contains("bottleneck-link IP packet indexes", GetPlanValue(output, "Expected observable behavior"), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("droplist --delay=15ms", GetPlanValue(output, "Simulator command"), StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    public async Task LossScenarioRequiresAnExplicitDroplist()
    {
        using NetworkSimulatorScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-DryRun",
            "-ScenarioId",
            "SIM-QUIC-LOSS-0001");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("requires -DropsToClient, -DropsToServer, or both", result.CombinedOutput, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    public async Task EvidenceOnlyPathPreservesMinimumScenarioEvidenceBundle()
    {
        using NetworkSimulatorScriptFixture fixture = new();
        fixture.CreateSimulatorComposeFile();

        ScriptRunResult result = await fixture.RunAsync(
            "-ScenarioId",
            "SIM-QUIC-BASE-0001",
            "-SimulatorRoot",
            fixture.SimulatorRoot,
            "-RunId",
            "test-run");

        Assert.True(
            result.ExitCode == 0,
            $"Helper exit code was {result.ExitCode}.\nSTDOUT:\n{result.Stdout}\nSTDERR:\n{result.Stderr}");

        string runRoot = Path.Combine(fixture.ArtifactsRoot, "SIM-QUIC-BASE-0001", "test-run");
        string scenarioSummaryPath = Path.Combine(runRoot, "scenario-summary.json");
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string stdoutPath = Path.Combine(runRoot, "simulator.stdout.log");
        string stderrPath = Path.Combine(runRoot, "simulator.stderr.log");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");

        Assert.True(File.Exists(scenarioSummaryPath));
        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(stdoutPath));
        Assert.True(File.Exists(stderrPath));
        Assert.True(File.Exists(artifactTreePath));

        string summaryText = File.ReadAllText(scenarioSummaryPath);
        using JsonDocument summary = JsonDocument.Parse(summaryText);

        Assert.Equal("execution-not-requested", summary.RootElement.GetProperty("status").GetString());
        Assert.Equal("not-promoted", summary.RootElement.GetProperty("promotion_result").GetString());
        Assert.Equal(0, summary.RootElement.GetProperty("exit_code").GetInt32());
        Assert.False(summary.RootElement.GetProperty("execute_requested").GetBoolean());
        Assert.Equal("SIM-QUIC-BASE-0001", summary.RootElement.GetProperty("scenario").GetProperty("scenario_id").GetString());
        Assert.Equal("simple-p2p", summary.RootElement.GetProperty("scenario").GetProperty("upstream_profile").GetString());
        Assert.Contains("Simulator execution was not requested", summary.RootElement.GetProperty("observed_result").GetString(), StringComparison.OrdinalIgnoreCase);

        Assert.Contains("ScenarioCommand: simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25", File.ReadAllText(invocationPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ComposeCommand: docker compose --file docker-compose.yml up --build --force-recreate --abort-on-container-exit", File.ReadAllText(invocationPath), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(string.Empty, File.ReadAllText(stdoutPath));
        Assert.Equal(string.Empty, File.ReadAllText(stderrPath));

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("scenario-summary.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("invocation.txt", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("simulator.stdout.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("simulator.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingSimulatorComposeFilePreservesPreflightFailureEvidence()
    {
        using NetworkSimulatorScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-ScenarioId",
            "SIM-QUIC-BASE-0001",
            "-SimulatorRoot",
            fixture.SimulatorRoot,
            "-RunId",
            "missing-compose-file");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("Simulator docker-compose file was not found", result.CombinedOutput, StringComparison.OrdinalIgnoreCase);

        string runRoot = Path.Combine(fixture.ArtifactsRoot, "SIM-QUIC-BASE-0001", "missing-compose-file");
        string scenarioSummaryPath = Path.Combine(runRoot, "scenario-summary.json");
        string stderrPath = Path.Combine(runRoot, "simulator.stderr.log");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");

        Assert.True(File.Exists(scenarioSummaryPath));
        Assert.True(File.Exists(stderrPath));
        Assert.True(File.Exists(artifactTreePath));

        using JsonDocument summary = JsonDocument.Parse(File.ReadAllText(scenarioSummaryPath));

        Assert.Equal("preflight-failed", summary.RootElement.GetProperty("status").GetString());
        Assert.Equal("not-promoted", summary.RootElement.GetProperty("promotion_result").GetString());
        Assert.Equal(1, summary.RootElement.GetProperty("exit_code").GetInt32());
        Assert.Contains("Simulator docker-compose file was not found", summary.RootElement.GetProperty("observed_result").GetString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Simulator docker-compose file was not found", File.ReadAllText(stderrPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("scenario-summary.json", File.ReadAllText(artifactTreePath), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SimulatorNonZeroExitPreservesFailureEvidence()
    {
        using NetworkSimulatorScriptFixture fixture = new();
        fixture.CreateSimulatorComposeFile();
        fixture.CreateEndpointDirectory("client-impl");
        fixture.CreateEndpointDirectory("server-impl");
        Directory.CreateDirectory(Path.Combine(fixture.SimulatorRoot, "logs", "sim"));
        File.WriteAllText(Path.Combine(fixture.SimulatorRoot, "logs", "sim", "trace_node_left.pcap"), "left-pcap");
        File.WriteAllText(Path.Combine(fixture.SimulatorRoot, "logs", "sim", "trace_node_right.pcap"), "right-pcap");
        fixture.ConfigureDockerStubExitCode(37);

        ScriptRunResult result = await fixture.RunAsync(
            "-ScenarioId",
            "SIM-QUIC-LOSS-0001",
            "-SimulatorRoot",
            fixture.SimulatorRoot,
            "-RunId",
            "simulator-failure",
            "-Execute",
            "-Client",
            "client-impl",
            "-Server",
            "server-impl",
            "-DropsToClient",
            "4");

        Assert.Equal(37, result.ExitCode);

        string runRoot = Path.Combine(fixture.ArtifactsRoot, "SIM-QUIC-LOSS-0001", "simulator-failure");
        string scenarioSummaryPath = Path.Combine(runRoot, "scenario-summary.json");
        string stdoutPath = Path.Combine(runRoot, "simulator.stdout.log");
        string stderrPath = Path.Combine(runRoot, "simulator.stderr.log");
        string simulatorLogsRoot = Path.Combine(runRoot, "simulator-logs", "sim");

        using JsonDocument summary = JsonDocument.Parse(File.ReadAllText(scenarioSummaryPath));

        Assert.Equal("simulator-failed", summary.RootElement.GetProperty("status").GetString());
        Assert.Equal("not-promoted", summary.RootElement.GetProperty("promotion_result").GetString());
        Assert.Equal(37, summary.RootElement.GetProperty("exit_code").GetInt32());
        Assert.True(summary.RootElement.GetProperty("execute_requested").GetBoolean());
        Assert.Equal("SIM-QUIC-LOSS-0001", summary.RootElement.GetProperty("scenario").GetProperty("scenario_id").GetString());
        Assert.Contains("Docker compose failed", summary.RootElement.GetProperty("observed_result").GetString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake docker invoked", File.ReadAllText(stdoutPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake docker stderr", File.ReadAllText(stderrPath), StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(Path.Combine(simulatorLogsRoot, "trace_node_left.pcap")));
        Assert.True(File.Exists(Path.Combine(simulatorLogsRoot, "trace_node_right.pcap")));
        Assert.Equal("left-pcap", File.ReadAllText(Path.Combine(simulatorLogsRoot, "trace_node_left.pcap")));
        Assert.Equal("right-pcap", File.ReadAllText(Path.Combine(simulatorLogsRoot, "trace_node_right.pcap")));
    }

    [Fact]
    public async Task ExecuteWithoutExplicitEndpointsStagesIncursaEndpointContextsAndComposeOverride()
    {
        using NetworkSimulatorScriptFixture fixture = new();
        fixture.CreateSimulatorComposeFile();
        fixture.CreateMinimalHarnessSource();
        fixture.ConfigureDockerStubExitCode(37);

        ScriptRunResult result = await fixture.RunAsync(
            "-ScenarioId",
            "SIM-QUIC-BASE-0001",
            "-SimulatorRoot",
            fixture.SimulatorRoot,
            "-RunId",
            "staged-incursa-endpoints",
            "-Execute");

        Assert.Equal(37, result.ExitCode);

        string runRoot = Path.Combine(fixture.ArtifactsRoot, "SIM-QUIC-BASE-0001", "staged-incursa-endpoints");
        string scenarioSummaryPath = Path.Combine(runRoot, "scenario-summary.json");
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string composeOverridePath = Path.Combine(runRoot, "incursa-endpoints.compose.yml");
        string contextRoot = Path.Combine(runRoot, "staged-endpoints", "incursa-quic");
        string wwwPath = Path.Combine(runRoot, "www", "10000.txt");
        string certPath = Path.Combine(runRoot, "certs", "cert.pem");
        string privateKeyPath = Path.Combine(runRoot, "certs", "priv.key");

        Assert.True(File.Exists(scenarioSummaryPath));
        Assert.True(File.Exists(composeOverridePath));
        Assert.True(File.Exists(Path.Combine(contextRoot, "Dockerfile")));
        Assert.True(File.Exists(Path.Combine(contextRoot, "quic-dotnet", "src", "Incursa.Quic.InteropHarness", "run_endpoint.sh")));
        Assert.True(File.Exists(wwwPath));
        Assert.True(File.Exists(certPath));
        Assert.True(File.Exists(privateKeyPath));

        string composeOverride = File.ReadAllText(composeOverridePath);
        Assert.Contains("TESTCASE=transfer", composeOverride, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REQUESTS=https://server4/10000.txt", composeOverride, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("/certs", composeOverride, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, CountOccurrences(composeOverride, ":/www", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("/downloads", composeOverride, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ComposeOverride:", File.ReadAllText(invocationPath), StringComparison.OrdinalIgnoreCase);

        using JsonDocument summary = JsonDocument.Parse(File.ReadAllText(scenarioSummaryPath));

        Assert.True(summary.RootElement.GetProperty("execute_requested").GetBoolean());
        Assert.Equal("incursa-client", summary.RootElement.GetProperty("client").GetString());
        Assert.Equal("incursa-server", summary.RootElement.GetProperty("server").GetString());
        Assert.Equal("simulator-failed", summary.RootElement.GetProperty("status").GetString());
        Assert.Equal(composeOverridePath, summary.RootElement.GetProperty("endpoint_staging").GetProperty("compose_override").GetString());
        Assert.Equal("https://server4/10000.txt", summary.RootElement.GetProperty("endpoint_staging").GetProperty("request_uri").GetString());
    }

    private static string GetPlanValue(string output, string label)
    {
        string prefix = $"{label}:";
        string? line = output
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(candidate => candidate.TrimStart().StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

        Assert.NotNull(line);
        int colonIndex = line!.IndexOf(':', StringComparison.Ordinal);
        Assert.True(colonIndex >= 0, $"Expected a '{label}' line in the plan output.\n{output}");
        return line[(colonIndex + 1)..].Trim();
    }

    private static int CountOccurrences(string value, string searchValue, StringComparison comparison)
    {
        int count = 0;
        int searchIndex = 0;
        while (searchIndex < value.Length)
        {
            int foundIndex = value.IndexOf(searchValue, searchIndex, comparison);
            if (foundIndex < 0)
            {
                return count;
            }

            count++;
            searchIndex = foundIndex + searchValue.Length;
        }

        return count;
    }

    private sealed class NetworkSimulatorScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-network-simulator-script");
        private readonly string powerShellExecutable;
        private readonly string scriptPath;
        private readonly string toolRoot;

        public NetworkSimulatorScriptFixture()
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            SimulatorRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-network-simulator");
            ArtifactsRoot = Path.Combine(workspaceRoot, "artifacts", "network-simulator");
            toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(RepoRoot);
            Directory.CreateDirectory(SimulatorRoot);
            Directory.CreateDirectory(toolRoot);

            CreateDockerStub(toolRoot, exitCode: 0);
            powerShellExecutable = ResolvePowerShellExecutable();
            scriptPath = FindScriptPath();
        }

        public string RepoRoot { get; }

        public string SimulatorRoot { get; }

        public string ArtifactsRoot { get; }

        public void CreateSimulatorComposeFile()
        {
            string composePath = Path.Combine(SimulatorRoot, "docker-compose.yml");
            File.WriteAllText(
                composePath,
                """
                services: {}
                """);
        }

        public void CreateEndpointDirectory(string name)
        {
            Directory.CreateDirectory(Path.Combine(SimulatorRoot, name));
        }

        public void CreateMinimalHarnessSource()
        {
            string harnessRoot = Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness");
            Directory.CreateDirectory(harnessRoot);

            File.WriteAllText(
                Path.Combine(harnessRoot, "Dockerfile"),
                """
                FROM scratch
                COPY quic-dotnet/src/Incursa.Quic.InteropHarness/run_endpoint.sh /run_endpoint.sh
                COPY quic-dotnet/src/Incursa.Quic.InteropHarness/setup.sh /setup.sh
                """);

            File.WriteAllText(
                Path.Combine(harnessRoot, "run_endpoint.sh"),
                """
                #!/usr/bin/env bash
                exit 0
                """);

            File.WriteAllText(
                Path.Combine(harnessRoot, "setup.sh"),
                """
                #!/usr/bin/env bash
                exit 0
                """);
        }

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
            startInfo.ArgumentList.Add(scriptPath);
            startInfo.ArgumentList.Add("-RepoRoot");
            startInfo.ArgumentList.Add(RepoRoot);
            startInfo.ArgumentList.Add("-ArtifactsRoot");
            startInfo.ArgumentList.Add(ArtifactsRoot);

            foreach (string argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            string existingPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            startInfo.Environment["PATH"] = $"{toolRoot}{Path.PathSeparator}{existingPath}";

            using Process process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Unable to start the network simulator helper script.");

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
                    $"The network simulator helper script did not exit within 30 seconds.\nSTDOUT:\n{await stdoutTask.ConfigureAwait(false)}\nSTDERR:\n{await stderrTask.ConfigureAwait(false)}");
            }

            await exitTask.ConfigureAwait(false);

            return new ScriptRunResult(
                process.ExitCode,
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false));
        }

        public void Dispose()
        {
            tempDirectoryFixture.Dispose();
        }

        public void ConfigureDockerStubExitCode(int exitCode)
        {
            CreateDockerStub(toolRoot, exitCode);
        }

        private static void CreateDockerStub(string toolRoot, int exitCode)
        {
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(
                    Path.Combine(toolRoot, "docker.cmd"),
                    $$"""
                    @echo off
                    echo fake docker invoked %*
                    echo fake docker stderr 1>&2
                    exit /b {{exitCode}}
                    """);
            }
            else
            {
                string dockerPath = Path.Combine(toolRoot, "docker");
                File.WriteAllText(
                    dockerPath,
                    $$"""
                    #!/usr/bin/env sh
                    printf '%s\n' "fake docker invoked $*"
                    printf '%s\n' "fake docker stderr" >&2
                    exit {{exitCode}}
                    """);

#pragma warning disable CA1416
                File.SetUnixFileMode(
                    dockerPath,
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
            DirectoryInfo? current = new(AppContext.BaseDirectory);
            while (current is not null)
            {
                string candidate = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicNetworkSimulatorScenario.ps1");
                if (File.Exists(candidate))
                {
                    return candidate;
                }

                current = current.Parent;
            }

            throw new InvalidOperationException("Unable to locate scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1.");
        }
    }

    private sealed record ScriptRunResult(int ExitCode, string Stdout, string Stderr)
    {
        public string CombinedOutput => $"{Stdout}{Environment.NewLine}{Stderr}";
    }
}

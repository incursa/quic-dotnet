using System.Diagnostics;
using System.Text.Json;

namespace Incursa.Quic.Tests;

public sealed class InteropRunnerScriptFailureSummaryTests
{
    [Fact]
    public async Task RunnerExitNonZeroAfterValidOutputsReportsFailureSummaryAndPreservesStderrLog()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-valid-outputs");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot);

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Reason: the runner exited non-zero after producing the expected outputs.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner stderr:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Evidence was preserved in the run root for post-failure inspection.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");
        string runnerLogPath = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories).Single();
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string inventoryJsonPath = Path.Combine(runRoot, "testcase-inventory.json");

        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(Path.Combine(runRoot, "docker-build.log")));
        Assert.True(File.Exists(inventoryJsonPath));
        Assert.True(File.Exists(runnerJsonPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogsPath));
        Assert.Contains("InventoryJson:", File.ReadAllText(invocationPath), StringComparison.OrdinalIgnoreCase);

        Assert.Equal("{\"mode\":\"non-zero-valid-outputs\"}", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains(
            "fake-runner sentinel non-zero-valid-outputs",
            File.ReadAllText(runnerMarkdownPath),
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Unable to create certificates",
            File.ReadAllText(runnerStdErrPath),
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "fake-runner mode=non-zero-valid-outputs",
            File.ReadAllText(runnerLogPath),
            StringComparison.OrdinalIgnoreCase);

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("testcase-inventory.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-logs", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroWithXquicAckConsumptionCandidateReportsDiagnosticButRemainsFailed()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-xquic-ack-consumption-candidate");
        File.WriteAllText(
            Path.Combine(fixture.RunnerRoot, "implementations_quic.json"),
            """
            {
              "chrome": { "role": "client" },
              "xquic": { "role": "server" }
            }
            """);

        ScriptRunResult result = await fixture.RunAsync(
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
            "xquic",
            "-TestCases",
            "transfer");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Reason: the runner exited non-zero after producing the expected outputs.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "xquic server log shows only early Application Data ACK processing",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "response burst reaching packet 22",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "pacing blocked at stream_offset:16536",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "managed client emitted valid post-burst ACKs",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "only records client short-header packet processing through packets 0..3",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("post-burst ACK consumption", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("xquic event-loop packet processing", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "xquic_chrome", "transfer", "output.txt")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "xquic_chrome", "transfer", "server", "server.log")));
    }

    [Theory]
    [InlineData("keyupdate")]
    [InlineData("chacha20")]
    public async Task RunnerExitNonZeroWithXquicSharedCeilingCandidateReportsSharedCeilingWhenServerMarkersAreAbsent(string testCase)
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-xquic-shared-ceiling-candidate");
        File.WriteAllText(
            Path.Combine(fixture.RunnerRoot, "implementations_quic.json"),
            """
            {
              "chrome": { "role": "client" },
              "xquic": { "role": "server" }
            }
            """);

        ScriptRunResult result = await fixture.RunAsync(
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
            "xquic",
            "-TestCases",
            testCase);

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("shared xquic non-handshake ceiling at 15,355 bytes", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "xquic_chrome", testCase, "output.txt")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "xquic_chrome", testCase, "server", "server.log")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterValidOutputsAcceptsDocumentedInventoryCellsAndRecordsThem()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-valid-outputs");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "versionnegotiation");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Reason: the runner exited non-zero after producing the expected outputs.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner exit code: 7", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string inventoryJsonPath = Path.Combine(runRoot, "testcase-inventory.json");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");

        Assert.True(File.Exists(inventoryJsonPath));
        Assert.Contains("testcase-inventory.json", File.ReadAllText(artifactTreePath), StringComparison.OrdinalIgnoreCase);

        using JsonDocument inventoryDocument = JsonDocument.Parse(File.ReadAllText(inventoryJsonPath));
        JsonElement requestedEntry = inventoryDocument.RootElement
            .GetProperty("inventory")
            .EnumerateArray()
            .Single(item => string.Equals(
                item.GetProperty("testcase").GetString(),
                "versionnegotiation",
                StringComparison.OrdinalIgnoreCase));

        Assert.Equal("supported-executed", requestedEntry.GetProperty("classification").GetString());
        Assert.True(requestedEntry.GetProperty("requested").GetBoolean());
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterValidOutputsAcceptsPeerAliasSlotsAndRecordsThem()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-valid-outputs");
        File.WriteAllText(
            Path.Combine(fixture.RunnerRoot, "implementations_quic.json"),
            """
            {
              "nginx": { "role": "server" },
              "neqo": { "role": "both" }
            }
            """);

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "neqo-peer",
            "-TestCases",
            "connectionmigration");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Peer implementation slot 'neqo-peer' was not found", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("requires the local replacement slot 'nginx' to differ", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string invocationText = File.ReadAllText(Path.Combine(runRoot, "invocation.txt"));
        string[] runnerArgs = GetInvocationRunnerArgs(invocationText);
        int serverIndex = Array.FindIndex(runnerArgs, arg => string.Equals(arg, "-s", StringComparison.Ordinal));
        int clientIndex = Array.FindIndex(runnerArgs, arg => string.Equals(arg, "-c", StringComparison.Ordinal));
        int replacementIndex = Array.FindIndex(runnerArgs, arg => string.Equals(arg, "-r", StringComparison.Ordinal));

        Assert.Equal("nginx", GetInvocationFieldValue(invocationText, "LocalImplementationSlot"));
        Assert.Equal("neqo-peer", GetInvocationFieldValue(invocationText, "PeerImplementationSlots"));
        Assert.True(serverIndex >= 0);
        Assert.Equal("nginx", runnerArgs[serverIndex + 1]);
        Assert.True(clientIndex >= 0);
        Assert.Equal("neqo", runnerArgs[clientIndex + 1]);
        Assert.True(replacementIndex >= 0);
        Assert.Equal("nginx=incursa-quic-interop-harness:local", runnerArgs[replacementIndex + 1]);
        Assert.DoesNotContain("neqo-peer", runnerArgs, StringComparer.Ordinal);
    }

    [Fact]
    public async Task SplitRolePeerAliasResolvingToLocalReplacementSlotIsRejectedBeforeBuildWorkBegins()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("non-zero-valid-outputs");
        File.WriteAllText(
            Path.Combine(fixture.RunnerRoot, "implementations_quic.json"),
            """
            {
              "neqo": { "role": "both" }
            }
            """);

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "neqo",
            "-PeerImplementationSlots",
            "neqo-peer",
            "-TestCases",
            "connectionmigration");

        string output = result.CombinedOutput;

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "requires the local replacement slot 'neqo' to differ from the resolved peer implementation slot 'neqo' (peer slot 'neqo-peer')",
            result.ExceptionMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundHandshakeServerSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        // Provenance: artifacts\interop-runner\20260422-134852409-server-nginx showed a completed
        // managed handshake response with both endpoints exiting cleanly before the external
        // runner's FileNotFoundError post-check failed.
        fixture.WriteRunnerScript("file-not-found-handshake-server-success");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "quic-go",
            "-TestCases",
            "handshake");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "completed managed handshake response and clean client/server exits",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner.stderr.log")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_nginx", "handshake", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundHandshakeServerWithoutCleanClientExitStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-handshake-server-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "quic-go",
            "-TestCases",
            "handshake");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain a completed managed handshake response with clean client/server exits",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundTransferClientSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-transfer-client-success");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "transfer");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "completed managed downloads for every transfer request and a clean local client exit",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner.stderr.log")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_chrome", "transfer", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundTransferServerSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        // Provenance: artifacts\interop-runner\20260422-141028552-server-nginx showed the
        // managed server completing all transfer responses with both endpoints exiting cleanly
        // before the external runner's FileNotFoundError post-check failed.
        fixture.WriteRunnerScript("file-not-found-transfer-server-success");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "quic-go",
            "-TestCases",
            "transfer");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "completed managed transfer responses with clean client/server exits",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner.stderr.log")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_nginx", "transfer", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundTransferClientWithoutAllCompletedDownloadsStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-transfer-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "transfer");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain completed managed downloads for every transfer request with a clean local client exit",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundTransferServerWithoutCleanClientExitStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-transfer-server-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "chrome",
            "-TestCases",
            "transfer");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain completed managed transfer responses with clean client/server exits",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundMulticonnectClientSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-multiconnect-client-success");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "multiconnect");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exit code: 7", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "completed managed downloads for every multiconnect request and a clean local client exit",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner.stderr.log")));
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_chrome", "handshakeloss", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundMulticonnectClientWithoutAllCompletedDownloadsStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-multiconnect-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "multiconnect");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain completed managed downloads for every multiconnect request with a clean local client exit",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundMulticonnectServerRoleStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-multiconnect-client-success");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "chrome",
            "-TestCases",
            "multiconnect");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "multiconnect fallback classification is only enabled for the client-role testcase",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundKeyUpdateClientSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-keyupdate-client-success");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "keyupdate");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("managed keyupdate download", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("one-RTT key-update initiation/observation marker", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_chrome", "keyupdate", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundKeyUpdateClientWithoutInitiationStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-keyupdate-client-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "keyupdate");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain a managed keyupdate download with a one-RTT key-update initiation/observation marker",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundKeyUpdateServerSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-keyupdate-server-success");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "quic-go",
            "-TestCases",
            "keyupdate");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("managed keyupdate responses with clean client/server exits", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_nginx", "keyupdate", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundResumptionClientSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-resumption-client-success");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "resumption");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("resumption ticket capture", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("accepted resumed connection evidence", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_chrome", "resumption", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundResumptionClientWithoutAcceptedResumeStillFails()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-resumption-client-incomplete");

        ScriptRunResult result = await fixture.RunAsync(
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
            "quic-go",
            "-TestCases",
            "resumption");

        string output = result.CombinedOutput;

        Assert.Equal(7, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "did not contain resumption ticket capture, accepted resumed connection evidence",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitNonZeroAfterFileNotFoundResumptionServerSuccessTreatsTheRunAsAdvisorySuccess()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("file-not-found-resumption-server-success");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "server",
            "-ImplementationSlot",
            "nginx",
            "-PeerImplementationSlots",
            "quic-go",
            "-TestCases",
            "resumption");

        string output = result.CombinedOutput;

        Assert.Equal(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Interop runner helper complete.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Advisory:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("accepted first and resumed connections", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("managed resumption responses", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        Assert.True(File.Exists(Path.Combine(runRoot, "runner-logs", "quic-go_nginx", "resumption", "output.txt")));
    }

    [Fact]
    public async Task RunnerExitZeroAfterValidOutputsButMissingRunnerStderrLogReportsFailureSummary()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("missing-stderr-log");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot);

        string output = result.CombinedOutput;

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");
        string runnerLogPath = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories).Single();

        AssertFailureSummary(
            output,
            runRoot,
            invocationPath,
            artifactTreePath,
            runnerStdErrPath,
            expectedRunnerExitCode: 0,
            expectedReason: "the runner did not produce the expected JSON, Markdown, or log outputs.",
            expectedMissingOutputLine: $"Missing outputs: runner stderr log at '{runnerStdErrPath}'");

        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(runnerJsonPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.False(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogsPath));

        Assert.Equal("{\"mode\":\"success\"}", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains("fake-runner sentinel success", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake-runner mode=success", File.ReadAllText(runnerLogPath), StringComparison.OrdinalIgnoreCase);

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("invocation.txt", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-logs", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunnerExitZeroAfterValidOutputsButMissingRunnerLogsDirectoryReportsFailureSummary()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteRunnerScript("missing-runner-logs-dir");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot);

        string output = result.CombinedOutput;

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        AssertFailureSummary(
            output,
            runRoot,
            invocationPath,
            artifactTreePath,
            runnerStdErrPath,
            expectedRunnerExitCode: 0,
            expectedReason: "the runner did not produce the expected JSON, Markdown, or log outputs.",
            expectedMissingOutputLine: $"Missing outputs: runner log directory at '{runnerLogsPath}'");

        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(runnerJsonPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.False(Directory.Exists(runnerLogsPath));

        Assert.Equal("{\"mode\":\"success\"}", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains("fake-runner sentinel success", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, new FileInfo(runnerStdErrPath).Length);

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("invocation.txt", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-logs", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DockerBuildFailureBeforeRunnerLaunchLeavesRunnerStderrMissingButExplainsTheBuildFailure()
    {
        using InteropRunnerScriptFixture fixture = new();
        fixture.WriteDockerfile("# fake-docker: fail-before-runner");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot);

        string output = result.CombinedOutput;

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));
        Assert.Contains("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Reason: docker build failed with exit code 19.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner stderr:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Evidence was preserved in the run root for post-failure inspection.", output, StringComparison.OrdinalIgnoreCase);

        string runRoot = GetSingleRunRoot(fixture.ArtifactsRoot);
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");

        Assert.True(File.Exists(Path.Combine(runRoot, "invocation.txt")));
        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(artifactTreePath));
        Assert.False(File.Exists(runnerStdErrPath));
        Assert.False(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.False(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.False(Directory.Exists(Path.Combine(runRoot, "runner-logs")));

        Assert.Contains(
            "fake docker build failed before runner launch",
            File.ReadAllText(dockerBuildLogPath),
            StringComparison.OrdinalIgnoreCase);

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-report.json", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    private static string GetSingleRunRoot(string artifactsRoot)
    {
        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);
        return runRoots[0];
    }

    private static string GetInvocationFieldValue(string invocationText, string fieldName)
    {
        string prefix = $"{fieldName}:";
        foreach (string line in GetLines(invocationText))
        {
            if (line.StartsWith(prefix, StringComparison.Ordinal))
            {
                return line.Substring(prefix.Length).Trim();
            }
        }

        throw new InvalidOperationException($"Invocation summary did not contain a '{fieldName}' field.");
    }

    private static string[] GetInvocationRunnerArgs(string invocationText)
    {
        string[] lines = GetLines(invocationText);
        int runnerArgsIndex = Array.FindIndex(lines, line => string.Equals(line, "RunnerArgs:", StringComparison.Ordinal));
        if (runnerArgsIndex < 0)
        {
            throw new InvalidOperationException("Invocation summary did not contain a RunnerArgs section.");
        }

        List<string> runnerArgs = new();
        for (int index = runnerArgsIndex + 1; index < lines.Length; index++)
        {
            string line = lines[index];
            if (string.IsNullOrWhiteSpace(line))
            {
                break;
            }

            if (!line.StartsWith("  ", StringComparison.Ordinal))
            {
                break;
            }

            runnerArgs.Add(line.Trim());
        }

        return runnerArgs.ToArray();
    }

    private static string[] GetLines(string text)
    {
        return text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
    }

    private static void AssertFailureSummary(
        string output,
        string runRoot,
        string invocationPath,
        string artifactTreePath,
        string runnerStdErrPath,
        int expectedRunnerExitCode,
        string expectedReason,
        string expectedMissingOutputLine)
    {
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Reason: {expectedReason}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Runner exit code: {expectedRunnerExitCode}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Run root:        {runRoot}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Invocation log:  {invocationPath}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Artifact tree:   {artifactTreePath}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"Runner stderr:   {runnerStdErrPath}", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(expectedMissingOutputLine, output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Output issues:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Evidence was preserved in the run root for post-failure inspection.", output, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class InteropRunnerScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-interop-runner-script-failure-summary");
        private readonly string powerShellExecutable;

        public InteropRunnerScriptFixture()
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-interop-runner");
            ArtifactsRoot = Path.Combine(workspaceRoot, "artifacts", "interop-runner");
            string toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness"));
            Directory.CreateDirectory(RunnerRoot);
            Directory.CreateDirectory(toolRoot);

            WriteDockerfile("FROM scratch");
            WriteRunnerScript("non-zero-valid-outputs");
            WriteRunnerRegistry();
            CreateCommandStubs(toolRoot);

            ToolRoot = toolRoot;
            powerShellExecutable = ResolvePowerShellExecutable();
            ScriptPath = FindScriptPath();
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public string ScriptPath { get; }

        public string ToolRoot { get; }

        public void WriteRunnerScript(string mode)
        {
            File.WriteAllText(Path.Combine(RunnerRoot, "run.py"), BuildRunnerScriptContent(mode));
        }

        public void WriteDockerfile(string contents)
        {
            File.WriteAllText(Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness", "Dockerfile"), contents);
        }

        public async Task<ScriptRunResult> RunAsync(params object?[] arguments)
        {
            ProcessStartInfo startInfo = new(powerShellExecutable)
            {
                WorkingDirectory = RepoRoot,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            string wrapperPath = Path.Combine(tempDirectoryFixture.RootDirectory, $"invoke-helper-wrapper-{Guid.NewGuid():N}.ps1");
            string exceptionMessagePath = Path.Combine(tempDirectoryFixture.RootDirectory, $"invoke-helper-exception-{Guid.NewGuid():N}.txt");
            File.WriteAllText(wrapperPath, BuildCommandText(ScriptPath, exceptionMessagePath, arguments));

            startInfo.ArgumentList.Add("-NoProfile");
            startInfo.ArgumentList.Add("-NonInteractive");
            startInfo.ArgumentList.Add("-ExecutionPolicy");
            startInfo.ArgumentList.Add("Bypass");
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(wrapperPath);

            string existingPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            startInfo.Environment["PATH"] = $"{ToolRoot}{Path.PathSeparator}{existingPath}";

            using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start the interop runner helper script.");
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

                throw new TimeoutException($"The interop runner helper script did not exit within 30 seconds.\nSTDOUT:\n{await stdoutTask.ConfigureAwait(false)}\nSTDERR:\n{await stderrTask.ConfigureAwait(false)}");
            }

            await exitTask.ConfigureAwait(false);
            string stdout = await stdoutTask.ConfigureAwait(false);
            string stderr = await stderrTask.ConfigureAwait(false);
            string exceptionMessage = File.Exists(exceptionMessagePath)
                ? File.ReadAllText(exceptionMessagePath).Trim()
                : string.Empty;

            return new ScriptRunResult(process.ExitCode, stdout, stderr, exceptionMessage);
        }

        public void Dispose()
        {
            tempDirectoryFixture.Dispose();
        }

        private void WriteRunnerRegistry()
        {
            File.WriteAllText(
                Path.Combine(RunnerRoot, "implementations_quic.json"),
                """
                {
                  "chrome": { "role": "client" },
                  "quic-go": { "role": "both" },
                  "msquic": { "role": "server" },
                  "nginx": { "role": "server" }
                }
                """);
        }

        private static void CreateCommandStubs(string toolRoot)
        {
            if (OperatingSystem.IsWindows())
            {
                CreateWindowsStub(Path.Combine(toolRoot, "docker.cmd"), GetDockerStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "python.cmd"), GetPythonStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "python3.cmd"), GetPythonStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "py.cmd"), GetPythonStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "tshark.cmd"), GetNoOpWindowsStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "editcap.cmd"), GetNoOpWindowsStubContent());
            }
            else
            {
                CreateUnixStub(Path.Combine(toolRoot, "docker"), GetDockerStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "python"), GetPythonStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "python3"), GetPythonStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "py"), GetPythonStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "tshark"), GetNoOpUnixStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "editcap"), GetNoOpUnixStubContent());
            }
        }

        private static void CreateWindowsStub(string path, string content)
        {
            File.WriteAllText(path, content);
        }

        private static void CreateUnixStub(string path, string content)
        {
            File.WriteAllText(path, content);

#pragma warning disable CA1416
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
        }

        private static string BuildRunnerScriptContent(string mode)
        {
            return $"# fake-runner: {mode}{Environment.NewLine}";
        }

        private static string GetDockerStubContent()
        {
            if (OperatingSystem.IsWindows())
            {
                return """
                @echo off
                setlocal
                set "dockerfile="

                :parse_args
                if "%~1"=="" goto parsed_args
                if /I "%~1"=="--file" (
                  set "dockerfile=%~2"
                  shift
                  shift
                  goto parse_args
                )
                shift
                goto parse_args

                :parsed_args
                if not defined dockerfile (
                  echo Fake docker did not receive a Dockerfile path. 1>&2
                  exit /b 2
                )

                findstr /c:"# fake-docker: fail-before-runner" "%dockerfile%" >nul
                if not errorlevel 1 (
                  echo fake docker build failed before runner launch 1>&2
                  exit /b 19
                )

                echo fake docker build
                exit /b 0
                """;
            }

            return """
            #!/usr/bin/env sh
            set -eu

            dockerfile=
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    --file)
                        dockerfile=$2
                        shift 2
                        ;;
                    *)
                        shift
                        ;;
                esac
            done

            if [ -z "$dockerfile" ]; then
                printf '%s\n' 'Fake docker did not receive a Dockerfile path.' >&2
                exit 2
            fi

            if grep -q '# fake-docker: fail-before-runner' "$dockerfile"; then
                printf '%s\n' 'fake docker build failed before runner launch' >&2
                exit 19
            fi

            printf '%s\n' 'fake docker build'
            exit 0
            """;
        }

        private static string GetNoOpWindowsStubContent()
        {
            return """
            @echo off
            exit /b 0
            """;
        }

        private static string GetNoOpUnixStubContent()
        {
            return """
            #!/bin/sh
            exit 0
            """;
        }

        private static string GetPythonStubContent()
        {
            if (OperatingSystem.IsWindows())
            {
                return """
                @echo off
                setlocal
                set "mode=success"

                findstr /c:"# fake-runner: non-zero-valid-outputs" run.py >nul && set "mode=non-zero-valid-outputs"
                findstr /c:"# fake-runner: non-zero-xquic-ack-consumption-candidate" run.py >nul && set "mode=non-zero-xquic-ack-consumption-candidate"
                findstr /c:"# fake-runner: non-zero-xquic-shared-ceiling-candidate" run.py >nul && set "mode=non-zero-xquic-shared-ceiling-candidate"
                findstr /c:"# fake-runner: file-not-found-handshake-server-success" run.py >nul && set "mode=file-not-found-handshake-server-success"
                findstr /c:"# fake-runner: file-not-found-handshake-server-incomplete" run.py >nul && set "mode=file-not-found-handshake-server-incomplete"
                findstr /c:"# fake-runner: file-not-found-transfer-client-success" run.py >nul && set "mode=file-not-found-transfer-client-success"
                findstr /c:"# fake-runner: file-not-found-transfer-server-success" run.py >nul && set "mode=file-not-found-transfer-server-success"
                findstr /c:"# fake-runner: file-not-found-transfer-server-incomplete" run.py >nul && set "mode=file-not-found-transfer-server-incomplete"
                findstr /c:"# fake-runner: file-not-found-transfer-incomplete" run.py >nul && set "mode=file-not-found-transfer-incomplete"
                findstr /c:"# fake-runner: file-not-found-multiconnect-client-success" run.py >nul && set "mode=file-not-found-multiconnect-client-success"
                findstr /c:"# fake-runner: file-not-found-multiconnect-incomplete" run.py >nul && set "mode=file-not-found-multiconnect-incomplete"
                findstr /c:"# fake-runner: file-not-found-keyupdate-client-success" run.py >nul && set "mode=file-not-found-keyupdate-client-success"
                findstr /c:"# fake-runner: file-not-found-keyupdate-client-incomplete" run.py >nul && set "mode=file-not-found-keyupdate-client-incomplete"
                findstr /c:"# fake-runner: file-not-found-keyupdate-server-success" run.py >nul && set "mode=file-not-found-keyupdate-server-success"
                findstr /c:"# fake-runner: file-not-found-resumption-client-success" run.py >nul && set "mode=file-not-found-resumption-client-success"
                findstr /c:"# fake-runner: file-not-found-resumption-client-incomplete" run.py >nul && set "mode=file-not-found-resumption-client-incomplete"
                findstr /c:"# fake-runner: file-not-found-resumption-server-success" run.py >nul && set "mode=file-not-found-resumption-server-success"

                set "jsonPath="
                set "logsDir="

                :parse_args
                if "%~1"=="" goto parsed_args
                if /I "%~1"=="-j" (
                  set "jsonPath=%~2"
                  shift
                  shift
                  goto parse_args
                )
                if /I "%~1"=="-l" (
                  set "logsDir=%~2"
                  shift
                  shift
                  goto parse_args
                )
                shift
                goto parse_args

                :parsed_args
                if not defined logsDir (
                  echo Fake runner did not receive a log directory. 1>&2
                  exit /b 2
                )

                if not exist "%logsDir%" md "%logsDir%" >nul 2>&1

                if /I "%mode%"=="non-zero-valid-outputs" (
                  echo fake-runner sentinel non-zero-valid-outputs
                  if not defined jsonPath exit /b 2
                  > "%jsonPath%" echo {"mode":"non-zero-valid-outputs"}
                  > "%logsDir%\fake-runner.log" echo fake-runner mode=non-zero-valid-outputs
                  echo Unable to create certificates 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="non-zero-xquic-ack-consumption-candidate" (
                  echo fake-runner sentinel non-zero-xquic-ack-consumption-candidate
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\xquic_chrome\transfer\server" md "%logsDir%\xquic_chrome\transfer\server" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"non-zero-xquic-ack-consumption-candidate"}
                  > "%logsDir%\xquic_chrome\transfer\output.txt" (
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 timed out waiting for response-stream FIN after 15355 bytes.
                  )
                  > "%logsDir%\xquic_chrome\transfer\server\server.log" (
                    echo xqc_send_ctl_on_ack_received^|now:0^|pns:2^|frame_largest_ack:1^|path_largest_ack:1^|
                    echo xqc_send_packet_with_pn^|pkt_num:17^|pkt_type:SHORT_HEADER^|frame:STREAM ^|stream_offset:14174^|
                    echo xqc_send_packet_with_pn^|pkt_num:22^|pkt_type:SHORT_HEADER^|frame:STREAM ^|stream_offset:15355^|
                    echo xqc_conn_on_pkt_processed^|size:65^|pkt_type:SHORT_HEADER^|pkt_num:2^|frame:PADDING STREAM ^|
                    echo xqc_conn_on_pkt_processed^|size:53^|pkt_type:SHORT_HEADER^|pkt_num:3^|frame:PADDING ACK ^|
                    echo xqc_send_ctl_get_pto_time_and_space^|PNS: 2, unacked: 15000^|
                    echo xqc_send_packet_pacer_allows^|pacing blocked^|stream_offset:16536^|
                  )
                  echo transfer timeout 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="non-zero-xquic-shared-ceiling-candidate" (
                  echo fake-runner sentinel non-zero-xquic-shared-ceiling-candidate
                  if not defined jsonPath exit /b 2
                  > "%jsonPath%" echo {"mode":"non-zero-xquic-shared-ceiling-candidate"}
                  for %%T in (keyupdate chacha20) do (
                    if not exist "%logsDir%\xquic_chrome\%%T\server" md "%logsDir%\xquic_chrome\%%T\server" >nul 2>&1
                    > "%logsDir%\xquic_chrome\%%T\output.txt" (
                      echo client ^| interop harness: role=client, testcase=%%T, requestCount=1 timed out waiting for response-stream FIN after reading 15355 bytes.
                    )
                    > "%logsDir%\xquic_chrome\%%T\server\server.log" (
                      echo xqc_hq_parse_req^|259^|^|hq recv CR LF^|
                    )
                  )
                  echo shared ceiling timeout 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-handshake-server-success" (
                  echo fake-runner sentinel file-not-found-handshake-server-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\handshake" md "%logsDir%\quic-go_nginx\handshake" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-handshake-server-success"}
                  > "%logsDir%\quic-go_nginx\handshake\output.txt" (
                    echo server ^| interop harness: role=server, testcase=handshake, requestCount=0 completed managed handshake response from /www/temperate-surprised-zip for target=temperate-surprised-zip, bytes=1024, stream 1.
                    echo client exited with code 0
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-handshake-server-incomplete" (
                  echo fake-runner sentinel file-not-found-handshake-server-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\handshake" md "%logsDir%\quic-go_nginx\handshake" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-handshake-server-incomplete"}
                  > "%logsDir%\quic-go_nginx\handshake\output.txt" (
                    echo server ^| interop harness: role=server, testcase=handshake, requestCount=0 completed managed handshake response from /www/temperate-surprised-zip for target=temperate-surprised-zip, bytes=1024, stream 1.
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-transfer-client-success" (
                  echo fake-runner sentinel file-not-found-transfer-client-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\transfer" md "%logsDir%\quic-go_chrome\transfer" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-transfer-client-success"}
                  > "%logsDir%\quic-go_chrome\transfer\output.txt" (
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, stream 1/3.
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, stream 2/3.
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/envious-mild-warlock from /envious-mild-warlock, bytes=5242880, stream 3/3.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-transfer-server-success" (
                  echo fake-runner sentinel file-not-found-transfer-server-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\transfer" md "%logsDir%\quic-go_nginx\transfer" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-transfer-server-success"}
                  > "%logsDir%\quic-go_nginx\transfer\output.txt" (
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/savory-thin-bluetooth for target=savory-thin-bluetooth, bytes=5242880, stream 1.
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/dull-jubilant-otter for target=dull-jubilant-otter, bytes=2097152, stream 2.
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/quiet-copious-assassin for target=quiet-copious-assassin, bytes=3145728, stream 3.
                    echo client exited with code 0
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-transfer-server-incomplete" (
                  echo fake-runner sentinel file-not-found-transfer-server-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\transfer" md "%logsDir%\quic-go_nginx\transfer" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-transfer-server-incomplete"}
                  > "%logsDir%\quic-go_nginx\transfer\output.txt" (
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/savory-thin-bluetooth for target=savory-thin-bluetooth, bytes=5242880, stream 1.
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/dull-jubilant-otter for target=dull-jubilant-otter, bytes=2097152, stream 2.
                    echo server ^| interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/quiet-copious-assassin for target=quiet-copious-assassin, bytes=3145728, stream 3.
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-transfer-incomplete" (
                  echo fake-runner sentinel file-not-found-transfer-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\transfer" md "%logsDir%\quic-go_chrome\transfer" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-transfer-incomplete"}
                  > "%logsDir%\quic-go_chrome\transfer\output.txt" (
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, stream 1/3.
                    echo client ^| interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, stream 2/3.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-multiconnect-client-success" (
                  echo fake-runner sentinel file-not-found-multiconnect-client-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\handshakeloss" md "%logsDir%\quic-go_chrome\handshakeloss" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-multiconnect-client-success"}
                  > "%logsDir%\quic-go_chrome\handshakeloss\output.txt" (
                    echo client ^| interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, connection 1/3.
                    echo client ^| interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, connection 2/3.
                    echo client ^| interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/envious-mild-warlock from /envious-mild-warlock, bytes=5242880, connection 3/3.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-multiconnect-incomplete" (
                  echo fake-runner sentinel file-not-found-multiconnect-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\handshakeloss" md "%logsDir%\quic-go_chrome\handshakeloss" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-multiconnect-incomplete"}
                  > "%logsDir%\quic-go_chrome\handshakeloss\output.txt" (
                    echo client ^| interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, connection 1/3.
                    echo client ^| interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, connection 2/3.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-keyupdate-client-success" (
                  echo fake-runner sentinel file-not-found-keyupdate-client-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\keyupdate" md "%logsDir%\quic-go_chrome\keyupdate" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-keyupdate-client-success"}
                  > "%logsDir%\quic-go_chrome\keyupdate\output.txt" (
                    echo client ^| interop harness: role=client, testcase=keyupdate, requestCount=1 initiated one-RTT key update after 1048576 bytes transferred.
                    echo client ^| interop harness: role=client, testcase=keyupdate, requestCount=1 completed managed keyupdate download to /downloads/brisk-keyupdate from /brisk-keyupdate, bytes=1500000, stream 1/1.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-keyupdate-client-incomplete" (
                  echo fake-runner sentinel file-not-found-keyupdate-client-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\keyupdate" md "%logsDir%\quic-go_chrome\keyupdate" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-keyupdate-client-incomplete"}
                  > "%logsDir%\quic-go_chrome\keyupdate\output.txt" (
                    echo client ^| interop harness: role=client, testcase=keyupdate, requestCount=1 completed managed keyupdate download to /downloads/brisk-keyupdate from /brisk-keyupdate, bytes=1500000, stream 1/1.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-keyupdate-server-success" (
                  echo fake-runner sentinel file-not-found-keyupdate-server-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\keyupdate" md "%logsDir%\quic-go_nginx\keyupdate" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-keyupdate-server-success"}
                  > "%logsDir%\quic-go_nginx\keyupdate\output.txt" (
                    echo server ^| interop harness: role=server, testcase=keyupdate, requestCount=0 completed managed keyupdate response from /www/brisk-keyupdate for target=brisk-keyupdate, bytes=1500000, stream 1.
                    echo client exited with code 0
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-resumption-client-success" (
                  echo fake-runner sentinel file-not-found-resumption-client-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\resumption" md "%logsDir%\quic-go_chrome\resumption" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-resumption-client-success"}
                  > "%logsDir%\quic-go_chrome\resumption\output.txt" (
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/first from /first, bytes=1024, connection 1/2.
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 captured detached resumption ticket after connection 1/2.
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 established resumed connection 2/2 with disposition=Accepted.
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/second from /second, bytes=1024, connection 2/2.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-resumption-client-incomplete" (
                  echo fake-runner sentinel file-not-found-resumption-client-incomplete
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_chrome\resumption" md "%logsDir%\quic-go_chrome\resumption" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-resumption-client-incomplete"}
                  > "%logsDir%\quic-go_chrome\resumption\output.txt" (
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/first from /first, bytes=1024, connection 1/2.
                    echo client ^| interop harness: role=client, testcase=resumption, requestCount=2 captured detached resumption ticket after connection 1/2.
                    echo client exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                if /I "%mode%"=="file-not-found-resumption-server-success" (
                  echo fake-runner sentinel file-not-found-resumption-server-success
                  if not defined jsonPath exit /b 2
                  if not exist "%logsDir%\quic-go_nginx\resumption" md "%logsDir%\quic-go_nginx\resumption" >nul 2>&1
                  > "%jsonPath%" echo {"mode":"file-not-found-resumption-server-success"}
                  > "%logsDir%\quic-go_nginx\resumption\output.txt" (
                    echo server ^| interop harness: role=server, testcase=resumption, requestCount=2 accepted managed connection 1/2.
                    echo server ^| interop harness: role=server, testcase=resumption, requestCount=2 completed managed resumption response from /www/first for target=first, bytes=1024, stream 1.
                    echo server ^| interop harness: role=server, testcase=resumption, requestCount=2 accepted managed connection 2/2.
                    echo server ^| interop harness: role=server, testcase=resumption, requestCount=2 completed managed resumption response from /www/second for target=second, bytes=1024, stream 1.
                    echo client exited with code 0
                    echo server exited with code 0
                  )
                  echo testcase.check^(^) threw FileNotFoundError: [WinError 2] The system cannot find the file specified 1>&2
                  exit /b 7
                )

                echo fake-runner sentinel success
                if defined jsonPath (
                  > "%jsonPath%" echo {"mode":"success"}
                )
                > "%logsDir%\fake-runner.log" echo fake-runner mode=success
                exit /b 0
                """;
            }

            return """
            #!/usr/bin/env sh
            set -eu

            mode=success
            if grep -q '# fake-runner: non-zero-valid-outputs' run.py; then
                mode=non-zero-valid-outputs
            elif grep -q '# fake-runner: non-zero-xquic-ack-consumption-candidate' run.py; then
                mode=non-zero-xquic-ack-consumption-candidate
            elif grep -q '# fake-runner: non-zero-xquic-shared-ceiling-candidate' run.py; then
                mode=non-zero-xquic-shared-ceiling-candidate
            elif grep -q '# fake-runner: file-not-found-handshake-server-success' run.py; then
                mode=file-not-found-handshake-server-success
            elif grep -q '# fake-runner: file-not-found-handshake-server-incomplete' run.py; then
                mode=file-not-found-handshake-server-incomplete
            elif grep -q '# fake-runner: file-not-found-transfer-client-success' run.py; then
                mode=file-not-found-transfer-client-success
            elif grep -q '# fake-runner: file-not-found-transfer-server-success' run.py; then
                mode=file-not-found-transfer-server-success
            elif grep -q '# fake-runner: file-not-found-transfer-server-incomplete' run.py; then
                mode=file-not-found-transfer-server-incomplete
            elif grep -q '# fake-runner: file-not-found-transfer-incomplete' run.py; then
                mode=file-not-found-transfer-incomplete
            elif grep -q '# fake-runner: file-not-found-multiconnect-client-success' run.py; then
                mode=file-not-found-multiconnect-client-success
            elif grep -q '# fake-runner: file-not-found-multiconnect-incomplete' run.py; then
                mode=file-not-found-multiconnect-incomplete
            elif grep -q '# fake-runner: file-not-found-keyupdate-client-success' run.py; then
                mode=file-not-found-keyupdate-client-success
            elif grep -q '# fake-runner: file-not-found-keyupdate-client-incomplete' run.py; then
                mode=file-not-found-keyupdate-client-incomplete
            elif grep -q '# fake-runner: file-not-found-keyupdate-server-success' run.py; then
                mode=file-not-found-keyupdate-server-success
            elif grep -q '# fake-runner: file-not-found-resumption-client-success' run.py; then
                mode=file-not-found-resumption-client-success
            elif grep -q '# fake-runner: file-not-found-resumption-client-incomplete' run.py; then
                mode=file-not-found-resumption-client-incomplete
            elif grep -q '# fake-runner: file-not-found-resumption-server-success' run.py; then
                mode=file-not-found-resumption-server-success
            fi

            json_path=
            logs_dir=
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -j)
                        json_path=$2
                        shift 2
                        ;;
                    -l)
                        logs_dir=$2
                        shift 2
                        ;;
                    *)
                        shift
                        ;;
                esac
            done

            if [ -z "$logs_dir" ]; then
                printf '%s\n' 'Fake runner did not receive a log directory.' >&2
                exit 2
            fi

            mkdir -p "$logs_dir"

            if [ "$mode" = "non-zero-valid-outputs" ]; then
                printf '%s\n' 'fake-runner sentinel non-zero-valid-outputs'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                printf '%s\n' '{"mode":"non-zero-valid-outputs"}' > "$json_path"
                printf '%s\n' 'fake-runner mode=non-zero-valid-outputs' > "$logs_dir/fake-runner.log"
                printf '%s\n' 'Unable to create certificates' >&2
                exit 7
            fi

            if [ "$mode" = "non-zero-xquic-ack-consumption-candidate" ]; then
                printf '%s\n' 'fake-runner sentinel non-zero-xquic-ack-consumption-candidate'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/xquic_chrome/transfer/server"
                printf '%s\n' '{"mode":"non-zero-xquic-ack-consumption-candidate"}' > "$json_path"
                printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 timed out waiting for response-stream FIN after 15355 bytes.' > "$logs_dir/xquic_chrome/transfer/output.txt"
                {
                    printf '%s\n' 'xqc_send_ctl_on_ack_received|now:0|pns:2|frame_largest_ack:1|path_largest_ack:1|'
                    printf '%s\n' 'xqc_send_packet_with_pn|pkt_num:17|pkt_type:SHORT_HEADER|frame:STREAM |stream_offset:14174|'
                    printf '%s\n' 'xqc_send_packet_with_pn|pkt_num:22|pkt_type:SHORT_HEADER|frame:STREAM |stream_offset:15355|'
                    printf '%s\n' 'xqc_conn_on_pkt_processed|size:65|pkt_type:SHORT_HEADER|pkt_num:2|frame:PADDING STREAM |'
                    printf '%s\n' 'xqc_conn_on_pkt_processed|size:53|pkt_type:SHORT_HEADER|pkt_num:3|frame:PADDING ACK |'
                    printf '%s\n' 'xqc_send_ctl_get_pto_time_and_space|PNS: 2, unacked: 15000|'
                    printf '%s\n' 'xqc_send_packet_pacer_allows|pacing blocked|stream_offset:16536|'
                } > "$logs_dir/xquic_chrome/transfer/server/server.log"
                printf '%s\n' 'transfer timeout' >&2
                exit 7
            fi

            if [ "$mode" = "non-zero-xquic-shared-ceiling-candidate" ]; then
                printf '%s\n' 'fake-runner sentinel non-zero-xquic-shared-ceiling-candidate'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                printf '%s\n' '{"mode":"non-zero-xquic-shared-ceiling-candidate"}' > "$json_path"
                for testcase in keyupdate chacha20; do
                    mkdir -p "$logs_dir/xquic_chrome/$testcase/server"
                    printf '%s\n' "client | interop harness: role=client, testcase=$testcase, requestCount=1 timed out waiting for response-stream FIN after reading 15355 bytes." > "$logs_dir/xquic_chrome/$testcase/output.txt"
                    printf '%s\n' 'xqc_hq_parse_req|259||hq recv CR LF|' > "$logs_dir/xquic_chrome/$testcase/server/server.log"
                done
                printf '%s\n' 'shared ceiling timeout' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-handshake-server-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-handshake-server-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/handshake"
                printf '%s\n' '{"mode":"file-not-found-handshake-server-success"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=handshake, requestCount=0 completed managed handshake response from /www/temperate-surprised-zip for target=temperate-surprised-zip, bytes=1024, stream 1.'
                    printf '%s\n' 'client exited with code 0'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/handshake/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-handshake-server-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-handshake-server-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/handshake"
                printf '%s\n' '{"mode":"file-not-found-handshake-server-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=handshake, requestCount=0 completed managed handshake response from /www/temperate-surprised-zip for target=temperate-surprised-zip, bytes=1024, stream 1.'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/handshake/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-transfer-client-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-transfer-client-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/transfer"
                printf '%s\n' '{"mode":"file-not-found-transfer-client-success"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, stream 1/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, stream 2/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/envious-mild-warlock from /envious-mild-warlock, bytes=5242880, stream 3/3.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/transfer/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-transfer-server-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-transfer-server-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/transfer"
                printf '%s\n' '{"mode":"file-not-found-transfer-server-success"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/savory-thin-bluetooth for target=savory-thin-bluetooth, bytes=5242880, stream 1.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/dull-jubilant-otter for target=dull-jubilant-otter, bytes=2097152, stream 2.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/quiet-copious-assassin for target=quiet-copious-assassin, bytes=3145728, stream 3.'
                    printf '%s\n' 'client exited with code 0'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/transfer/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-transfer-server-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-transfer-server-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/transfer"
                printf '%s\n' '{"mode":"file-not-found-transfer-server-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/savory-thin-bluetooth for target=savory-thin-bluetooth, bytes=5242880, stream 1.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/dull-jubilant-otter for target=dull-jubilant-otter, bytes=2097152, stream 2.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=transfer, requestCount=0 completed managed transfer response from /www/quiet-copious-assassin for target=quiet-copious-assassin, bytes=3145728, stream 3.'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/transfer/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-transfer-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-transfer-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/transfer"
                printf '%s\n' '{"mode":"file-not-found-transfer-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, stream 1/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=transfer, requestCount=3 completed managed transfer download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, stream 2/3.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/transfer/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-multiconnect-client-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-multiconnect-client-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/handshakeloss"
                printf '%s\n' '{"mode":"file-not-found-multiconnect-client-success"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, connection 1/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, connection 2/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/envious-mild-warlock from /envious-mild-warlock, bytes=5242880, connection 3/3.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/handshakeloss/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-multiconnect-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-multiconnect-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/handshakeloss"
                printf '%s\n' '{"mode":"file-not-found-multiconnect-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/moderate-red-car from /moderate-red-car, bytes=2097152, connection 1/3.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=multiconnect, requestCount=3 completed managed multiconnect download to /downloads/zestful-aquamarine-hat from /zestful-aquamarine-hat, bytes=3145728, connection 2/3.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/handshakeloss/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-keyupdate-client-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-keyupdate-client-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/keyupdate"
                printf '%s\n' '{"mode":"file-not-found-keyupdate-client-success"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=keyupdate, requestCount=1 initiated one-RTT key update after 1048576 bytes transferred.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=keyupdate, requestCount=1 completed managed keyupdate download to /downloads/brisk-keyupdate from /brisk-keyupdate, bytes=1500000, stream 1/1.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/keyupdate/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-keyupdate-client-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-keyupdate-client-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/keyupdate"
                printf '%s\n' '{"mode":"file-not-found-keyupdate-client-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=keyupdate, requestCount=1 completed managed keyupdate download to /downloads/brisk-keyupdate from /brisk-keyupdate, bytes=1500000, stream 1/1.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/keyupdate/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-keyupdate-server-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-keyupdate-server-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/keyupdate"
                printf '%s\n' '{"mode":"file-not-found-keyupdate-server-success"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=keyupdate, requestCount=0 completed managed keyupdate response from /www/brisk-keyupdate for target=brisk-keyupdate, bytes=1500000, stream 1.'
                    printf '%s\n' 'client exited with code 0'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/keyupdate/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-resumption-client-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-resumption-client-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/resumption"
                printf '%s\n' '{"mode":"file-not-found-resumption-client-success"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/first from /first, bytes=1024, connection 1/2.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 captured detached resumption ticket after connection 1/2.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 established resumed connection 2/2 with disposition=Accepted.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/second from /second, bytes=1024, connection 2/2.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/resumption/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-resumption-client-incomplete" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-resumption-client-incomplete'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_chrome/resumption"
                printf '%s\n' '{"mode":"file-not-found-resumption-client-incomplete"}' > "$json_path"
                {
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 completed managed resumption download to /downloads/first from /first, bytes=1024, connection 1/2.'
                    printf '%s\n' 'client | interop harness: role=client, testcase=resumption, requestCount=2 captured detached resumption ticket after connection 1/2.'
                    printf '%s\n' 'client exited with code 0'
                } > "$logs_dir/quic-go_chrome/resumption/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            if [ "$mode" = "file-not-found-resumption-server-success" ]; then
                printf '%s\n' 'fake-runner sentinel file-not-found-resumption-server-success'
                if [ -z "$json_path" ]; then
                    exit 2
                fi
                mkdir -p "$logs_dir/quic-go_nginx/resumption"
                printf '%s\n' '{"mode":"file-not-found-resumption-server-success"}' > "$json_path"
                {
                    printf '%s\n' 'server | interop harness: role=server, testcase=resumption, requestCount=2 accepted managed connection 1/2.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=resumption, requestCount=2 completed managed resumption response from /www/first for target=first, bytes=1024, stream 1.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=resumption, requestCount=2 accepted managed connection 2/2.'
                    printf '%s\n' 'server | interop harness: role=server, testcase=resumption, requestCount=2 completed managed resumption response from /www/second for target=second, bytes=1024, stream 1.'
                    printf '%s\n' 'client exited with code 0'
                    printf '%s\n' 'server exited with code 0'
                } > "$logs_dir/quic-go_nginx/resumption/output.txt"
                printf '%s\n' 'testcase.check() threw FileNotFoundError: [WinError 2] The system cannot find the file specified' >&2
                exit 7
            fi

            printf '%s\n' 'fake-runner sentinel success'
            if [ -n "$json_path" ]; then
                printf '%s\n' '{"mode":"success"}' > "$json_path"
            fi
            printf '%s\n' 'fake-runner mode=success' > "$logs_dir/fake-runner.log"
            exit 0
            """;
        }

        private static string BuildCommandText(
            string scriptPath,
            string exceptionMessagePath,
            IReadOnlyList<object?> arguments)
        {
            if ((arguments.Count & 1) != 0)
            {
                throw new ArgumentException("Helper script arguments must be supplied as name/value pairs.", nameof(arguments));
            }

            string scriptParameters = string.Join(
                Environment.NewLine,
                Enumerable.Range(0, arguments.Count / 2)
                    .Select(index =>
                    {
                        string name = arguments[index * 2] as string ?? throw new ArgumentException("Helper script arguments must use non-empty parameter names.", nameof(arguments));
                        object? value = arguments[index * 2 + 1];
                        if (string.IsNullOrWhiteSpace(name))
                        {
                            throw new ArgumentException("Helper script arguments must use non-empty parameter names.", nameof(arguments));
                        }

                        return $"  {name.TrimStart('-')} = {FormatPowerShellValue(value)}";
                    }));

            return
                "$errorMessagePath = " + QuotePowerShellSingleQuoted(exceptionMessagePath) + "\n" +
                "$scriptParameters = @{\n" +
                scriptParameters +
                "\n}\n\n" +
                "try {\n" +
                "  & " + QuotePowerShellSingleQuoted(scriptPath) + " @scriptParameters\n" +
                "  if ($LASTEXITCODE -ne 0) {\n" +
                "    exit $LASTEXITCODE\n" +
                "  }\n" +
                "}\n" +
                "catch {\n" +
                "  $exceptionMessage = $_.Exception.Message\n" +
                "  Set-Content -LiteralPath $errorMessagePath -Value $exceptionMessage -Encoding utf8\n" +
                "  Write-Error -Message ('CAUGHT:' + $exceptionMessage)\n" +
                "  exit 1\n" +
                "}\n";
        }

        private static string FormatPowerShellValue(object? value)
        {
            return value switch
            {
                null => "$null",
                bool boolValue => boolValue ? "$true" : "$false",
                string stringValue => QuotePowerShellSingleQuoted(stringValue),
                _ => QuotePowerShellSingleQuoted(value.ToString() ?? string.Empty),
            };
        }

        private static string QuotePowerShellSingleQuoted(string value)
        {
            return $"'{value.Replace("'", "''")}'";
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

    private sealed record ScriptRunResult(int ExitCode, string Stdout, string Stderr, string ExceptionMessage)
    {
        public string CombinedOutput => $"{Stdout}{Environment.NewLine}{Stderr}";
    }
}

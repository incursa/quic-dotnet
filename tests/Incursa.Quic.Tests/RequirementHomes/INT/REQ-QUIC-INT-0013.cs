using System.Diagnostics;
using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0013")]
public sealed class REQ_QUIC_INT_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalHelperCapturesExpectedArtifactsForSameSlotBothRoleRuns()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "both",
            "-ImplementationSlot",
            "quic-go");

        await AssertSuccessfulHelperRunAsync(
            fixture.ArtifactsRoot,
            result,
            expectedLocalRole: "both",
            expectedLocalImplementationSlot: "quic-go",
            expectedPeerImplementationSlots: "quic-go,msquic",
            expectedRunnerServerImplementations: "quic-go",
            expectedRunnerClientImplementations: "quic-go",
            expectedReplacement: "quic-go=incursa-quic-interop-harness:local");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalHelperCapturesExpectedArtifactsForSplitClientRoleRunsAgainstServerPeers()
    {
        using InteropRunnerScriptFixture fixture = new();

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
            "msquic");

        await AssertSuccessfulHelperRunAsync(
            fixture.ArtifactsRoot,
            result,
            expectedLocalRole: "client",
            expectedLocalImplementationSlot: "chrome",
            expectedPeerImplementationSlots: "msquic",
            expectedRunnerServerImplementations: "msquic",
            expectedRunnerClientImplementations: "chrome",
            expectedReplacement: "chrome=incursa-quic-interop-harness:local");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalHelperCapturesExpectedArtifactsForSplitServerRoleRunsAgainstClientPeers()
    {
        using InteropRunnerScriptFixture fixture = new();

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
            "quic-go");

        await AssertSuccessfulHelperRunAsync(
            fixture.ArtifactsRoot,
            result,
            expectedLocalRole: "server",
            expectedLocalImplementationSlot: "nginx",
            expectedPeerImplementationSlots: "quic-go",
            expectedRunnerServerImplementations: "nginx",
            expectedRunnerClientImplementations: "quic-go",
            expectedReplacement: "nginx=incursa-quic-interop-harness:local");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HelperRejectsUnsupportedTestcasesBeforeBuildWorkBegins()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-TestCases",
            "handshake,unsupported");

        string output = result.CombinedOutput;
        string exceptionMessage = result.ExceptionMessage;

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "Requested testcase(s) unsupported are not part of the runner-recognized local subset for this helper.",
            exceptionMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SplitRoleModeRejectsAnEmptyPeerImplementationSlotList()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "client",
            "-PeerImplementationSlots",
            null!);

        string output = result.CombinedOutput;
        string exceptionMessage = result.ExceptionMessage;

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "PeerImplementationSlots must include at least one implementation when LocalRole is client or server.",
            exceptionMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientSplitModeDefaultsToChromeAndRejectsUsingThatSameSlotAsThePeerReplacement()
    {
        using InteropRunnerScriptFixture fixture = new();

        ScriptRunResult result = await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot,
            "-LocalRole",
            "client",
            "-PeerImplementationSlots",
            "chrome");

        string output = result.CombinedOutput;
        string exceptionMessage = result.ExceptionMessage;

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(exceptionMessage));
        Assert.Contains(
            "LocalRole 'client' requires the local replacement slot 'chrome' to differ from the peer implementation slot list.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        AssertPreservedFailureEvidence(fixture.ArtifactsRoot);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientSplitModeRejectsAPeerImplementationSlotWithAnIncompatibleRole()
    {
        using InteropRunnerScriptFixture fixture = new();

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
            "quic-go");

        string output = result.CombinedOutput;
        string exceptionMessage = result.ExceptionMessage;

        Assert.NotEqual(0, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(exceptionMessage));
        Assert.Contains(
            "Peer implementation slot 'quic-go' is role 'client' which is not compatible with LocalRole 'client'.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        AssertPreservedFailureEvidence(fixture.ArtifactsRoot);
    }

    private static async Task AssertSuccessfulHelperRunAsync(
        string artifactsRoot,
        ScriptRunResult result,
        string expectedLocalRole,
        string expectedLocalImplementationSlot,
        string expectedPeerImplementationSlots,
        string expectedRunnerServerImplementations,
        string expectedRunnerClientImplementations,
        string expectedReplacement,
        string expectedTestCases = "handshake,retry,transfer")
    {
        Assert.True(
            result.ExitCode == 0,
            $"Helper exit code was {result.ExitCode}.\nException message:\n{result.ExceptionMessage}\nSTDOUT:\n{result.Stdout}\nSTDERR:\n{result.Stderr}");
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));

        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);

        string runRoot = runRoots[0];
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerReportJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerReportMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogDir = Path.Combine(runRoot, "runner-logs");
        string runnerReceivedArgsPath = Path.Combine(runnerLogDir, "received-args.txt");

        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(artifactTreePath));
        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(runnerReportJsonPath));
        Assert.True(File.Exists(runnerReportMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogDir));
        Assert.True(File.Exists(runnerReceivedArgsPath));

        string invocationText = File.ReadAllText(invocationPath);
        string artifactTreeText = File.ReadAllText(artifactTreePath);
        string dockerBuildLogText = File.ReadAllText(dockerBuildLogPath);
        string runnerReportMarkdownText = File.ReadAllText(runnerReportMarkdownPath);
        string runnerStdErrText = File.ReadAllText(runnerStdErrPath);
        string[] runnerReceivedArgs = File.ReadAllLines(runnerReceivedArgsPath);

        Assert.Equal(expectedLocalRole, GetInvocationFieldValue(invocationText, "LocalRole"));
        Assert.Equal(expectedLocalImplementationSlot, GetInvocationFieldValue(invocationText, "LocalImplementationSlot"));
        Assert.Equal(expectedPeerImplementationSlots, GetInvocationFieldValue(invocationText, "PeerImplementationSlots"));
        Assert.Equal("incursa-quic-interop-harness:local", GetInvocationFieldValue(invocationText, "ImageTag"));

        string[] expectedRunnerArgs = CreateExpectedRunnerArgs(
            expectedRunnerServerImplementations,
            expectedRunnerClientImplementations,
            expectedReplacement,
            runnerLogDir,
            runnerReportJsonPath,
            expectedTestCases);

        Assert.Equal(expectedRunnerArgs, GetInvocationRunnerArgs(invocationText));
        Assert.Equal(expectedRunnerArgs, runnerReceivedArgs);

        using JsonDocument runnerReport = JsonDocument.Parse(File.ReadAllText(runnerReportJsonPath));
        JsonElement runnerReportRoot = runnerReport.RootElement;

        Assert.Equal(expectedRunnerServerImplementations, runnerReportRoot.GetProperty("serverImplementations").GetString());
        Assert.Equal(expectedRunnerClientImplementations, runnerReportRoot.GetProperty("clientImplementations").GetString());
        Assert.Equal(expectedReplacement, runnerReportRoot.GetProperty("replacement").GetString());
        Assert.Equal(expectedTestCases, runnerReportRoot.GetProperty("testcases").GetString());
        Assert.Equal(
            expectedRunnerArgs,
            runnerReportRoot.GetProperty("args").EnumerateArray().Select(element => element.GetString() ?? string.Empty).ToArray());

        Assert.Contains("# Fake runner report", runnerReportMarkdownText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"serverImplementations: {expectedRunnerServerImplementations}", runnerReportMarkdownText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"clientImplementations: {expectedRunnerClientImplementations}", runnerReportMarkdownText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"replacement: {expectedReplacement}", runnerReportMarkdownText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake runner stderr", runnerStdErrText, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("docker build", dockerBuildLogText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-logs", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("received-args.txt", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("invocation.txt", artifactTreeText, StringComparison.OrdinalIgnoreCase);
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

    private static string[] CreateExpectedRunnerArgs(
        string expectedRunnerServerImplementations,
        string expectedRunnerClientImplementations,
        string expectedReplacement,
        string expectedRunnerLogDir,
        string expectedRunnerJsonPath,
        string expectedTestCases)
    {
        return new[]
        {
            "-p",
            "quic",
            "-s",
            expectedRunnerServerImplementations,
            "-c",
            expectedRunnerClientImplementations,
            "-t",
            expectedTestCases,
            "-r",
            expectedReplacement,
            "-l",
            expectedRunnerLogDir,
            "-j",
            expectedRunnerJsonPath,
            "-m",
        };
    }

    private static string[] GetLines(string text)
    {
        return text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
    }

    private static void AssertPreservedFailureEvidence(string artifactsRoot)
    {
        Assert.True(Directory.Exists(artifactsRoot));

        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);

        string runRoot = runRoots[0];
        Assert.True(File.Exists(Path.Combine(runRoot, "invocation.txt")));
        Assert.True(File.Exists(Path.Combine(runRoot, "artifact-tree.txt")));
        Assert.False(File.Exists(Path.Combine(runRoot, "docker-build.log")));
        Assert.False(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.False(File.Exists(Path.Combine(runRoot, "runner-report.md")));
        Assert.False(File.Exists(Path.Combine(runRoot, "runner.stderr.log")));
        Assert.False(Directory.Exists(Path.Combine(runRoot, "runner-logs")));
    }

    private sealed class InteropRunnerScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-interop-runner-script");
        private readonly string powerShellExecutable;

        public InteropRunnerScriptFixture(string quicGoRole = "client")
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-interop-runner");
            ArtifactsRoot = Path.Combine(workspaceRoot, "artifacts", "interop-runner");
            string qlogDotnetRoot = Path.Combine(workspaceRoot, "incursa", "qlog-dotnet");
            string toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness"));
            Directory.CreateDirectory(qlogDotnetRoot);
            Directory.CreateDirectory(RunnerRoot);
            Directory.CreateDirectory(toolRoot);

            File.WriteAllText(
                Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness", "Dockerfile"),
                """
                FROM scratch
                """);

            File.WriteAllText(
                Path.Combine(RunnerRoot, "implementations_quic.json"),
                $$"""
                {
                  "chrome": { "role": "client" },
                  "quic-go": { "role": "{{quicGoRole}}" },
                  "msquic": { "role": "server" },
                  "nginx": { "role": "server" }
                }
                """);

            File.WriteAllText(Path.Combine(RunnerRoot, "run.py"), "raise SystemExit(0)\n");
            CreateCommandStubs(toolRoot);
            powerShellExecutable = ResolvePowerShellExecutable();
            ScriptPath = FindScriptPath();
            ToolRoot = toolRoot;
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public string ScriptPath { get; }

        public string ToolRoot { get; }

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

        private static void CreateCommandStubs(string toolRoot)
        {
            File.WriteAllText(
                Path.Combine(toolRoot, "fake-docker.ps1"),
                """
                [Console]::Out.WriteLine("fake docker build: $env:FAKE_COMMAND_ARGS")
                exit 0
                """);

            File.WriteAllText(
                Path.Combine(toolRoot, "fake-python.ps1"),
                """
                $rawInvocationArgs = $env:FAKE_COMMAND_ARGS
                $InvocationArgs = @()
                if (-not [string]::IsNullOrWhiteSpace($rawInvocationArgs)) {
                    $InvocationArgs = $rawInvocationArgs.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                }

                function Get-ArgumentValue {
                    param(
                        [Parameter(Mandatory)]
                        [string[]]$Arguments,

                        [Parameter(Mandatory)]
                        [string]$Name
                    )

                    for ($index = 0; $index -lt $Arguments.Count; $index++) {
                        if ($Arguments[$index] -eq $Name) {
                            if ($index + 1 -ge $Arguments.Count) {
                                throw "The fake runner did not receive a value for '$Name'."
                            }

                            return [string]$Arguments[$index + 1]
                        }
                    }

                    throw "The fake runner did not receive '$Name'."
                }

                $runnerShimIndex = -1
                for ($index = 0; $index -lt $InvocationArgs.Count; $index++) {
                    if ($InvocationArgs[$index] -like '*.py') {
                        $runnerShimIndex = $index
                        break
                    }
                }

                if ($runnerShimIndex -lt 0) {
                    throw 'The fake runner did not receive the runner shim path.'
                }

                $runnerArgs = @()
                if ($runnerShimIndex + 1 -lt $InvocationArgs.Count) {
                    $runnerArgs = $InvocationArgs[($runnerShimIndex + 1)..($InvocationArgs.Count - 1)]
                }

                $runnerLogDir = Get-ArgumentValue -Arguments $runnerArgs -Name '-l'
                $runnerJsonPath = Get-ArgumentValue -Arguments $runnerArgs -Name '-j'
                $serverImplementations = Get-ArgumentValue -Arguments $runnerArgs -Name '-s'
                $clientImplementations = Get-ArgumentValue -Arguments $runnerArgs -Name '-c'
                $replacement = Get-ArgumentValue -Arguments $runnerArgs -Name '-r'
                $testCases = Get-ArgumentValue -Arguments $runnerArgs -Name '-t'

                New-Item -Path $runnerLogDir -ItemType Directory -Force | Out-Null
                $receivedArgsPath = Join-Path $runnerLogDir 'received-args.txt'
                $runnerArgs | Set-Content -LiteralPath $receivedArgsPath -Encoding utf8

                $payload = [ordered]@{
                    runnerShim = $InvocationArgs[$runnerShimIndex]
                    args = @($runnerArgs)
                    serverImplementations = $serverImplementations
                    clientImplementations = $clientImplementations
                    replacement = $replacement
                    testcases = $testCases
                    runnerLogDir = $runnerLogDir
                    runnerJsonPath = $runnerJsonPath
                }

                $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $runnerJsonPath -Encoding utf8

                [Console]::Out.WriteLine('# Fake runner report')
                [Console]::Out.WriteLine('')
                [Console]::Out.WriteLine("serverImplementations: $serverImplementations")
                [Console]::Out.WriteLine("clientImplementations: $clientImplementations")
                [Console]::Out.WriteLine("replacement: $replacement")
                [Console]::Out.WriteLine("testcases: $testCases")
                [Console]::Error.WriteLine('fake runner stderr')
                exit 0
                """);

            if (OperatingSystem.IsWindows())
            {
                CreateWindowsLauncher(Path.Combine(toolRoot, "docker.cmd"), "fake-docker.ps1");
                CreateWindowsLauncher(Path.Combine(toolRoot, "python.cmd"), "fake-python.ps1");
                CreateWindowsLauncher(Path.Combine(toolRoot, "python3.cmd"), "fake-python.ps1");
                CreateWindowsLauncher(Path.Combine(toolRoot, "py.cmd"), "fake-python.ps1");
            }
            else
            {
                CreateUnixLauncher(Path.Combine(toolRoot, "docker"), "fake-docker.ps1");
                CreateUnixLauncher(Path.Combine(toolRoot, "python"), "fake-python.ps1");
                CreateUnixLauncher(Path.Combine(toolRoot, "python3"), "fake-python.ps1");
                CreateUnixLauncher(Path.Combine(toolRoot, "py"), "fake-python.ps1");
            }
        }

        private static void CreateWindowsLauncher(string path, string scriptName)
        {
            File.WriteAllText(
                path,
                $"""
                @echo off
                setlocal
                set "SCRIPT_DIR=%~dp0"
                set "FAKE_COMMAND_ARGS=%*"
                where pwsh >nul 2>nul
                if not errorlevel 1 (
                  set "POWERSHELL_EXECUTABLE=pwsh"
                ) else (
                  set "POWERSHELL_EXECUTABLE=powershell"
                )
                "%POWERSHELL_EXECUTABLE%" -NoProfile -File "%SCRIPT_DIR%{scriptName}"
                exit /b %errorlevel%
                """);
        }

        private static void CreateUnixLauncher(string path, string scriptName)
        {
            File.WriteAllText(
                path,
                $"""
                #!/usr/bin/env sh
                script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
                export FAKE_COMMAND_ARGS="$*"
                if command -v pwsh >/dev/null 2>&1; then
                  exec pwsh -NoProfile -File "$script_dir/{scriptName}"
                fi

                exec powershell -NoProfile -File "$script_dir/{scriptName}"
                """);

#pragma warning disable CA1416
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
        }

        private static string BuildCommandText(
            string scriptPath,
            string exceptionMessagePath,
            IReadOnlyList<string> arguments)
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
                        string name = arguments[index * 2];
                        string value = arguments[index * 2 + 1];
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

        private static string FormatPowerShellValue(string? value)
        {
            return value is null ? "$null" : QuotePowerShellSingleQuoted(value);
        }

        private static string QuotePowerShellSingleQuoted(string value)
        {
            return $"'{value.Replace("'", "''")}'";
        }

        private static string ResolvePowerShellExecutable()
        {
            string[] candidates = OperatingSystem.IsWindows()
                ? new[] { "pwsh.exe", "pwsh", "powershell.exe", "powershell" }
                : new[] { "pwsh", "pwsh.exe" };

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

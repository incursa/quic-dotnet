using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0013")]
public sealed class REQ_QUIC_INT_0013
{
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HelperRejectsMissingRunnerReportJsonAfterPostRunValidation()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");
        fixture.WriteRunnerScript("missing-json");

        ScriptRunResult result = await RunPostRunValidationCaseAsync(fixture);

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));

        string runRoot = AssertPostRunValidationEvidence(
            fixture.ArtifactsRoot,
            result.CombinedOutput,
            "fake-runner sentinel missing-json",
            "Missing outputs: runner JSON at");

        Assert.False(File.Exists(Path.Combine(runRoot, "runner-report.json")));
        Assert.Contains(
            "fake-runner sentinel missing-json",
            File.ReadAllText(Path.Combine(runRoot, "runner-report.md")),
            StringComparison.OrdinalIgnoreCase);

        string logFile = Directory.GetFiles(Path.Combine(runRoot, "runner-logs"), "*", SearchOption.AllDirectories).Single();
        Assert.Contains("fake-runner mode=missing-json", File.ReadAllText(logFile), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HelperRejectsInvalidRunnerReportJsonAfterPostRunValidation()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");
        fixture.WriteRunnerScript("invalid-json");

        ScriptRunResult result = await RunPostRunValidationCaseAsync(fixture);

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));

        string runRoot = AssertPostRunValidationEvidence(
            fixture.ArtifactsRoot,
            result.CombinedOutput,
            "fake-runner sentinel invalid-json",
            "runner JSON at");

        Assert.Equal("{\"mode\":\"invalid-json\"", File.ReadAllText(Path.Combine(runRoot, "runner-report.json")).Trim());
        Assert.Contains(
            "fake-runner sentinel invalid-json",
            File.ReadAllText(Path.Combine(runRoot, "runner-report.md")),
            StringComparison.OrdinalIgnoreCase);

        string logFile = Directory.GetFiles(Path.Combine(runRoot, "runner-logs"), "*", SearchOption.AllDirectories).Single();
        Assert.Contains("fake-runner mode=invalid-json", File.ReadAllText(logFile), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HelperRejectsEmptyRunnerReportMarkdownAfterPostRunValidation()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");
        fixture.WriteRunnerScript("empty-markdown");

        ScriptRunResult result = await RunPostRunValidationCaseAsync(fixture);

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));

        string runRoot = AssertPostRunValidationEvidence(
            fixture.ArtifactsRoot,
            result.CombinedOutput,
            "fake-runner sentinel empty-markdown",
            "runner Markdown at");

        Assert.Equal(0, new FileInfo(Path.Combine(runRoot, "runner-report.md")).Length);
        Assert.Equal("{\"mode\":\"empty-markdown\"}", File.ReadAllText(Path.Combine(runRoot, "runner-report.json")).Trim());

        string logFile = Directory.GetFiles(Path.Combine(runRoot, "runner-logs"), "*", SearchOption.AllDirectories).Single();
        Assert.Contains("fake-runner mode=empty-markdown", File.ReadAllText(logFile), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task HelperRejectsEmptyRunnerLogsAfterPostRunValidation()
    {
        using InteropRunnerScriptFixture fixture = new(quicGoRole: "both");
        fixture.WriteRunnerScript("empty-logs");

        ScriptRunResult result = await RunPostRunValidationCaseAsync(fixture);

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrEmpty(result.ExceptionMessage));

        string runRoot = AssertPostRunValidationEvidence(
            fixture.ArtifactsRoot,
            result.CombinedOutput,
            "fake-runner sentinel empty-logs",
            "runner log directory at");

        Assert.Equal("{\"mode\":\"empty-logs\"}", File.ReadAllText(Path.Combine(runRoot, "runner-report.json")).Trim());
        Assert.Contains(
            "fake-runner sentinel empty-logs",
            File.ReadAllText(Path.Combine(runRoot, "runner-report.md")),
            StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(Path.Combine(runRoot, "runner-logs"), "*", SearchOption.AllDirectories));
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

    private static async Task<ScriptRunResult> RunPostRunValidationCaseAsync(InteropRunnerScriptFixture fixture)
    {
        return await fixture.RunAsync(
            "-RepoRoot",
            fixture.RepoRoot,
            "-RunnerRoot",
            fixture.RunnerRoot,
            "-ArtifactsRoot",
            fixture.ArtifactsRoot);
    }

    private static string AssertPostRunValidationEvidence(
        string artifactsRoot,
        string output,
        string sentinel,
        string expectedValidationFragment)
    {
        Assert.Contains("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Reason: the runner did not produce the expected JSON, Markdown, or log outputs.",
            output,
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Run root:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Invocation log:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Artifact tree:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Evidence was preserved in the run root for post-failure inspection.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(expectedValidationFragment, output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(sentinel, output, StringComparison.OrdinalIgnoreCase);

        Assert.True(Directory.Exists(artifactsRoot));

        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);

        string runRoot = runRoots[0];
        string invocationLog = Path.Combine(runRoot, "invocation.txt");
        string artifactTreeLog = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLog = Path.Combine(runRoot, "docker-build.log");
        string runnerStdErr = Path.Combine(runRoot, "runner.stderr.log");
        string runnerMarkdown = Path.Combine(runRoot, "runner-report.md");
        string runnerLogs = Path.Combine(runRoot, "runner-logs");

        Assert.True(File.Exists(invocationLog));
        Assert.True(File.Exists(artifactTreeLog));
        Assert.True(File.Exists(dockerBuildLog));
        Assert.True(File.Exists(runnerStdErr));
        Assert.True(File.Exists(runnerMarkdown));
        Assert.True(Directory.Exists(runnerLogs));

        string artifactTree = File.ReadAllText(artifactTreeLog);
        Assert.Contains("invocation.txt", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(sentinel, artifactTree, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("fake docker build", File.ReadAllText(dockerBuildLog), StringComparison.OrdinalIgnoreCase);

        return runRoot;
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

            WriteRunnerScript("success");
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

        public void WriteRunnerScript(string mode)
        {
            File.WriteAllText(Path.Combine(RunnerRoot, "run.py"), BuildRunnerScriptContent(mode));
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
            if (OperatingSystem.IsWindows())
            {
                CreateWindowsStub(Path.Combine(toolRoot, "docker.cmd"), GetDockerStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "python.cmd"), GetPythonStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "python3.cmd"), GetPythonStubContent());
                CreateWindowsStub(Path.Combine(toolRoot, "py.cmd"), GetPythonStubContent());
            }
            else
            {
                CreateUnixStub(Path.Combine(toolRoot, "docker"), GetDockerStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "python"), GetPythonStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "python3"), GetPythonStubContent());
                CreateUnixStub(Path.Combine(toolRoot, "py"), GetPythonStubContent());
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
                echo fake docker build
                exit /b 0
                """;
            }

            return """
            #!/usr/bin/env sh
            printf '%s\n' 'fake docker build'
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

                findstr /c:"# fake-runner: missing-json" run.py >nul && set "mode=missing-json"
                findstr /c:"# fake-runner: invalid-json" run.py >nul && set "mode=invalid-json"
                findstr /c:"# fake-runner: empty-markdown" run.py >nul && set "mode=empty-markdown"
                findstr /c:"# fake-runner: empty-logs" run.py >nul && set "mode=empty-logs"

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

                if /I "%mode%"=="missing-json" (
                  echo fake-runner sentinel missing-json
                  > "%logsDir%\fake-runner.log" echo fake-runner mode=missing-json
                  exit /b 0
                )

                if /I "%mode%"=="invalid-json" (
                  echo fake-runner sentinel invalid-json
                  if not defined jsonPath exit /b 2
                  > "%jsonPath%" echo {"mode":"invalid-json"
                  > "%logsDir%\fake-runner.log" echo fake-runner mode=invalid-json
                  exit /b 0
                )

                if /I "%mode%"=="empty-markdown" (
                  if not defined jsonPath exit /b 2
                  > "%jsonPath%" echo {"mode":"empty-markdown"}
                  > "%logsDir%\fake-runner.log" echo fake-runner mode=empty-markdown
                  exit /b 0
                )

                if /I "%mode%"=="empty-logs" (
                  echo fake-runner sentinel empty-logs
                  if not defined jsonPath exit /b 2
                  > "%jsonPath%" echo {"mode":"empty-logs"}
                  rem Keep runner-logs empty on purpose.
                  exit /b 0
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
            if grep -q '# fake-runner: missing-json' run.py; then
                mode=missing-json
            elif grep -q '# fake-runner: invalid-json' run.py; then
                mode=invalid-json
            elif grep -q '# fake-runner: empty-markdown' run.py; then
                mode=empty-markdown
            elif grep -q '# fake-runner: empty-logs' run.py; then
                mode=empty-logs
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

            case "$mode" in
                missing-json)
                    printf '%s\n' 'fake-runner sentinel missing-json'
                    printf '%s\n' 'fake-runner mode=missing-json' > "$logs_dir/fake-runner.log"
                    ;;
                invalid-json)
                    printf '%s\n' 'fake-runner sentinel invalid-json'
                    if [ -z "$json_path" ]; then
                        exit 2
                    fi
                    printf '%s\n' '{"mode":"invalid-json"' > "$json_path"
                    printf '%s\n' 'fake-runner mode=invalid-json' > "$logs_dir/fake-runner.log"
                    ;;
                empty-markdown)
                    if [ -z "$json_path" ]; then
                        exit 2
                    fi
                    printf '%s\n' '{"mode":"empty-markdown"}' > "$json_path"
                    printf '%s\n' 'fake-runner mode=empty-markdown' > "$logs_dir/fake-runner.log"
                    ;;
                empty-logs)
                    printf '%s\n' 'fake-runner sentinel empty-logs'
                    if [ -z "$json_path" ]; then
                        exit 2
                    fi
                    printf '%s\n' '{"mode":"empty-logs"}' > "$json_path"
                    mkdir -p "$logs_dir"
                    ;;
                *)
                    printf '%s\n' 'fake-runner sentinel success'
                    if [ -n "$json_path" ]; then
                        printf '%s\n' '{"mode":"success"}' > "$json_path"
                    fi
                    printf '%s\n' 'fake-runner mode=success' > "$logs_dir/fake-runner.log"
                    ;;
            esac

            exit 0
            """;
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

using System.Diagnostics;

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
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");
        string runnerLogPath = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories).Single();
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");

        Assert.True(File.Exists(Path.Combine(runRoot, "invocation.txt")));
        Assert.True(File.Exists(Path.Combine(runRoot, "docker-build.log")));
        Assert.True(File.Exists(runnerJsonPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogsPath));

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
        Assert.Contains("runner-logs", artifactTree, StringComparison.OrdinalIgnoreCase);
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

        private static string GetPythonStubContent()
        {
            if (OperatingSystem.IsWindows())
            {
                return """
                @echo off
                setlocal
                set "mode=success"

                findstr /c:"# fake-runner: non-zero-valid-outputs" run.py >nul && set "mode=non-zero-valid-outputs"

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

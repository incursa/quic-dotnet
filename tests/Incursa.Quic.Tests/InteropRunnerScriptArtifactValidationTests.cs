using System.Diagnostics;

namespace Incursa.Quic.Tests;

public sealed class InteropRunnerScriptArtifactValidationTests
{
    [Fact]
    public async Task SuccessPathPreservesTheExpectedArtifactSet()
    {
        using InteropRunnerScriptFixture fixture = new("success");

        ScriptRunResult result = await fixture.RunAsync();

        Assert.True(
            result.ExitCode == 0,
            $"Helper exit code was {result.ExitCode}.\nSTDOUT:\n{result.Stdout}\nSTDERR:\n{result.Stderr}");

        string runRoot = AssertSuccessfulArtifactSet(fixture.ArtifactsRoot);
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");

        Assert.Equal("{\"mode\":\"success\"}", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains("fake-runner sentinel success", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake docker build", File.ReadAllText(dockerBuildLogPath), StringComparison.OrdinalIgnoreCase);

        string[] logFiles = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories);
        Assert.Single(logFiles);
        Assert.Contains("fake-runner mode=success", File.ReadAllText(logFiles[0]), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingRunnerReportJsonFailsValidation()
    {
        using InteropRunnerScriptFixture fixture = new("missing-json");

        ScriptRunResult result = await fixture.RunAsync();

        Assert.Equal(
            1,
            result.ExitCode);

        string runRoot = AssertFailureArtifactEvidence(fixture.ArtifactsRoot);
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.False(File.Exists(runnerJsonPath));
        Assert.Contains("fake-runner sentinel missing-json", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);

        string artifactTreeText = File.ReadAllText(artifactTreePath);
        Assert.DoesNotContain("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake-runner.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);

        string[] logFiles = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories);
        Assert.Single(logFiles);
        Assert.Contains("fake-runner mode=missing-json", File.ReadAllText(logFiles[0]), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task InvalidRunnerReportJsonFailsValidation()
    {
        using InteropRunnerScriptFixture fixture = new("invalid-json");

        ScriptRunResult result = await fixture.RunAsync();

        Assert.Equal(1, result.ExitCode);

        string runRoot = AssertFailureArtifactEvidence(fixture.ArtifactsRoot);
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.Equal("{\"mode\":\"invalid-json\"", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains("fake-runner sentinel invalid-json", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);

        string artifactTreeText = File.ReadAllText(artifactTreePath);
        Assert.Contains("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake-runner.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);

        string[] logFiles = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories);
        Assert.Single(logFiles);
        Assert.Contains("fake-runner mode=invalid-json", File.ReadAllText(logFiles[0]), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EmptyRunnerReportMarkdownFailsValidation()
    {
        using InteropRunnerScriptFixture fixture = new("empty-markdown");

        ScriptRunResult result = await fixture.RunAsync();

        Assert.Equal(1, result.ExitCode);

        string runRoot = AssertFailureArtifactEvidence(fixture.ArtifactsRoot);
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.Equal(0, new FileInfo(runnerMarkdownPath).Length);
        Assert.Equal("{\"mode\":\"empty-markdown\"}", File.ReadAllText(runnerJsonPath).Trim());

        string artifactTreeText = File.ReadAllText(artifactTreePath);
        Assert.Contains("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("fake-runner.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);

        string[] logFiles = Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories);
        Assert.Single(logFiles);
        Assert.Contains("fake-runner mode=empty-markdown", File.ReadAllText(logFiles[0]), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EmptyRunnerLogsDirectoryFailsValidation()
    {
        using InteropRunnerScriptFixture fixture = new("empty-logs");

        ScriptRunResult result = await fixture.RunAsync();

        Assert.Equal(1, result.ExitCode);

        string runRoot = AssertFailureArtifactEvidence(fixture.ArtifactsRoot);
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.Equal("{\"mode\":\"empty-logs\"}", File.ReadAllText(runnerJsonPath).Trim());
        Assert.Contains("fake-runner sentinel empty-logs", File.ReadAllText(runnerMarkdownPath), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(runnerLogsPath, "*", SearchOption.AllDirectories));

        string artifactTreeText = File.ReadAllText(artifactTreePath);
        Assert.Contains("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fake-runner.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);
    }

    private static string AssertSuccessfulArtifactSet(string artifactsRoot)
    {
        string runRoot = GetSingleRunRoot(artifactsRoot);

        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(artifactTreePath));
        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(runnerJsonPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogsPath));

        string invocationText = File.ReadAllText(invocationPath);
        string artifactTreeText = File.ReadAllText(artifactTreePath);

        Assert.Contains("RepoRoot:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerRoot:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerJson:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerMarkdown:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerStdErr:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerLogDir:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ArtifactTreeLog:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerArgs:", invocationText, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("invocation.txt", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("docker-build.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.json", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-logs", artifactTreeText, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("fake docker build", File.ReadAllText(dockerBuildLogPath), StringComparison.OrdinalIgnoreCase);

        return runRoot;
    }

    private static string AssertFailureArtifactEvidence(string artifactsRoot)
    {
        string runRoot = GetSingleRunRoot(artifactsRoot);

        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(artifactTreePath));
        Assert.True(File.Exists(dockerBuildLogPath));
        Assert.True(File.Exists(runnerMarkdownPath));
        Assert.True(File.Exists(runnerStdErrPath));
        Assert.True(Directory.Exists(runnerLogsPath));

        string invocationText = File.ReadAllText(invocationPath);
        string artifactTreeText = File.ReadAllText(artifactTreePath);

        Assert.Contains("RepoRoot:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerRoot:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerJson:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerMarkdown:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerStdErr:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerLogDir:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ArtifactTreeLog:", invocationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RunnerArgs:", invocationText, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("invocation.txt", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("docker-build.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner-report.md", artifactTreeText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("runner.stderr.log", artifactTreeText, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("fake docker build", File.ReadAllText(dockerBuildLogPath), StringComparison.OrdinalIgnoreCase);

        return runRoot;
    }

    private static string GetSingleRunRoot(string artifactsRoot)
    {
        Assert.True(Directory.Exists(artifactsRoot));

        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);

        return runRoots[0];
    }

    private sealed class InteropRunnerScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("interop-runner-script-artifact-validation");
        private readonly string powerShellExecutable;
        private readonly string scriptPath;
        private readonly string toolRoot;

        public InteropRunnerScriptFixture(string runnerMode)
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-interop-runner");
            ArtifactsRoot = Path.Combine(workspaceRoot, "artifacts", "interop-runner");
            toolRoot = Path.Combine(workspaceRoot, "tools");

            Directory.CreateDirectory(Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness"));
            Directory.CreateDirectory(RunnerRoot);
            Directory.CreateDirectory(toolRoot);

            File.WriteAllText(
                Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness", "Dockerfile"),
                """
                FROM scratch
                """);

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

            WriteRunnerScript(runnerMode);
            CreateCommandStubs(toolRoot);
            powerShellExecutable = ResolvePowerShellExecutable();
            scriptPath = FindScriptPath();
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public void WriteRunnerScript(string mode)
        {
            File.WriteAllText(Path.Combine(RunnerRoot, "run.py"), BuildRunnerScriptContent(mode));
        }

        public async Task<ScriptRunResult> RunAsync()
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
            startInfo.ArgumentList.Add("-RunnerRoot");
            startInfo.ArgumentList.Add(RunnerRoot);
            startInfo.ArgumentList.Add("-ArtifactsRoot");
            startInfo.ArgumentList.Add(ArtifactsRoot);

            string existingPath = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            startInfo.Environment["PATH"] = $"{toolRoot}{Path.PathSeparator}{existingPath}";

            using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start the interop runner helper script.");
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();

            await process.WaitForExitAsync().ConfigureAwait(false);

            string stdout = await stdoutTask.ConfigureAwait(false);
            string stderr = await stderrTask.ConfigureAwait(false);

            return new ScriptRunResult(process.ExitCode, stdout, stderr);
        }

        public void Dispose()
        {
            tempDirectoryFixture.Dispose();
        }

        private static string BuildRunnerScriptContent(string mode)
        {
            return $"# fake-runner: {mode}{Environment.NewLine}";
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

    private sealed record ScriptRunResult(int ExitCode, string Stdout, string Stderr);
}

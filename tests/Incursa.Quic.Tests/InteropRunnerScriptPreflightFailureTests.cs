using System.Diagnostics;

namespace Incursa.Quic.Tests;

public sealed class InteropRunnerScriptPreflightFailureTests
{
    [Theory]
    [MemberData(nameof(GetPreflightFailureModes))]
    public async Task PreflightPrerequisiteFailuresStopBeforeBuildAndRunnerLaunch(PreflightFailureMode mode)
    {
        using InteropRunnerScriptFixture fixture = new(mode);

        ScriptRunResult result = await fixture.RunAsync();

        string output = result.CombinedOutput;

        Assert.Equal(1, result.ExitCode);
        Assert.True(string.IsNullOrWhiteSpace(result.ExceptionMessage));
        Assert.Contains("Interop runner helper failed.", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(GetExpectedReason(mode), output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Run root:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Invocation log:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Artifact tree:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Runner stderr:", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Evidence was preserved in the run root for post-failure inspection.", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Runner exit code:", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Building Incursa.Quic.InteropHarness image...", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Running quic-interop-runner locally...", output, StringComparison.OrdinalIgnoreCase);

        AssertPreflightArtifacts(
            fixture.ArtifactsRoot,
            fixture.DockerInvocationSentinelPath,
            fixture.PythonInvocationSentinelPath);
    }

    public static IEnumerable<object?[]> GetPreflightFailureModes()
    {
        yield return [PreflightFailureMode.MissingRunnerCheckout];
        yield return [PreflightFailureMode.MissingImplementationsRegistry];
        yield return [PreflightFailureMode.MissingRunPy];
        yield return [PreflightFailureMode.MissingDockerfile];
        yield return [PreflightFailureMode.MissingDockerOnPath];
        yield return [PreflightFailureMode.MissingPythonOnPath];
    }

    private static string GetExpectedReason(PreflightFailureMode mode)
    {
        return mode switch
        {
            PreflightFailureMode.MissingRunnerCheckout => "Interop runner checkout was not found",
            PreflightFailureMode.MissingImplementationsRegistry => "Runner implementation registry was not found",
            PreflightFailureMode.MissingRunPy => "Interop runner entry point was not found",
            PreflightFailureMode.MissingDockerfile => "Harness Dockerfile was not found",
            PreflightFailureMode.MissingDockerOnPath => "docker is required but was not found on PATH.",
            PreflightFailureMode.MissingPythonOnPath => "python is required but was not found on PATH.",
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, null),
        };
    }

    private static void AssertPreflightArtifacts(string artifactsRoot, string dockerSentinelPath, string pythonSentinelPath)
    {
        string[] runRoots = Directory.GetDirectories(artifactsRoot);
        Assert.Single(runRoots);

        string runRoot = runRoots[0];
        string invocationPath = Path.Combine(runRoot, "invocation.txt");
        string artifactTreePath = Path.Combine(runRoot, "artifact-tree.txt");
        string dockerBuildLogPath = Path.Combine(runRoot, "docker-build.log");
        string runnerShimPath = Path.Combine(runRoot, "runner-shim.py");
        string runnerMarkdownPath = Path.Combine(runRoot, "runner-report.md");
        string runnerStdErrPath = Path.Combine(runRoot, "runner.stderr.log");
        string runnerJsonPath = Path.Combine(runRoot, "runner-report.json");
        string runnerLogsPath = Path.Combine(runRoot, "runner-logs");

        string[] fileSystemEntries = Directory.GetFileSystemEntries(runRoot);
        Assert.Equal(2, fileSystemEntries.Length);
        Assert.Contains(invocationPath, fileSystemEntries);
        Assert.Contains(artifactTreePath, fileSystemEntries);

        Assert.True(File.Exists(invocationPath));
        Assert.True(File.Exists(artifactTreePath));
        Assert.False(File.Exists(dockerBuildLogPath));
        Assert.False(File.Exists(runnerShimPath));
        Assert.False(File.Exists(runnerMarkdownPath));
        Assert.False(File.Exists(runnerStdErrPath));
        Assert.False(File.Exists(runnerJsonPath));
        Assert.False(Directory.Exists(runnerLogsPath));
        Assert.False(File.Exists(dockerSentinelPath));
        Assert.False(File.Exists(pythonSentinelPath));

        string artifactTree = File.ReadAllText(artifactTreePath);
        Assert.Contains("invocation.txt", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("docker-build.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-shim.py", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-report.json", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-report.md", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner.stderr.log", artifactTree, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("runner-logs", artifactTree, StringComparison.OrdinalIgnoreCase);
    }

    public enum PreflightFailureMode
    {
        MissingRunnerCheckout,
        MissingImplementationsRegistry,
        MissingRunPy,
        MissingDockerfile,
        MissingDockerOnPath,
        MissingPythonOnPath,
    }

    private sealed class InteropRunnerScriptFixture : IDisposable
    {
        private readonly TempDirectoryFixture tempDirectoryFixture = new("incursa-quic-interop-runner-script-preflight-failure");
        private readonly string powerShellExecutable;
        private readonly string scriptPath;
        private readonly string toolRoot;

        public InteropRunnerScriptFixture(PreflightFailureMode mode)
        {
            string workspaceRoot = Path.Combine(tempDirectoryFixture.RootDirectory, "workspace");
            RepoRoot = Path.Combine(workspaceRoot, "incursa", "quic-dotnet");
            RunnerRoot = Path.Combine(workspaceRoot, "quic-interop", "quic-interop-runner");
            ArtifactsRoot = Path.Combine(workspaceRoot, "artifacts", "interop-runner");
            toolRoot = Path.Combine(workspaceRoot, "tools");
            DockerInvocationSentinelPath = Path.Combine(tempDirectoryFixture.RootDirectory, "docker-invoked.txt");
            PythonInvocationSentinelPath = Path.Combine(tempDirectoryFixture.RootDirectory, "python-invoked.txt");

            Directory.CreateDirectory(RepoRoot);
            Directory.CreateDirectory(Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness"));
            Directory.CreateDirectory(toolRoot);

            switch (mode)
            {
                case PreflightFailureMode.MissingRunnerCheckout:
                    CreateRepoDockerfile();
                    CreateCommandStubs(includeDocker: true, includePython: true);
                    break;

                case PreflightFailureMode.MissingImplementationsRegistry:
                    Directory.CreateDirectory(RunnerRoot);
                    CreateRepoDockerfile();
                    CreateRunnerScript();
                    CreateCommandStubs(includeDocker: true, includePython: true);
                    break;

                case PreflightFailureMode.MissingRunPy:
                    Directory.CreateDirectory(RunnerRoot);
                    CreateRepoDockerfile();
                    CreateRunnerRegistry();
                    CreateCommandStubs(includeDocker: true, includePython: true);
                    break;

                case PreflightFailureMode.MissingDockerfile:
                    Directory.CreateDirectory(RunnerRoot);
                    CreateRunnerRegistry();
                    CreateRunnerScript();
                    CreateCommandStubs(includeDocker: true, includePython: true);
                    break;

                case PreflightFailureMode.MissingDockerOnPath:
                    Directory.CreateDirectory(RunnerRoot);
                    CreateRepoDockerfile();
                    CreateRunnerRegistry();
                    CreateRunnerScript();
                    CreateCommandStubs(includeDocker: false, includePython: true);
                    break;

                case PreflightFailureMode.MissingPythonOnPath:
                    Directory.CreateDirectory(RunnerRoot);
                    CreateRepoDockerfile();
                    CreateRunnerRegistry();
                    CreateRunnerScript();
                    CreateCommandStubs(includeDocker: true, includePython: false);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
            }

            powerShellExecutable = ResolvePowerShellExecutable();
            scriptPath = FindScriptPath();
        }

        public string RepoRoot { get; }

        public string RunnerRoot { get; }

        public string ArtifactsRoot { get; }

        public string DockerInvocationSentinelPath { get; }

        public string PythonInvocationSentinelPath { get; }

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

            startInfo.Environment["PATH"] = toolRoot;

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

        private void CreateRepoDockerfile()
        {
            File.WriteAllText(
                Path.Combine(RepoRoot, "src", "Incursa.Quic.InteropHarness", "Dockerfile"),
                """
                FROM scratch
                """);
        }

        private void CreateRunnerRegistry()
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

        private void CreateRunnerScript()
        {
            File.WriteAllText(
                Path.Combine(RunnerRoot, "run.py"),
                "# fake runner entry point\n");
        }

        private void CreateCommandStubs(bool includeDocker, bool includePython)
        {
            if (OperatingSystem.IsWindows())
            {
                if (includeDocker)
                {
                    CreateWindowsStub(
                        Path.Combine(toolRoot, "docker.cmd"),
                        DockerInvocationSentinelPath,
                        "fake docker build");
                }

                if (includePython)
                {
                    CreateWindowsStub(
                        Path.Combine(toolRoot, "python.cmd"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                    CreateWindowsStub(
                        Path.Combine(toolRoot, "python3.cmd"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                    CreateWindowsStub(
                        Path.Combine(toolRoot, "py.cmd"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                }
            }
            else
            {
                if (includeDocker)
                {
                    CreateUnixStub(
                        Path.Combine(toolRoot, "docker"),
                        DockerInvocationSentinelPath,
                        "fake docker build");
                }

                if (includePython)
                {
                    CreateUnixStub(
                        Path.Combine(toolRoot, "python"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                    CreateUnixStub(
                        Path.Combine(toolRoot, "python3"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                    CreateUnixStub(
                        Path.Combine(toolRoot, "py"),
                        PythonInvocationSentinelPath,
                        "fake runner invocation");
                }
            }
        }

        private static void CreateWindowsStub(string path, string sentinelPath, string message)
        {
            File.WriteAllText(
                path,
                @$"@echo off
echo {message} > ""{sentinelPath}""
exit /b 0
");
        }

        private static void CreateUnixStub(string path, string sentinelPath, string message)
        {
            File.WriteAllText(
                path,
                $@"#!/bin/sh
printf '%s\n' '{message}' > ""{sentinelPath}""
exit 0
");

#pragma warning disable CA1416
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
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

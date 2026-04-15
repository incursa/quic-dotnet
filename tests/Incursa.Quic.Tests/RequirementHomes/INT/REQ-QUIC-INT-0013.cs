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
        Assert.Contains(
            "LocalRole 'client' requires the local replacement slot 'chrome' to differ from the peer implementation slot list.",
            exceptionMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
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
        Assert.Contains(
            "Peer implementation slot 'quic-go' is role 'client' which is not compatible with LocalRole 'client'.",
            exceptionMessage,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(output.Contains("Building Incursa.Quic.InteropHarness image...", StringComparison.OrdinalIgnoreCase));
        Assert.False(Directory.Exists(fixture.ArtifactsRoot));
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
            if (OperatingSystem.IsWindows())
            {
                CreateWindowsStub(Path.Combine(toolRoot, "docker.cmd"));
                CreateWindowsStub(Path.Combine(toolRoot, "python.cmd"));
                CreateWindowsStub(Path.Combine(toolRoot, "python3.cmd"));
                CreateWindowsStub(Path.Combine(toolRoot, "py.cmd"));
            }
            else
            {
                CreateUnixStub(Path.Combine(toolRoot, "docker"));
                CreateUnixStub(Path.Combine(toolRoot, "python"));
                CreateUnixStub(Path.Combine(toolRoot, "python3"));
                CreateUnixStub(Path.Combine(toolRoot, "py"));
            }
        }

        private static void CreateWindowsStub(string path)
        {
            File.WriteAllText(
                path,
                """
                @echo off
                exit /b 0
                """);
        }

        private static void CreateUnixStub(string path)
        {
            File.WriteAllText(
                path,
                """
                #!/usr/bin/env sh
                exit 0
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

using System.Diagnostics;
using System.Net;
using System.Text;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0010")]
public sealed class REQ_QUIC_INT_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ManagedChildProcessHarnessTransfersEveryOrderedRequestFromWwwToDownloadsOnOneConnection()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string[] relativePaths =
            [
                $"transfer-{Guid.NewGuid():N}-1.txt",
                $"transfer-{Guid.NewGuid():N}-2.txt",
                $"transfer-{Guid.NewGuid():N}-3.txt",
            ];
            string[] requestUris =
            [
                $"https://localhost:{listenEndPoint.Port}/{relativePaths[0]}",
                $"https://localhost:{listenEndPoint.Port}/{relativePaths[1]}",
                $"https://localhost:{listenEndPoint.Port}/{relativePaths[2]}",
            ];
            string requests = string.Join(" ", requestUris);

            string[] sourcePaths =
            [
                Path.Combine(sourceRoot, relativePaths[0]),
                Path.Combine(sourceRoot, relativePaths[1]),
                Path.Combine(sourceRoot, relativePaths[2]),
            ];
            string[] destinationPaths =
            [
                Path.Combine(destinationRoot, relativePaths[0]),
                Path.Combine(destinationRoot, relativePaths[1]),
                Path.Combine(destinationRoot, relativePaths[2]),
            ];
            byte[][] payloads =
            [
                Encoding.UTF8.GetBytes($"managed transfer proof one {Guid.NewGuid():N}"),
                Encoding.UTF8.GetBytes($"managed transfer proof two {Guid.NewGuid():N}"),
                Encoding.UTF8.GetBytes($"managed transfer proof three {Guid.NewGuid():N}"),
            ];

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            for (int index = 0; index < sourcePaths.Length; index++)
            {
                File.WriteAllBytes(sourcePaths[index], payloads[index]);
                TryDelete(destinationPaths[index]);
            }

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", requests, harnessDll);
                await clientProcess.WaitForStdoutContainsAsync("stream 3/3", TimeSpan.FromSeconds(20));
                await serverProcess.WaitForStdoutContainsAsync("stream 3", TimeSpan.FromSeconds(20));
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

                Assert.Equal(0, clientProcess.Process.ExitCode);
                Assert.Equal(0, serverProcess.Process.ExitCode);
                Assert.Empty(clientProcess.Stderr);
                Assert.Empty(serverProcess.Stderr);

                for (int index = 0; index < destinationPaths.Length; index++)
                {
                    Assert.True(File.Exists(destinationPaths[index]), $"Expected destination file '{destinationPaths[index]}' to exist.");
                    Assert.Equal(payloads[index], File.ReadAllBytes(destinationPaths[index]));
                }

                Assert.Contains("testcase=transfer", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("completed managed transfer download", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 1/3", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 2/3", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 3/3", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("testcase=transfer", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("completed managed transfer response", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 1", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 2", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("stream 3", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                foreach (string sourcePath in sourcePaths)
                {
                    TryDelete(sourcePath);
                }

                foreach (string destinationPath in destinationPaths)
                {
                    TryDelete(destinationPath);
                }
            }
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ManagedChildProcessHarnessServerRoleTransferAcceptsEmptyRequestsForRunnerDispatch()
    {
        // Provenance: artifacts\interop-runner\20260422-140138237-server-nginx failed before QUIC
        // work because the external runner passed REQUESTS_SERVER="" for server-role transfer, so
        // this regression locks the empty-server-REQUESTS dispatch plan locally.
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "transfer",
                requests: string.Empty),
            out InteropHarnessEnvironment? settings,
            out string? errorMessage));
        Assert.NotNull(settings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner planner = new(settings!, TextWriter.Null);
        InteropHarnessRunner.ServerTransferDispatchPlanBuildResult result =
            await InteropHarnessRunner.TryCreateServerTransferDispatchPlanAsync(settings!, planner);

        Assert.True(result.Success);
        Assert.NotNull(result.Plan);
        Assert.Null(result.ErrorMessage);
        Assert.Equal(IPAddress.Any, result.Plan!.ListenEndPoint.Address);
        Assert.Equal(443, result.Plan.ListenEndPoint.Port);
        Assert.Equal(0, result.Plan.ExpectedRequestCount);
        Assert.Equal(0, result.Plan.ConfiguredRequestCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ManagedChildProcessHarnessFailsTransferWhenAnyOrderedServerFileIsMissing()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string[] relativePaths =
            [
                $"transfer-missing-{Guid.NewGuid():N}-1.txt",
                $"transfer-missing-{Guid.NewGuid():N}-2.txt",
                $"transfer-missing-{Guid.NewGuid():N}-3.txt",
            ];
            string requests = string.Join(
                " ",
                [
                    $"https://localhost:{listenEndPoint.Port}/{relativePaths[0]}",
                    $"https://localhost:{listenEndPoint.Port}/{relativePaths[1]}",
                    $"https://localhost:{listenEndPoint.Port}/{relativePaths[2]}",
                ]);
            string[] sourcePaths =
            [
                Path.Combine(sourceRoot, relativePaths[0]),
                Path.Combine(sourceRoot, relativePaths[1]),
                Path.Combine(sourceRoot, relativePaths[2]),
            ];
            string[] destinationPaths =
            [
                Path.Combine(destinationRoot, relativePaths[0]),
                Path.Combine(destinationRoot, relativePaths[1]),
                Path.Combine(destinationRoot, relativePaths[2]),
            ];

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            File.WriteAllBytes(sourcePaths[0], Encoding.UTF8.GetBytes($"ordered transfer proof one {Guid.NewGuid():N}"));
            TryDelete(sourcePaths[1]);
            File.WriteAllBytes(sourcePaths[2], Encoding.UTF8.GetBytes($"ordered transfer proof three {Guid.NewGuid():N}"));

            foreach (string destinationPath in destinationPaths)
            {
                TryDelete(destinationPath);
            }

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", requests, harnessDll);
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(45));

                Assert.Equal(1, clientProcess.Process.ExitCode);
                Assert.Equal(1, serverProcess.Process.ExitCode);
                Assert.Contains(sourcePaths[1], serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("was not found", serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.StartsWith("interop harness: role=client, testcase=transfer failed:", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("stream 3/3", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("stream 3", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.False(File.Exists(destinationPaths[1]));
                Assert.False(File.Exists(destinationPaths[2]));
            }
            finally
            {
                foreach (string sourcePath in sourcePaths)
                {
                    TryDelete(sourcePath);
                }

                foreach (string destinationPath in destinationPaths)
                {
                    TryDelete(destinationPath);
                }
            }
        });
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup only.
        }
    }

    private static async Task WaitForExitAsync(
        HarnessProcess serverProcess,
        HarnessProcess clientProcess,
        TimeSpan timeout)
    {
        Task completionTask = Task.WhenAll(
            serverProcess.Process.WaitForExitAsync(),
            clientProcess.Process.WaitForExitAsync());

        Task completed = await Task.WhenAny(completionTask, Task.Delay(timeout)).ConfigureAwait(false);
        if (completed == completionTask)
        {
            await completionTask.ConfigureAwait(false);
            return;
        }

        throw new TimeoutException(
            $"Harness transfer did not complete within {timeout}.\nSERVER STDOUT:\n{serverProcess.Stdout}\nSERVER STDERR:\n{serverProcess.Stderr}\nCLIENT STDOUT:\n{clientProcess.Stdout}\nCLIENT STDERR:\n{clientProcess.Stderr}");
    }

    private sealed class HarnessProcess : IAsyncDisposable
    {
        private readonly StringBuilder stdoutBuilder = new();
        private readonly StringBuilder stderrBuilder = new();
        private readonly object gate = new();
        private readonly Task stdoutTask;
        private readonly Task stderrTask;
        private int disposed;

        private HarnessProcess(Process process)
        {
            Process = process;
            stdoutTask = ConsumeAsync(process.StandardOutput, line =>
            {
                lock (gate)
                {
                    stdoutBuilder.AppendLine(line);
                }
            });
            stderrTask = ConsumeAsync(process.StandardError, line =>
            {
                lock (gate)
                {
                    stderrBuilder.AppendLine(line);
                }
            });
        }

        public Process Process { get; }

        public string Stdout
        {
            get
            {
                lock (gate)
                {
                    return stdoutBuilder.ToString();
                }
            }
        }

        public string Stderr
        {
            get
            {
                lock (gate)
                {
                    return stderrBuilder.ToString();
                }
            }
        }

        public static HarnessProcess Start(string role, string testCase, string requests, string harnessDll)
        {
            ProcessStartInfo startInfo = new("dotnet")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            startInfo.ArgumentList.Add(harnessDll);
            startInfo.Environment["ROLE"] = role;
            startInfo.Environment["TESTCASE"] = testCase;
            startInfo.Environment["REQUESTS"] = requests;

            Process process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start the interop harness process.");
            return new HarnessProcess(process);
        }

        public async Task WaitForStdoutContainsAsync(string value, TimeSpan timeout)
        {
            DateTime deadline = DateTime.UtcNow + timeout;

            while (DateTime.UtcNow < deadline)
            {
                if (Stdout.Contains(value, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                if (Process.HasExited)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
            }

            throw new TimeoutException(
                $"The harness process did not write '{value}' within {timeout}.\nSTDOUT:\n{Stdout}\nSTDERR:\n{Stderr}");
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0)
            {
                return;
            }

            try
            {
                bool hasExited = false;
                try
                {
                    hasExited = Process.HasExited;
                }
                catch (InvalidOperationException)
                {
                    return;
                }

                if (!hasExited)
                {
                    try
                    {
                        Process.Kill(entireProcessTree: true);
                    }
                    catch
                    {
                        // Best-effort cleanup only.
                    }

                    try
                    {
                        await Process.WaitForExitAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                        // Best-effort cleanup only.
                    }
                }

                await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
            }
            finally
            {
                Process.Dispose();
            }
        }

        private static async Task ConsumeAsync(StreamReader reader, Action<string> onLine)
        {
            while (true)
            {
                string? line = await reader.ReadLineAsync().ConfigureAwait(false);
                if (line is null)
                {
                    return;
                }

                onLine(line);
            }
        }
    }
}

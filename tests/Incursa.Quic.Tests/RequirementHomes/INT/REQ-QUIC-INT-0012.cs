using System.Diagnostics;
using System.Net;
using System.Text;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0012")]
public sealed class REQ_QUIC_INT_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ManagedChildProcessHarnessEmitsAndConsumesExactlyOneRetryBeforeDeliveringRequestedData()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string relativePath = $"retry-{Guid.NewGuid():N}.txt";
            string requests = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string sourcePath = Path.Combine(sourceRoot, relativePath);
            string destinationPath = Path.Combine(destinationRoot, relativePath);
            byte[] payload = Encoding.UTF8.GetBytes($"managed retry delivery proof {Guid.NewGuid():N}");

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            File.WriteAllBytes(sourcePath, payload);
            TryDelete(destinationPath);

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "retry", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "retry", requests, harnessDll);

                await WaitForRetryLifecycleAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(15));
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(25));

                Assert.Equal(0, clientProcess.Process.ExitCode);
                Assert.Equal(0, serverProcess.Process.ExitCode);
                Assert.Empty(clientProcess.Stderr);
                Assert.Empty(serverProcess.Stderr);
                Assert.True(File.Exists(destinationPath), $"Expected destination file '{destinationPath}' to exist.");
                Assert.Equal(payload, File.ReadAllBytes(destinationPath));
                Assert.Contains("testcase=retry", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                AssertContainsInOrder(
                    clientProcess.Stdout,
                    "connecting to",
                    "observed exactly one Retry transition (token=",
                    "observed exactly one Retry transition and completed managed client bootstrap.",
                    "completed managed retry download");
                Assert.Contains("testcase=retry", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                AssertContainsInOrder(
                    serverProcess.Stdout,
                    "listening on",
                    "issued exactly one Retry (token=",
                    "issued exactly one Retry and completed managed listener bootstrap.",
                    "completed managed retry response");
            }
            finally
            {
                TryDelete(sourcePath);
                TryDelete(destinationPath);
            }
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ServerRetryDispatchCanStartWithEmptyRequests()
    {
        await InteropHarnessTestSupport.WithDefaultPortHarnessAsync(async () =>
        {
            await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
            {
                string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "retry", string.Empty, harnessDll);

                await serverProcess.WaitForStdoutContainsAsync("retry contract enabled", TimeSpan.FromSeconds(10));
                Assert.Contains("requestCount=0", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("listening on", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Empty(serverProcess.Stderr);
            });
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ManagedChildProcessHarnessFailsRetryDeliveryWhenTheRequestedServerFileIsMissing()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string relativePath = $"retry-missing-{Guid.NewGuid():N}.txt";
            string requests = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string sourcePath = Path.Combine(sourceRoot, relativePath);
            string destinationPath = Path.Combine(destinationRoot, relativePath);

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            TryDelete(sourcePath);
            TryDelete(destinationPath);

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "retry", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "retry", requests, harnessDll);

                await WaitForRetryLifecycleAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(15));
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(45));

                Assert.Equal(1, clientProcess.Process.ExitCode);
                Assert.Equal(1, serverProcess.Process.ExitCode);
                Assert.Contains(sourcePath, serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("was not found", serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.StartsWith("interop harness: role=client, testcase=retry failed:", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("completed managed retry download", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("completed managed retry response", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.False(File.Exists(destinationPath));
            }
            finally
            {
                TryDelete(sourcePath);
                TryDelete(destinationPath);
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
            $"Harness retry did not complete within {timeout}.\nSERVER STDOUT:\n{serverProcess.Stdout}\nSERVER STDERR:\n{serverProcess.Stderr}\nCLIENT STDOUT:\n{clientProcess.Stdout}\nCLIENT STDERR:\n{clientProcess.Stderr}");
    }

    private static async Task WaitForRetryLifecycleAsync(
        HarnessProcess serverProcess,
        HarnessProcess clientProcess,
        TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            bool serverObserved = serverProcess.Stdout.Contains("issued exactly one Retry (token=", StringComparison.OrdinalIgnoreCase);
            bool clientObserved = clientProcess.Stdout.Contains("observed exactly one Retry transition (token=", StringComparison.OrdinalIgnoreCase);
            if (serverObserved && clientObserved)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
        }

        throw new TimeoutException(
            $"Harness retry did not observe the expected client/server Retry lifecycle markers within {timeout}.\nSERVER STDOUT:\n{serverProcess.Stdout}\nSERVER STDERR:\n{serverProcess.Stderr}\nCLIENT STDOUT:\n{clientProcess.Stdout}\nCLIENT STDERR:\n{clientProcess.Stderr}");
    }

    private static void AssertContainsInOrder(string stdout, params string[] markers)
    {
        string[] lines = stdout.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
        int searchStart = 0;

        foreach (string marker in markers)
        {
            int foundIndex = -1;
            for (int i = searchStart; i < lines.Length; i++)
            {
                if (lines[i].Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    foundIndex = i;
                    break;
                }
            }

            Assert.True(foundIndex >= 0, $"Expected to find '{marker}' after line {searchStart} in stdout:\n{stdout}");
            searchStart = foundIndex + 1;
        }
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

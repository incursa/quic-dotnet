using System.Diagnostics;
using System.Net;
using System.Text;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessProcessObservabilityTests
{
    [Fact]
    public async Task ChildProcessHandshakeDownloadsTheRequestedFileAndKeepsStderrEmptyOnTheGreenPath()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string relativePath = $"handshake-{Guid.NewGuid():N}.txt";
            string requestPath = $"/{relativePath}";
            string requests = $"https://localhost:{listenEndPoint.Port}{requestPath}";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string sourcePath = Path.Combine(sourceRoot, relativePath);
            string destinationPath = Path.Combine(destinationRoot, relativePath);
            byte[] payload = Encoding.UTF8.GetBytes($"managed handshake proof {Guid.NewGuid():N}");

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            File.WriteAllBytes(sourcePath, payload);
            TryDelete(destinationPath);

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "handshake", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "handshake", requests, harnessDll);
                await WaitForPairMarkersAsync(
                    serverProcess,
                    clientProcess,
                    "completed managed handshake response",
                    "completed managed handshake download",
                    TimeSpan.FromSeconds(20));
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

                Assert.Equal(0, serverProcess.Process.ExitCode);
                Assert.Equal(0, clientProcess.Process.ExitCode);
                Assert.Empty(serverProcess.Stderr);
                Assert.Empty(clientProcess.Stderr);
                Assert.True(File.Exists(destinationPath));
                Assert.Equal(payload, File.ReadAllBytes(destinationPath));
                Assert.Contains("role=server, testcase=handshake", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("role=client, testcase=handshake", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                AssertContainsInOrder(
                    serverProcess.Stdout,
                    "listening on",
                    "completed managed listener bootstrap",
                    "completed managed handshake response");
                AssertContainsInOrder(
                    clientProcess.Stdout,
                    "connecting to",
                    "completed managed client bootstrap",
                    "completed managed handshake download");
            }
            finally
            {
                TryDelete(sourcePath);
                TryDelete(destinationPath);
            }
        });
    }

    [Fact]
    public async Task ChildProcessPostHandshakeStreamEmitsLifecycleMarkersInOrderAndKeepsStderrEmptyOnTheGreenPath()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string requests = $"https://localhost:{listenEndPoint.Port}/post-handshake-stream";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "post-handshake-stream", requests, harnessDll);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "post-handshake-stream", requests, harnessDll);
            await WaitForPairMarkersAsync(
                serverProcess,
                clientProcess,
                "accepted stream",
                "opened stream",
                TimeSpan.FromSeconds(15));
            await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(15));

            Assert.Equal(0, serverProcess.Process.ExitCode);
            Assert.Equal(0, clientProcess.Process.ExitCode);
            Assert.Empty(serverProcess.Stderr);
            Assert.Empty(clientProcess.Stderr);
            Assert.Contains("role=server, testcase=post-handshake-stream", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("role=client, testcase=post-handshake-stream", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            AssertContainsInOrder(
                serverProcess.Stdout,
                "listening on",
                "accepted stream");
            AssertContainsInOrder(
                clientProcess.Stdout,
                "connecting to",
                "opened stream");
        });
    }

    [Fact]
    public async Task ChildProcessRetryEmitsLifecycleMarkersInOrderAndKeepsStderrEmptyOnTheGreenPath()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string requests = $"https://localhost:{listenEndPoint.Port}/retry";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "retry", requests, harnessDll);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "retry", requests, harnessDll);
            await WaitForPairMarkersAsync(
                serverProcess,
                clientProcess,
                "completed managed listener bootstrap",
                "completed managed client bootstrap",
                TimeSpan.FromSeconds(20));
            await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

            Assert.Equal(0, serverProcess.Process.ExitCode);
            Assert.Equal(0, clientProcess.Process.ExitCode);
            Assert.Empty(serverProcess.Stderr);
            Assert.Empty(clientProcess.Stderr);
            Assert.Contains("role=server, testcase=retry", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("role=client, testcase=retry", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            AssertContainsInOrder(
                serverProcess.Stdout,
                "listening on",
                "issued exactly one Retry",
                "completed managed listener bootstrap");
            AssertContainsInOrder(
                clientProcess.Stdout,
                "connecting to",
                "observed exactly one Retry transition",
                "completed managed client bootstrap");
        });
    }

    [Fact]
    public async Task ChildProcessTransferEmitsLifecycleMarkersInOrderAndKeepsStderrEmptyOnTheGreenPath()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string relativePath = $"transfer-{Guid.NewGuid():N}.txt";
            string requestPath = $"/{relativePath}";
            string requests = $"https://localhost:{listenEndPoint.Port}{requestPath}";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string sourcePath = Path.Combine(sourceRoot, relativePath);
            string destinationPath = Path.Combine(destinationRoot, relativePath);
            byte[] payload = Encoding.UTF8.GetBytes($"managed transfer proof {Guid.NewGuid():N}");

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            File.WriteAllBytes(sourcePath, payload);
            TryDelete(destinationPath);

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", requests, harnessDll);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", requests, harnessDll);
                await WaitForPairMarkersAsync(
                    serverProcess,
                    clientProcess,
                    "completed managed transfer from",
                    "completed managed transfer to",
                    TimeSpan.FromSeconds(20));
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

                Assert.Equal(0, serverProcess.Process.ExitCode);
                Assert.Equal(0, clientProcess.Process.ExitCode);
                Assert.Empty(serverProcess.Stderr);
                Assert.Empty(clientProcess.Stderr);
                Assert.True(File.Exists(destinationPath));
                Assert.Equal(payload, File.ReadAllBytes(destinationPath));
                Assert.Contains("role=server, testcase=transfer", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("role=client, testcase=transfer", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                AssertContainsInOrder(
                    serverProcess.Stdout,
                    "listening on",
                    "transferring",
                    "completed managed transfer from");
                AssertContainsInOrder(
                    clientProcess.Stdout,
                    "connecting to",
                    "completed managed transfer to");
            }
            finally
            {
                TryDelete(sourcePath);
                TryDelete(destinationPath);
            }
        });
    }

    [Fact]
    public async Task FailureHelperIncludesBothClientAndServerStreamsWhenTheExpectedMarkersNeverAppear()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string requests = $"https://localhost:{listenEndPoint.Port}/post-handshake-stream";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "post-handshake-stream", requests, harnessDll);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "post-handshake-stream", requests, harnessDll);
            await WaitForPairMarkersAsync(
                serverProcess,
                clientProcess,
                "accepted stream",
                "opened stream",
                TimeSpan.FromSeconds(15));

            TimeoutException exception = await Assert.ThrowsAsync<TimeoutException>(() => WaitForPairMarkersAsync(
                serverProcess,
                clientProcess,
                "completed managed transfer from",
                "completed managed transfer to",
                TimeSpan.FromMilliseconds(250)));

            Assert.Contains("SERVER STDOUT:", exception.Message, StringComparison.Ordinal);
            Assert.Contains("SERVER STDERR:", exception.Message, StringComparison.Ordinal);
            Assert.Contains("CLIENT STDOUT:", exception.Message, StringComparison.Ordinal);
            Assert.Contains("CLIENT STDERR:", exception.Message, StringComparison.Ordinal);
            Assert.Contains("role=server, testcase=post-handshake-stream", exception.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("role=client, testcase=post-handshake-stream", exception.Message, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static async Task WaitForPairMarkersAsync(
        HarnessProcess serverProcess,
        HarnessProcess clientProcess,
        string serverMarker,
        string clientMarker,
        TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            bool serverObserved = serverProcess.Stdout.Contains(serverMarker, StringComparison.OrdinalIgnoreCase);
            bool clientObserved = clientProcess.Stdout.Contains(clientMarker, StringComparison.OrdinalIgnoreCase);

            if (serverObserved && clientObserved)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
        }

        throw new TimeoutException(
            $"The harness processes did not write the expected lifecycle markers within {timeout}.{Environment.NewLine}" +
            $"Expected server marker: '{serverMarker}'{Environment.NewLine}" +
            $"Expected client marker: '{clientMarker}'{Environment.NewLine}" +
            $"SERVER STDOUT:{Environment.NewLine}{serverProcess.Stdout}{Environment.NewLine}" +
            $"SERVER STDERR:{Environment.NewLine}{serverProcess.Stderr}{Environment.NewLine}" +
            $"CLIENT STDOUT:{Environment.NewLine}{clientProcess.Stdout}{Environment.NewLine}" +
            $"CLIENT STDERR:{Environment.NewLine}{clientProcess.Stderr}");
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
        if (completed != completionTask)
        {
            throw new TimeoutException(
                $"The harness processes did not exit within {timeout}.{Environment.NewLine}" +
                $"SERVER STDOUT:{Environment.NewLine}{serverProcess.Stdout}{Environment.NewLine}" +
                $"SERVER STDERR:{Environment.NewLine}{serverProcess.Stderr}{Environment.NewLine}" +
                $"CLIENT STDOUT:{Environment.NewLine}{clientProcess.Stdout}{Environment.NewLine}" +
                $"CLIENT STDERR:{Environment.NewLine}{clientProcess.Stderr}");
        }

        await completionTask.ConfigureAwait(false);
        await Task.WhenAll(serverProcess.CompleteCaptureAsync(), clientProcess.CompleteCaptureAsync()).ConfigureAwait(false);
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

            Assert.True(foundIndex >= 0, $"Expected to find '{marker}' after line {searchStart} in stdout:{Environment.NewLine}{stdout}");
            searchStart = foundIndex + 1;
        }
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
                $"The harness process did not write '{value}' within {timeout}.{Environment.NewLine}" +
                $"STDOUT:{Environment.NewLine}{Stdout}{Environment.NewLine}" +
                $"STDERR:{Environment.NewLine}{Stderr}");
        }

        public Task CompleteCaptureAsync()
        {
            return Task.WhenAll(stdoutTask, stderrTask);
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

                await CompleteCaptureAsync().ConfigureAwait(false);
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

using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0020")]
public sealed class REQ_QUIC_INT_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ManagedChildProcessHarnessSupportsVersionNegotiationUsingReservedClientVersions()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            using TempDirectoryFixture qlogFixture = new("interop-versionnegotiation-qlog");
            string qlogDirectory = qlogFixture.CreateSubdirectory("qlog");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string requests = $"https://localhost:{listenEndPoint.Port}/";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "versionnegotiation", requests, harnessDll, qlogDirectory);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "versionnegotiation", requests, harnessDll, qlogDirectory);
            await WaitForPairMarkersAsync(
                serverProcess,
                clientProcess,
                "completed managed listener bootstrap after sending version negotiation",
                "observed version negotiation using reserved version",
                TimeSpan.FromSeconds(20));
            await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

            Assert.Equal(0, serverProcess.Process.ExitCode);
            Assert.Equal(0, clientProcess.Process.ExitCode);
            Assert.Empty(serverProcess.Stderr);
            Assert.Empty(clientProcess.Stderr);
            Assert.Contains("role=server, testcase=versionnegotiation", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("role=client, testcase=versionnegotiation", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            AssertContainsInOrder(
                serverProcess.Stdout,
                "listening on",
                "waiting for reserved client version",
                "completed managed listener bootstrap after sending version negotiation");
            AssertContainsInOrder(
                clientProcess.Stdout,
                "connecting to",
                "observed version negotiation using reserved version");
            Assert.True(Directory.GetFiles(qlogDirectory, "*.qlog").Length >= 2);
        });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientVersionNegotiationDispatchRejectsHttpRequestsLikeTheHandshakePath()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(
            InteropHarnessTestSupport.CreateEnvironment("client", "versionnegotiation", "http://localhost:443/dispatch"),
            stdout,
            stderr);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());
        Assert.Equal("REQUESTS entry 'http://localhost:443/dispatch' must use https for testcase dispatch." + Environment.NewLine, stderr.ToString());
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

        public static HarnessProcess Start(string role, string testCase, string requests, string harnessDll, string? qlogDirectory = null)
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
            if (qlogDirectory is not null)
            {
                startInfo.Environment["QLOGDIR"] = qlogDirectory;
            }

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

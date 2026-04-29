using System.Diagnostics;
using System.Net;
using System.Text;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessProcessFailureTests
{
    [Fact]
    public async Task TransferWithMissingSourceFileReportsActionableDiagnosticsAndExitsNonZero()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            using TempDirectoryFixture fixture = new(nameof(InteropHarnessProcessFailureTests));
            string qlogDirectory = fixture.CreateSubdirectory("qlog");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
            string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
            string[] relativePaths =
            [
                $"missing-transfer-source-{Guid.NewGuid():N}-1.txt",
                $"missing-transfer-source-{Guid.NewGuid():N}-2.txt",
                $"missing-transfer-source-{Guid.NewGuid():N}-3.txt",
            ];
            string request = string.Join(
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
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            Directory.CreateDirectory(sourceRoot);
            Directory.CreateDirectory(destinationRoot);
            File.WriteAllBytes(sourcePaths[0], Encoding.UTF8.GetBytes($"transfer proof one {Guid.NewGuid():N}"));
            TryDelete(sourcePaths[1]);
            File.WriteAllBytes(sourcePaths[2], Encoding.UTF8.GetBytes($"transfer proof three {Guid.NewGuid():N}"));

            foreach (string destinationPath in destinationPaths)
            {
                TryDelete(destinationPath);
            }

            try
            {
                await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", request, harnessDll, qlogDirectory);
                await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

                await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", request, harnessDll, qlogDirectory);
                await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(35));

                Assert.Equal(1, serverProcess.Process.ExitCode);
                Assert.Equal(1, clientProcess.Process.ExitCode);
                Assert.Contains(sourcePaths[1], serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("was not found", serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.StartsWith("interop harness: role=client, testcase=transfer failed:", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("stream 3", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("stream 3/3", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
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
    public async Task MalformedRootPathTransferRequestFailsWithoutSuccessMarkers()
    {
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessProcessFailureTests));
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string request = $"https://localhost:{listenEndPoint.Port}/";
        string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

        await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", request, harnessDll, qlogDirectory);
        await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", request, harnessDll, qlogDirectory);

        await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(10));

        Assert.Equal(1, serverProcess.Process.ExitCode);
        Assert.Equal(1, clientProcess.Process.ExitCode);
        Assert.Empty(serverProcess.Stdout);
        Assert.Empty(clientProcess.Stdout);
        Assert.Contains(request, serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("non-root path", serverProcess.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(request, clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("non-root path", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }

    [Fact]
    public async Task IpLiteralHostAgainstLocalhostOnlyCertificateFailsWithClientDiagnostics()
    {
        await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
        {
            using TempDirectoryFixture fixture = new(nameof(InteropHarnessProcessFailureTests));
            string qlogDirectory = fixture.CreateSubdirectory("qlog");
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
            string request = $"https://127.0.0.1:{listenEndPoint.Port}/handshake";
            string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;

            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "handshake", request, harnessDll, qlogDirectory);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "handshake", request, harnessDll, qlogDirectory);
            Task clientExitTask = clientProcess.Process.WaitForExitAsync();
            Task completed = await Task.WhenAny(clientExitTask, Task.Delay(TimeSpan.FromSeconds(20))).ConfigureAwait(false);
            if (completed != clientExitTask)
            {
                throw new TimeoutException(
                    $"The client harness process did not exit within 00:00:20.{Environment.NewLine}" +
                    $"SERVER STDOUT:{Environment.NewLine}{serverProcess.Stdout}{Environment.NewLine}" +
                    $"SERVER STDERR:{Environment.NewLine}{serverProcess.Stderr}{Environment.NewLine}" +
                    $"CLIENT STDOUT:{Environment.NewLine}{clientProcess.Stdout}{Environment.NewLine}" +
                    $"CLIENT STDERR:{Environment.NewLine}{clientProcess.Stderr}");
            }

            await clientExitTask.ConfigureAwait(false);
            await clientProcess.CompleteCaptureAsync().ConfigureAwait(false);

            Assert.Equal(1, clientProcess.Process.ExitCode);
            Assert.Contains("listening on", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("completed managed listener bootstrap", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("certificate errors=", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("RemoteCertificateNameMismatch", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("failed:", clientProcess.Stderr, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("completed managed client bootstrap", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
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

        public static HarnessProcess Start(string role, string testCase, string requests, string harnessDll, string? qlogDir = null)
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

            if (!string.IsNullOrWhiteSpace(qlogDir))
            {
                startInfo.Environment["QLOGDIR"] = qlogDir;
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

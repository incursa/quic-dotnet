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
    public async Task ManagedChildProcessHarnessTransfersOneFileFromWwwToDownloadsAndCompletesOnEOF()
    {
        string harnessDll = typeof(InteropHarnessRunner).Assembly.Location;
        string relativePath = $"transfer-{Guid.NewGuid():N}.txt";
        string requestPath = $"/{relativePath}";
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string requests = $"https://127.0.0.1:{listenEndPoint.Port}{requestPath}";
        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string sourcePath = Path.Combine(sourceRoot, relativePath);
        string destinationPath = Path.Combine(destinationRoot, relativePath);
        byte[] payload = Encoding.UTF8.GetBytes($"managed transfer proof {Guid.NewGuid():N}");

        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(destinationRoot);
        File.WriteAllBytes(sourcePath, payload);

        if (File.Exists(destinationPath))
        {
            File.Delete(destinationPath);
        }

        try
        {
            await using HarnessProcess serverProcess = HarnessProcess.Start("server", "transfer", requests, harnessDll);
            await serverProcess.WaitForStdoutContainsAsync("listening on", TimeSpan.FromSeconds(10));

            await using HarnessProcess clientProcess = HarnessProcess.Start("client", "transfer", requests, harnessDll);
            await clientProcess.WaitForStdoutContainsAsync("completed managed transfer", TimeSpan.FromSeconds(10));
            await serverProcess.WaitForStdoutContainsAsync("completed managed transfer", TimeSpan.FromSeconds(10));
            await WaitForExitAsync(serverProcess, clientProcess, TimeSpan.FromSeconds(20));

            Assert.Equal(0, clientProcess.Process.ExitCode);
            Assert.Equal(0, serverProcess.Process.ExitCode);
            Assert.True(File.Exists(destinationPath));
            Assert.Equal(payload, File.ReadAllBytes(destinationPath));
            Assert.Contains("testcase=transfer", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed transfer", clientProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("testcase=transfer", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed transfer", serverProcess.Stdout, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(sourcePath);
            TryDelete(destinationPath);
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

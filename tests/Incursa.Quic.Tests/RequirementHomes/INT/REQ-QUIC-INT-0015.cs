using System.Net;
using System.Text;
using Incursa.Quic.InteropHarness;
using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0015")]
public sealed class REQ_QUIC_INT_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalhostMulticonnectSmokeCompletesSequentialRequestsWithQlogCapture()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-multiconnect");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string relativePathOne = $"preflight-multiconnect-{Guid.NewGuid():N}-1.txt";
        string relativePathTwo = $"preflight-multiconnect-{Guid.NewGuid():N}-2.txt";
        string sourcePathOne = Path.Combine(sourceRoot, relativePathOne);
        string sourcePathTwo = Path.Combine(sourceRoot, relativePathTwo);
        string destinationPathOne = Path.Combine(destinationRoot, relativePathOne);
        string destinationPathTwo = Path.Combine(destinationRoot, relativePathTwo);
        byte[] payloadOne = Encoding.UTF8.GetBytes($"preflight multiconnect payload one {Guid.NewGuid():N}");
        byte[] payloadTwo = Encoding.UTF8.GetBytes($"preflight multiconnect payload two {Guid.NewGuid():N}");

        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(destinationRoot);
        File.WriteAllBytes(sourcePathOne, payloadOne);
        File.WriteAllBytes(sourcePathTwo, payloadTwo);
        TryDelete(destinationPathOne);
        TryDelete(destinationPathTwo);

        try
        {
            HarnessRunResult? serverResult = null;
            HarnessRunResult? clientResult = null;

            await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
            {
                IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
                string requests = $"https://localhost:{listenEndPoint.Port}/{relativePathOne} https://localhost:{listenEndPoint.Port}/{relativePathTwo}";

                (serverResult, clientResult) = await RunHarnessPairAsync(
                    "multiconnect",
                    requests,
                    InteropHarnessEnvironment.CertificatePath,
                    InteropHarnessEnvironment.PrivateKeyPath,
                    qlogDirectory);
            });

            Assert.NotNull(serverResult);
            Assert.NotNull(clientResult);

            Assert.Equal(0, serverResult!.ExitCode);
            Assert.Equal(0, clientResult!.ExitCode);
            Assert.Contains("testcase=multiconnect", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("testcase=multiconnect", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 1/2", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 2/2", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 1/2", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 2/2", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed multiconnect transfer", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed multiconnect transfer", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);

            Assert.True(File.Exists(destinationPathOne));
            Assert.True(File.Exists(destinationPathTwo));
            Assert.Equal(payloadOne, File.ReadAllBytes(destinationPathOne));
            Assert.Equal(payloadTwo, File.ReadAllBytes(destinationPathTwo));

            string[] qlogFiles = Directory.GetFiles(qlogDirectory, "*.qlog");
            Assert.NotEmpty(qlogFiles);
            QlogFile qlog = QlogJsonSerializer.Deserialize(File.ReadAllText(qlogFiles[0]));
            Assert.NotEmpty(qlog.Traces);
        }
        finally
        {
            TryDelete(sourcePathOne);
            TryDelete(sourcePathTwo);
            TryDelete(destinationPathOne);
            TryDelete(destinationPathTwo);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MalformedMulticonnectRequestsFailBeforeTransportSuccessIsClaimed()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-malformed-multiconnect");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = InteropHarnessTestSupport.CreateTlsMaterialFixture(fixture);
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string requests = $"https://localhost:{listenEndPoint.Port}/one not-a-url";

        (HarnessRunResult serverResult, HarnessRunResult clientResult) = await RunHarnessPairWithoutListeningAsync(
            "multiconnect",
            requests,
            CertificatePath,
            PrivateKeyPath,
            qlogDirectory);

        Assert.Equal(1, serverResult.ExitCode);
        Assert.Equal(1, clientResult.ExitCode);
        Assert.Empty(serverResult.Stdout);
        Assert.Empty(clientResult.Stdout);
        Assert.Contains("not a valid absolute URL", serverResult.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not a valid absolute URL", clientResult.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }

    private static Task<int> StartHarnessRunAsync(
        string role,
        string testcase,
        string request,
        string? qlogDirectory,
        string certificatePath,
        string privateKeyPath,
        RecordingTextWriter stdout,
        RecordingTextWriter stderr)
    {
        Task<int> runTask = Task.Factory.StartNew(
            () => InteropHarnessRunner.Run(
                InteropHarnessTestSupport.CreateEnvironment(role, testcase, request, qlogDirectory),
                stdout,
                stderr,
                certificatePath,
                privateKeyPath),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        return runTask;
    }

    private static async Task<(HarnessRunResult Server, HarnessRunResult Client)> RunHarnessPairAsync(
        string testcase,
        string request,
        string certificatePath,
        string privateKeyPath,
        string? qlogDirectory)
    {
        RecordingTextWriter serverStdout = new();
        RecordingTextWriter serverStderr = new();
        RecordingTextWriter clientStdout = new();
        RecordingTextWriter clientStderr = new();

        Task<int> serverTask = StartHarnessRunAsync("server", testcase, request, qlogDirectory, certificatePath, privateKeyPath, serverStdout, serverStderr);
        await WaitForTextAsync(serverTask, serverStdout, "listening on", TimeSpan.FromSeconds(10)).ConfigureAwait(false);

        Task<int> clientTask = StartHarnessRunAsync("client", testcase, request, qlogDirectory, certificatePath, privateKeyPath, clientStdout, clientStderr);
        try
        {
            await WaitForPairCompletionAsync(serverTask, clientTask, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new TimeoutException(
                $"{ex.Message}\nSERVER STDOUT:\n{serverStdout}\nSERVER STDERR:\n{serverStderr}\nCLIENT STDOUT:\n{clientStdout}\nCLIENT STDERR:\n{clientStderr}",
                ex);
        }

        return (
            new HarnessRunResult(await serverTask.ConfigureAwait(false), serverStdout.ToString(), serverStderr.ToString()),
            new HarnessRunResult(await clientTask.ConfigureAwait(false), clientStdout.ToString(), clientStderr.ToString()));
    }

    private static async Task<(HarnessRunResult Server, HarnessRunResult Client)> RunHarnessPairWithoutListeningAsync(
        string testcase,
        string request,
        string certificatePath,
        string privateKeyPath,
        string? qlogDirectory)
    {
        RecordingTextWriter serverStdout = new();
        RecordingTextWriter serverStderr = new();
        RecordingTextWriter clientStdout = new();
        RecordingTextWriter clientStderr = new();

        Task<int> serverTask = StartHarnessRunAsync("server", testcase, request, qlogDirectory, certificatePath, privateKeyPath, serverStdout, serverStderr);
        Task<int> clientTask = StartHarnessRunAsync("client", testcase, request, qlogDirectory, certificatePath, privateKeyPath, clientStdout, clientStderr);

        try
        {
            await WaitForPairCompletionAsync(serverTask, clientTask, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            throw new TimeoutException(
                $"{ex.Message}\nSERVER STDOUT:\n{serverStdout}\nSERVER STDERR:\n{serverStderr}\nCLIENT STDOUT:\n{clientStdout}\nCLIENT STDERR:\n{clientStderr}",
                ex);
        }

        return (
            new HarnessRunResult(await serverTask.ConfigureAwait(false), serverStdout.ToString(), serverStderr.ToString()),
            new HarnessRunResult(await clientTask.ConfigureAwait(false), clientStdout.ToString(), clientStderr.ToString()));
    }

    private static async Task WaitForPairCompletionAsync(Task firstTask, Task secondTask, TimeSpan timeout)
    {
        Task completionTask = Task.WhenAll(firstTask, secondTask);
        Task completed = await Task.WhenAny(completionTask, Task.Delay(timeout)).ConfigureAwait(false);
        if (completed == completionTask)
        {
            await completionTask.ConfigureAwait(false);
            return;
        }

        throw new TimeoutException($"The local harness pair did not complete within {timeout}.");
    }

    private static async Task WaitForTextAsync(
        Task task,
        RecordingTextWriter writer,
        string expected,
        TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            if (writer.Contains(expected))
            {
                return;
            }

            if (task.IsCompleted)
            {
                break;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(50)).ConfigureAwait(false);
        }

        throw new TimeoutException($"The harness did not write '{expected}' within {timeout}.\nSTDOUT:\n{writer}");
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

    private sealed record HarnessRunResult(int ExitCode, string Stdout, string Stderr);

    private sealed class RecordingTextWriter : TextWriter
    {
        private readonly StringBuilder builder = new();
        private readonly object gate = new();

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(string? value)
        {
            lock (gate)
            {
                builder.Append(value);
            }
        }

        public override void WriteLine(string? value)
        {
            lock (gate)
            {
                builder.AppendLine(value);
            }
        }

        public bool Contains(string value)
        {
            lock (gate)
            {
                return builder.ToString().Contains(value, StringComparison.OrdinalIgnoreCase);
            }
        }

        public override string ToString()
        {
            lock (gate)
            {
                return builder.ToString();
            }
        }
    }
}

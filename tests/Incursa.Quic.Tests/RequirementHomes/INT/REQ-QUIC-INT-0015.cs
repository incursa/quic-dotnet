using System.Net;
using System.Security.Cryptography.X509Certificates;
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
    public async Task LocalhostMulticonnectSmokeCompletesSequentialHttp09DownloadsWithQlogCapture()
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
            Assert.Contains("connectionCount=2", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("accepted managed connection 1/2", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("accepted managed connection 2/2", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 1/2", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("connection 2/2", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("accepted multiconnect request stream 1", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains($"parsed HTTP/0.9 request target /{relativePathOne}", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains($"parsed HTTP/0.9 request target /{relativePathTwo}", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains($"sent HTTP/0.9 request line for /{relativePathOne}", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains($"sent HTTP/0.9 request line for /{relativePathTwo}", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed multiconnect response", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed multiconnect download", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);

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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task MulticonnectServerRoleAcceptsEmptyRequestsForRunnerDispatch()
    {
        // Provenance: artifacts\interop-runner\20260422-142116187-server-nginx failed before QUIC
        // work because the external runner passed REQUESTS_SERVER="" for server-role multiconnect,
        // so this regression locks the empty-server-REQUESTS dispatch plan locally.
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "multiconnect",
                requests: string.Empty),
            out InteropHarnessEnvironment? settings,
            out string? errorMessage));
        Assert.NotNull(settings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner planner = new(settings!, TextWriter.Null);
        InteropHarnessRunner.ServerMulticonnectDispatchPlanBuildResult result =
            await InteropHarnessRunner.TryCreateServerMulticonnectDispatchPlanAsync(settings!, planner);

        Assert.True(result.Success);
        Assert.NotNull(result.Plan);
        Assert.Null(result.ErrorMessage);
        Assert.Equal(IPAddress.Any, result.Plan!.ListenEndPoint.Address);
        Assert.Equal(443, result.Plan.ListenEndPoint.Port);
        Assert.Equal(0, result.Plan.ExpectedConnectionCount);
        Assert.Equal(0, result.Plan.ConfiguredConnectionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MulticonnectClientFailsHonestlyWhenASequentialResponseStallsAfterTheRequestLine()
    {
        // Regression from the preserved 2026-04-21 client-role quic-go multiconnect handshakeloss run:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-182027795-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-b7d0662decde48a0bbd3ea68033bf1d8.qlog
        // Connection 7/50 sent the HTTP/0.9 request line for /dry-jealous-tie and then
        // stalled without response bytes or EOF, which kept the child process alive until the
        // outer runner timed out. The bounded multiconnect slice must fail honestly instead of
        // hanging when one sequential response stops making progress after the request is sent.
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-stalled-multiconnect");
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string relativePath = $"stalled-multiconnect-{Guid.NewGuid():N}.txt";
        string destinationPath = Path.Combine(destinationRoot, relativePath);
        string stagingPath = destinationPath + ".partial";
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string requests = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
        RecordingTextWriter clientStdout = new();
        RecordingTextWriter clientStderr = new();

        Directory.CreateDirectory(destinationRoot);
        TryDelete(destinationPath);
        TryDelete(stagingPath);

        try
        {
            Assert.True(
                InteropHarnessEnvironment.TryCreate(
                    InteropHarnessTestSupport.CreateEnvironment("client", "multiconnect", requests),
                    out InteropHarnessEnvironment? settings,
                    out string? errorMessage));
            Assert.Null(errorMessage);
            Assert.NotNull(settings);

            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(InteropHarnessPreflightPlanner.CreateSupportedServerOptions(serverCertificate)),
            };

            await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
            Task stalledServerTask = Task.Run(async () =>
            {
                await using QuicConnection serverConnection = await listener.AcceptConnectionAsync().ConfigureAwait(false);
                await using QuicStream requestStream = await serverConnection.AcceptInboundStreamAsync().ConfigureAwait(false);
                await DrainClientRequestAsync(requestStream).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            });

            int exitCode = await InteropHarnessRunner.RunMulticonnectClientAsync(
                settings!,
                clientStdout,
                clientStderr,
                TimeSpan.FromMilliseconds(250)).WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(1, exitCode);
            Assert.Contains("sent HTTP/0.9 request line", clientStdout.ToString(), StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Timed out waiting for multiconnect response bytes or EOF", clientStdout.ToString(), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("completed managed multiconnect download", clientStdout.ToString(), StringComparison.OrdinalIgnoreCase);
            Assert.Empty(clientStderr.ToString());
            Assert.False(File.Exists(destinationPath));
            Assert.False(File.Exists(stagingPath));

            await stalledServerTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            TryDelete(destinationPath);
            TryDelete(stagingPath);
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MulticonnectRejectsConflictingHostOrPortBeforeListenerStartup()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-conflicting-multiconnect");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = InteropHarnessTestSupport.CreateTlsMaterialFixture(fixture);
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string requests = $"https://localhost:{listenEndPoint.Port}/one https://127.0.0.1:{listenEndPoint.Port}/two";

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
        Assert.Contains("must target the same host and port", serverResult.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("must target the same host and port", clientResult.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task TransientSendCreditRetry_WaitsOutTheExactCongestionExhaustionObservedByMulticonnect()
    {
        // Regression from the preserved 2026-04-21 client-role quic-go multiconnect run:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-142834827-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt
        // Connection 7/50 reached certificate validation and then failed before
        // "opened multiconnect request stream 7/50" with the exact message
        // "The congestion controller cannot send another ordinary packet." The harness
        // must wait out that transient send-credit condition instead of turning it into
        // a false testcase failure before any HTTP/0.9 request bytes are sent.
        int attempts = 0;

        string result = await InteropHarnessRunner.RetryTransientSendCreditAsync(
            () =>
            {
                attempts++;
                return attempts < 3
                    ? ValueTask.FromException<string>(new InvalidOperationException("The congestion controller cannot send another ordinary packet."))
                    : ValueTask.FromResult("opened");
            },
            "Timed out waiting for QUIC stream open send credit.");

        Assert.Equal("opened", result);
        Assert.Equal(3, attempts);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task TransientSendCreditRetry_DoesNotSwallowUnrelatedStreamOpenFailures()
    {
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            InteropHarnessRunner.RetryTransientSendCreditAsync(
                () => ValueTask.FromException<string>(new InvalidOperationException("The connection is not established.")),
                "Timed out waiting for QUIC stream open send credit."));

        Assert.Equal("The connection is not established.", exception.Message);
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

    private static async Task DrainClientRequestAsync(QuicStream requestStream)
    {
        byte[] buffer = new byte[128];
        int totalBytesRead = 0;

        while (true)
        {
            int bytesRead = await requestStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }

            totalBytesRead += bytesRead;
        }

        Assert.True(totalBytesRead > 0);
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

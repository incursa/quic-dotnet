using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Incursa.Quic.InteropHarness;
using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0014")]
public sealed class REQ_QUIC_INT_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task PlannerSeparatesLocalDispatchRequestParsingQlogSelectionAndTransferPathMapping()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-planner");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");

        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "handshake",
                requests: "https://localhost:4242/preflight",
                qlogDir: qlogDirectory),
            out InteropHarnessEnvironment? clientSettings,
            out string? errorMessage));
        Assert.NotNull(clientSettings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner clientPlanner = new(clientSettings!, TextWriter.Null);
        Assert.True(clientPlanner.TryGetDispatchRequestUri(out Uri? requestUri, out errorMessage));
        Assert.NotNull(requestUri);
        Assert.Null(errorMessage);
        Assert.Equal("https", requestUri!.Scheme);
        Assert.Equal("localhost", requestUri.Host);
        Assert.Equal(4242, requestUri.Port);
        Assert.Equal("client-handshake", clientPlanner.QlogFileStem);
        using InteropHarnessQlogCaptureScope? qlogScope = clientPlanner.CreateQlogCaptureScope();
        Assert.NotNull(qlogScope);

        IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri);
        Assert.True(IPAddress.IsLoopback(remoteEndPoint.Address));
        Assert.Equal(4242, remoteEndPoint.Port);

        Assert.True(InteropHarnessPreflightPlanner.TryGetTransferPaths(
            new Uri("https://localhost:4242/files/subdir/payload.txt"),
            out string? relativePath,
            out string? sourcePath,
            out string? destinationPath,
            out errorMessage));
        Assert.Equal(Path.Combine("files", "subdir", "payload.txt"), relativePath);
        Assert.Equal(Path.GetFullPath(Path.Combine(InteropHarnessEnvironment.WwwDirectory, relativePath!)), sourcePath);
        Assert.Equal(Path.GetFullPath(Path.Combine(InteropHarnessEnvironment.DownloadsDirectory, relativePath!)), destinationPath);

        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string fallbackRelativePath = $"!preflight-default-{Guid.NewGuid():N}.txt";
        string fallbackSourcePath = Path.Combine(sourceRoot, fallbackRelativePath);
        string fallbackDestinationPath = Path.Combine(destinationRoot, fallbackRelativePath);
        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(destinationRoot);
        File.WriteAllText(fallbackSourcePath, "fallback");

        try
        {
            Assert.True(InteropHarnessPreflightPlanner.TryGetTransferPaths(
                null,
                out string? defaultRelativePath,
                out string? defaultSourcePath,
                out string? defaultDestinationPath,
                out errorMessage));
            Assert.Equal(fallbackRelativePath, defaultRelativePath);
            Assert.Equal(Path.GetFullPath(fallbackSourcePath), defaultSourcePath);
            Assert.Equal(Path.GetFullPath(fallbackDestinationPath), defaultDestinationPath);
        }
        finally
        {
            TryDelete(fallbackSourcePath);
            TryDelete(fallbackDestinationPath);
        }

        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "server",
                testcase: "retry",
                qlogDir: qlogDirectory),
            out InteropHarnessEnvironment? serverSettings,
            out errorMessage));
        Assert.NotNull(serverSettings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner serverPlanner = new(serverSettings!, TextWriter.Null);
        Assert.True(serverPlanner.TryGetDispatchRequestUri(out requestUri, out errorMessage, allowEmptyRequests: true));
        Assert.Null(requestUri);
        Assert.Null(errorMessage);
        Assert.Equal("server-retry", serverPlanner.QlogFileStem);

        IPEndPoint listenEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeListenEndPointAsync(requestUri);
        Assert.Equal(IPAddress.Any, listenEndPoint.Address);
        Assert.Equal(443, listenEndPoint.Port);

        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "handshake",
                requests: "https://localhost:4242/preflight"),
            out InteropHarnessEnvironment? noQlogSettings,
            out errorMessage));
        Assert.NotNull(noQlogSettings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner noQlogPlanner = new(noQlogSettings!, TextWriter.Null);
        using InteropHarnessQlogCaptureScope? noQlogScope = noQlogPlanner.CreateQlogCaptureScope();
        if (OperatingSystem.IsLinux())
        {
            Assert.NotNull(noQlogScope);
            Assert.Equal("/logs/qlog", Path.GetDirectoryName(noQlogScope!.OutputPath));
        }
        else
        {
            Assert.Null(noQlogScope);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalhostHandshakeSmokeCompletesWithQlogCapture()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-handshake");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = CreateServerCertificateFiles(fixture, "localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string request = $"https://localhost:{listenEndPoint.Port}/handshake";

        (HarnessRunResult server, HarnessRunResult client) = await RunHarnessPairAsync(
            "handshake",
            request,
            CertificatePath,
            PrivateKeyPath,
            qlogDirectory);

        Assert.Equal(0, server.ExitCode);
        Assert.Equal(0, client.ExitCode);
        Assert.Contains("completed managed listener bootstrap", server.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("completed managed client bootstrap", client.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("qlog capture enabled", server.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("qlog capture enabled", client.Stdout, StringComparison.OrdinalIgnoreCase);

        string[] qlogFiles = Directory.GetFiles(qlogDirectory, "*.qlog");
        Assert.NotEmpty(qlogFiles);
        QlogFile qlog = QlogJsonSerializer.Deserialize(File.ReadAllText(qlogFiles[0]));
        Assert.NotEmpty(qlog.Traces);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalhostRetrySmokeCompletesWithQlogCapture()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-retry");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = CreateServerCertificateFiles(fixture, "localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string request = $"https://localhost:{listenEndPoint.Port}/retry";

        (HarnessRunResult server, HarnessRunResult client) = await RunHarnessPairAsync(
            "retry",
            request,
            CertificatePath,
            PrivateKeyPath,
            qlogDirectory);

        Assert.Equal(0, server.ExitCode);
        Assert.Equal(0, client.ExitCode);
        Assert.Contains("issued exactly one Retry", server.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("observed exactly one Retry transition", client.Stdout, StringComparison.OrdinalIgnoreCase);

        string[] qlogFiles = Directory.GetFiles(qlogDirectory, "*.qlog");
        Assert.NotEmpty(qlogFiles);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalhostTransferSmokeOverwritesPreexistingDestinationFileWithQlogCapture()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-transfer");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = CreateServerCertificateFiles(fixture, "localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string relativePath = $"preflight-transfer-{Guid.NewGuid():N}.txt";
        string request = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string sourcePath = Path.Combine(sourceRoot, relativePath);
        string destinationPath = Path.Combine(destinationRoot, relativePath);
        byte[] payload = Encoding.UTF8.GetBytes($"preflight transfer payload {Guid.NewGuid():N}");
        byte[] preexistingPayload = Encoding.UTF8.GetBytes($"preexisting destination payload {Guid.NewGuid():N}");
        Assert.NotEqual(preexistingPayload, payload);

        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(destinationRoot);
        File.WriteAllBytes(sourcePath, payload);
        File.WriteAllBytes(destinationPath, preexistingPayload);

        try
        {
            (HarnessRunResult server, HarnessRunResult client) = await RunHarnessPairAsync(
                "transfer",
                request,
                CertificatePath,
                PrivateKeyPath,
                qlogDirectory);

            Assert.Equal(0, server.ExitCode);
            Assert.Equal(0, client.ExitCode);
            Assert.Contains("completed managed transfer", server.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("completed managed transfer", client.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(destinationPath));
            Assert.Equal(payload, File.ReadAllBytes(destinationPath));

            string[] qlogFiles = Directory.GetFiles(qlogDirectory, "*.qlog");
            Assert.NotEmpty(qlogFiles);
        }
        finally
        {
            TryDelete(sourcePath);
            TryDelete(destinationPath);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LocalhostTransferSmokeFailsWhenTheSourceFileIsMissing()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-missing-transfer-source");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = CreateServerCertificateFiles(fixture, "localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string relativePath = $"missing-transfer-source-{Guid.NewGuid():N}.txt";
        string request = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
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
            (HarnessRunResult server, HarnessRunResult client) = await RunHarnessPairAsync(
                "transfer",
                request,
                CertificatePath,
                PrivateKeyPath,
                qlogDirectory);

            Assert.Equal(1, server.ExitCode);
            Assert.Equal(1, client.ExitCode);
            Assert.Contains("missing source file", server.Stderr, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith(
                "interop harness: role=client, testcase=transfer failed:",
                client.Stderr,
                StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("completed managed transfer", server.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("completed managed transfer", client.Stdout, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(sourcePath);
            TryDelete(destinationPath);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task IpLiteralHostStillFailsAgainstALocalhostOnlyCertificate()
    {
        using X509Certificate2 localhostCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");

        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "handshake",
                requests: "https://127.0.0.1:4242/handshake"),
            out InteropHarnessEnvironment? clientSettings,
            out string? errorMessage));
        Assert.NotNull(clientSettings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner planner = new(clientSettings!, TextWriter.Null);
        Assert.True(planner.TryGetDispatchRequestUri(out Uri? requestUri, out errorMessage));
        Assert.NotNull(requestUri);
        Assert.Equal("127.0.0.1", requestUri!.Host);

        IPEndPoint remoteEndPoint = await InteropHarnessPreflightPlanner.ResolveHandshakeRemoteEndPointAsync(requestUri);
        Assert.Equal(IPAddress.Loopback, remoteEndPoint.Address);

        QuicClientConnectionOptions clientOptions = planner.CreateSupportedClientOptions(remoteEndPoint, requestUri.Host);
        Assert.NotNull(clientOptions.ClientAuthenticationOptions);
        Assert.Equal("127.0.0.1", clientOptions.ClientAuthenticationOptions!.TargetHost);
        Assert.NotNull(clientOptions.ClientAuthenticationOptions.RemoteCertificateValidationCallback);
        Assert.NotNull(clientOptions.ClientAuthenticationOptions.ApplicationProtocols);
        IReadOnlyList<SslApplicationProtocol> applicationProtocols = clientOptions.ClientAuthenticationOptions.ApplicationProtocols!;
        Assert.Single(applicationProtocols);
        Assert.Equal(
            InteropHarnessProtocols.QuicInterop,
            applicationProtocols[0]);

        bool accepted = clientOptions.ClientAuthenticationOptions.RemoteCertificateValidationCallback!(
            null!,
            localhostCertificate,
            new X509Chain(),
            SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors);

        Assert.False(accepted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task MalformedTransferRequestsFailBeforeTransportSuccessIsClaimed()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-preflight-malformed-transfer");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        (string CertificatePath, string PrivateKeyPath) = CreateServerCertificateFiles(fixture, "localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        string request = $"https://localhost:{listenEndPoint.Port}/";

        (HarnessRunResult server, HarnessRunResult client) = await RunHarnessPairWithoutListeningAsync(
            "transfer",
            request,
            CertificatePath,
            PrivateKeyPath,
            qlogDirectory);

        Assert.Equal(1, server.ExitCode);
        Assert.Equal(1, client.ExitCode);
        Assert.Empty(server.Stdout);
        Assert.Empty(client.Stdout);
        Assert.Contains("must include a non-root path for transfer dispatch.", server.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("must include a non-root path for transfer dispatch.", client.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransferPathMappingRejectsRootRequests()
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "transfer",
                requests: "https://localhost:4242/"),
            out InteropHarnessEnvironment? clientSettings,
            out string? errorMessage));
        Assert.NotNull(clientSettings);
        Assert.Null(errorMessage);

        InteropHarnessPreflightPlanner planner = new(clientSettings!, TextWriter.Null);
        Assert.True(planner.TryGetDispatchRequestUri(out Uri? requestUri, out errorMessage));
        Assert.NotNull(requestUri);
        Assert.Null(errorMessage);

        Assert.False(InteropHarnessPreflightPlanner.TryGetTransferPaths(
            requestUri,
            out string? relativePath,
            out string? sourcePath,
            out string? destinationPath,
            out errorMessage));
        Assert.Null(relativePath);
        Assert.Null(sourcePath);
        Assert.Null(destinationPath);
        Assert.NotNull(errorMessage);
        Assert.Contains("non-root path", errorMessage, StringComparison.OrdinalIgnoreCase);
    }

    private static (string CertificatePath, string PrivateKeyPath) CreateServerCertificateFiles(
        TempDirectoryFixture fixture,
        string dnsName)
    {
        using X509Certificate2 certificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate(dnsName);
        string certificatePath = fixture.CreateFile("cert.pem", certificate.ExportCertificatePem());
        using ECDsa? privateKey = certificate.GetECDsaPrivateKey();
        string privateKeyPath = fixture.CreateFile("priv.key", privateKey!.ExportPkcs8PrivateKeyPem());
        return (certificatePath, privateKeyPath);
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
        await WaitForPairCompletionAsync(serverTask, clientTask, TimeSpan.FromSeconds(30)).ConfigureAwait(false);

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

        await WaitForPairCompletionAsync(serverTask, clientTask, TimeSpan.FromSeconds(30)).ConfigureAwait(false);

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

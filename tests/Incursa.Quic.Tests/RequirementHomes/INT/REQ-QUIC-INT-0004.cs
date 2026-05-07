using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using Incursa.Quic.InteropHarness;
using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0004")]
public sealed class REQ_QUIC_INT_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DiagnosticsSinkRemainsStructuredAndCheapWhenDisabled()
    {
        CollectingDiagnosticsSink sink = new();
        QuicDiagnosticEvent diagnostic = new(
            "connection.runtime.path",
            "classified",
            "Packet classified as probable NAT rebinding.",
            QuicDiagnosticSeverity.Warning);

        sink.Emit(diagnostic);
        QuicNullDiagnosticsSink.Instance.Emit(diagnostic);

        Assert.True(sink.IsEnabled);
        Assert.Single(sink.Events);
        Assert.Equal("connection.runtime.path", sink.Events[0].Category);
        Assert.Equal("classified", sink.Events[0].Name);
        Assert.False(QuicNullDiagnosticsSink.Instance.IsEnabled);

        QuicConnectionEmitDiagnosticEffect effect = new(diagnostic);
        Assert.Equal(QuicDiagnosticSeverity.Warning, effect.Diagnostic.Severity);
        Assert.Contains("probable NAT rebinding", effect.Diagnostic.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QlogWriterPersistsContainedJsonToTheRequestedDirectory()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");

        QlogFile file = new();
        QlogTrace trace = new()
        {
            VantagePoint = new QlogVantagePoint
            {
                Type = QlogKnownValues.ClientVantagePoint,
            },
        };
        trace.EventSchemas.Add(new Uri("urn:ietf:params:qlog:events:quic"));
        file.Traces.Add(trace);

        string outputPath = InteropHarnessQlogWriter.CreateOutputPath(qlogDirectory, "client-handshake");
        Assert.True(InteropHarnessQlogWriter.TryWrite(outputPath, file, out string? errorMessage), errorMessage);
        Assert.EndsWith(".qlog", outputPath, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(outputPath));

        QlogFile roundTripped = QlogJsonSerializer.Deserialize(File.ReadAllText(outputPath));
        Assert.Single(roundTripped.Traces);
        Assert.Equal(QlogKnownValues.ContainedFileSchemaUri, roundTripped.FileSchema);
        Assert.Equal(QlogKnownValues.ContainedJsonSerializationFormat, roundTripped.SerializationFormat);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LocalhostHandshakeSmokeLeavesSslKeyLogFileAsAnHonestTodo()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-qlog-keylog");
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        string sslKeyLogPath = Path.Combine(fixture.RootDirectory, "sslkeylog.log");
        string sourceRoot = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        string destinationRoot = Path.GetFullPath(InteropHarnessEnvironment.DownloadsDirectory);
        string relativePath = $"keylog-handshake-{Guid.NewGuid():N}.txt";
        string sourcePath = Path.Combine(sourceRoot, relativePath);
        string destinationPath = Path.Combine(destinationRoot, relativePath);
        byte[] payload = Encoding.UTF8.GetBytes($"keylog handshake payload {Guid.NewGuid():N}");

        Directory.CreateDirectory(sourceRoot);
        Directory.CreateDirectory(destinationRoot);
        File.WriteAllBytes(sourcePath, payload);
        TryDelete(destinationPath);

        try
        {
            HarnessRunResult? serverResult = null;
            HarnessRunResult? clientResult = null;

            await InteropHarnessTestSupport.WithHarnessCertificateAsync("localhost", async () =>
            {
                IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
                string request = $"https://localhost:{listenEndPoint.Port}/{relativePath}";
                (serverResult, clientResult) = await RunHarnessPairAsync(
                    "handshake",
                    request,
                    InteropHarnessEnvironment.CertificatePath,
                    InteropHarnessEnvironment.PrivateKeyPath,
                    qlogDirectory,
                    sslKeyLogPath);
            });

            Assert.NotNull(serverResult);
            Assert.NotNull(clientResult);
            Assert.Equal(0, serverResult!.ExitCode);
            Assert.Equal(0, clientResult!.ExitCode);
            Assert.Contains(
                "SSLKEYLOGFILE is set but keylog export is not yet implemented.",
                serverResult.Stdout,
                StringComparison.OrdinalIgnoreCase);
            Assert.Contains(
                "SSLKEYLOGFILE is set but keylog export is not yet implemented.",
                clientResult.Stdout,
                StringComparison.OrdinalIgnoreCase);
            Assert.Contains("qlog capture enabled", serverResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("qlog capture enabled", clientResult.Stdout, StringComparison.OrdinalIgnoreCase);
            Assert.False(File.Exists(sslKeyLogPath));
            Assert.True(File.Exists(destinationPath));
            Assert.Equal(payload, File.ReadAllBytes(destinationPath));

            string[] qlogFiles = Directory.GetFiles(qlogDirectory, "*.qlog");
            Assert.NotEmpty(qlogFiles);
            QlogFile qlog = QlogJsonSerializer.Deserialize(File.ReadAllText(qlogFiles[0]));
            Assert.NotEmpty(qlog.Traces);
        }
        finally
        {
            TryDelete(sourcePath);
            TryDelete(destinationPath);
        }
    }

    private static async Task<(HarnessRunResult Server, HarnessRunResult Client)> RunHarnessPairAsync(
        string testcase,
        string request,
        string certificatePath,
        string privateKeyPath,
        string? qlogDirectory,
        string? sslKeyLogFile = null)
    {
        RecordingTextWriter serverStdout = new();
        RecordingTextWriter serverStderr = new();
        RecordingTextWriter clientStdout = new();
        RecordingTextWriter clientStderr = new();

        Task<int> serverTask = StartHarnessRunAsync(
            "server",
            testcase,
            request,
            qlogDirectory,
            sslKeyLogFile,
            certificatePath,
            privateKeyPath,
            serverStdout,
            serverStderr);
        await WaitForTextAsync(serverTask, serverStdout, "listening on", TimeSpan.FromSeconds(10)).ConfigureAwait(false);

        Task<int> clientTask = StartHarnessRunAsync(
            "client",
            testcase,
            request,
            qlogDirectory,
            sslKeyLogFile,
            certificatePath,
            privateKeyPath,
            clientStdout,
            clientStderr);
        await WaitForPairCompletionAsync(serverTask, clientTask, TimeSpan.FromSeconds(30)).ConfigureAwait(false);

        return (
            new HarnessRunResult(await serverTask.ConfigureAwait(false), serverStdout.ToString(), serverStderr.ToString()),
            new HarnessRunResult(await clientTask.ConfigureAwait(false), clientStdout.ToString(), clientStderr.ToString()));
    }

    private static Task<int> StartHarnessRunAsync(
        string role,
        string testcase,
        string request,
        string? qlogDirectory,
        string? sslKeyLogFile,
        string certificatePath,
        string privateKeyPath,
        RecordingTextWriter stdout,
        RecordingTextWriter stderr)
    {
        return Task.Factory.StartNew(
            () => InteropHarnessRunner.Run(
                InteropHarnessTestSupport.CreateEnvironment(role, testcase, request, qlogDirectory, sslKeyLogFile),
                stdout,
                stderr,
                certificatePath,
                privateKeyPath),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
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

    private sealed class CollectingDiagnosticsSink : IQuicDiagnosticsSink
    {
        public List<QuicDiagnosticEvent> Events { get; } = [];

        public bool IsEnabled => true;

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            Events.Add(diagnosticEvent);
        }
    }
}

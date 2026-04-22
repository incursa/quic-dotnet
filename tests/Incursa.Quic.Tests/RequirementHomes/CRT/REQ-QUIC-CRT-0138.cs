using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Incursa.Quic.Qlog;
using Incursa.Qlog;
using Incursa.Qlog.Quic;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0138")]
public sealed class REQ_QUIC_CRT_0138
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientCaptureProducesContainedJsonQlog()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) =>
                ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));

        QuicQlogCapture capture = new(title: "client qlog capture");

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = capture.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            Assert.Single(capture.File.Traces);
            QlogTrace captureTrace = Assert.IsType<QlogTrace>(capture.File.Traces[0]);
            Assert.Equal(QlogKnownValues.ClientVantagePoint, captureTrace.VantagePoint?.Type);
            Assert.NotEmpty(captureTrace.Events);
            Assert.Contains(captureTrace.Events, qlogEvent => qlogEvent.Name == QlogQuicKnownValues.PacketReceivedEventName);

            string json = capture.ToJson(indented: true);
            QlogFile roundTrip = QlogJsonSerializer.Deserialize(json);

            Assert.Single(roundTrip.Traces);
            QlogTrace serializedTrace = Assert.IsType<QlogTrace>(roundTrip.Traces[0]);
            Assert.Equal(QlogKnownValues.ClientVantagePoint, serializedTrace.VantagePoint?.Type);
            Assert.NotEmpty(serializedTrace.Events);
            Assert.Contains(serializedTrace.Events, qlogEvent => qlogEvent.Name == QlogQuicKnownValues.PacketReceivedEventName);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ListenerCaptureCreatesDistinctTracesForAcceptedConnections()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 2,
            ConnectionOptionsCallback = (_, _, _) =>
                ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        QuicClientConnectionOptions clientOptions1 = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));
        QuicClientConnectionOptions clientOptions2 = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));

        QuicQlogCapture capture = new(title: "listener qlog capture");

        await using QuicListener listener = await capture.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask1 = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> acceptTask2 = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask1 = QuicConnection.ConnectAsync(clientOptions1).AsTask();
        Task<QuicConnection> connectTask2 = QuicConnection.ConnectAsync(clientOptions2).AsTask();

        await Task.WhenAll(acceptTask1, acceptTask2, connectTask1, connectTask2).WaitAsync(TimeSpan.FromSeconds(10));

        QuicConnection serverConnection1 = await acceptTask1;
        QuicConnection serverConnection2 = await acceptTask2;
        QuicConnection clientConnection1 = await connectTask1;
        QuicConnection clientConnection2 = await connectTask2;

        try
        {
            Assert.Equal(2, capture.File.Traces.Count);

            QlogTrace[] captureTraces = capture.File.Traces.Cast<QlogTrace>().ToArray();
            Assert.All(captureTraces, trace =>
            {
                Assert.Equal(QlogKnownValues.ServerVantagePoint, trace.VantagePoint?.Type);
                Assert.NotEmpty(trace.Events);
            });

            string json = capture.ToJson();
            QlogFile roundTrip = QlogJsonSerializer.Deserialize(json);
            QlogTrace[] serializedTraces = roundTrip.Traces.Cast<QlogTrace>().ToArray();

            Assert.Equal(2, serializedTraces.Length);
            Assert.All(serializedTraces, trace =>
            {
                Assert.Equal(QlogKnownValues.ServerVantagePoint, trace.VantagePoint?.Type);
                Assert.NotEmpty(trace.Events);
            });
        }
        finally
        {
            await serverConnection2.DisposeAsync();
            await serverConnection1.DisposeAsync();
            await clientConnection2.DisposeAsync();
            await clientConnection1.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteJson_SerializesASnapshotWithoutBlockingLiveDiagnosticsEmission()
    {
        // Provenance: preserved multiconnect handshakeloss evidence under
        // artifacts/interop-runner/20260422-085849660-client-chrome showed later connections
        // stalling while qlog capture was enabled, making it necessary to prove snapshot
        // serialization does not hold the live diagnostics append path behind file I/O.
        QuicQlogCapture capture = new(title: "snapshot qlog capture");
        QuicQlogDiagnosticsSink sink = Assert.IsType<QuicQlogDiagnosticsSink>(capture.CreateClientDiagnosticsSinkFactory()());
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "193.167.100.100",
            LocalAddress: "193.167.0.100",
            RemotePort: 443,
            LocalPort: 47878);

        sink.Emit(QuicDiagnostics.InitialPacketSent(pathIdentity, new byte[1200]));

        using BlockingWriteStream stream = new();
        Task serializeTask = Task.Run(() => capture.WriteJson(stream, indented: true));
        Assert.True(stream.WaitForFirstWrite(TimeSpan.FromSeconds(5)), "Timed out waiting for qlog serialization to begin writing.");

        Task emitTask = Task.Run(() => sink.Emit(QuicDiagnostics.HandshakePacketSent(pathIdentity, [0x01, 0x02, 0x03])));

        try
        {
            await emitTask.WaitAsync(TimeSpan.FromSeconds(1));
        }
        finally
        {
            stream.ReleaseWrites();
            await serializeTask.WaitAsync(TimeSpan.FromSeconds(5));
        }

        Assert.Equal(2, sink.Trace.Events.Count);

        QlogFile serializedFile = QlogJsonSerializer.Deserialize(stream.GetWrittenText());
        QlogTrace serializedTrace = Assert.IsType<QlogTrace>(Assert.Single(serializedFile.Traces));
        Assert.Single(serializedTrace.Events);
        Assert.Equal(QlogQuicKnownValues.PacketSentEventName, serializedTrace.Events[0].Name);
    }

    private sealed class BlockingWriteStream : Stream
    {
        private readonly MemoryStream inner = new();
        private readonly ManualResetEventSlim firstWriteStarted = new(false);
        private readonly ManualResetEventSlim allowWrites = new(false);
        private int firstWriteObserved;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => inner.Length;

        public override long Position
        {
            get => inner.Position;
            set => throw new NotSupportedException();
        }

        public bool WaitForFirstWrite(TimeSpan timeout)
        {
            return firstWriteStarted.Wait(timeout);
        }

        public void ReleaseWrites()
        {
            allowWrites.Set();
        }

        public string GetWrittenText()
        {
            return Encoding.UTF8.GetString(inner.ToArray());
        }

        public override void Flush()
        {
            inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            inner.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            WaitForRelease();
            inner.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            WaitForRelease();
            inner.Write(buffer);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
                firstWriteStarted.Dispose();
                allowWrites.Dispose();
            }

            base.Dispose(disposing);
        }

        private void WaitForRelease()
        {
            if (Interlocked.Exchange(ref firstWriteObserved, 1) == 0)
            {
                firstWriteStarted.Set();
            }

            allowWrites.Wait();
        }
    }
}

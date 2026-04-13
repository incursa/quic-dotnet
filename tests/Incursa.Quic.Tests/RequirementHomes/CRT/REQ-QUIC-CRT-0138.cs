using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
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
}

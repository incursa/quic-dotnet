using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0014">On the supported active loopback path, QuicConnection.OpenOutboundStreamAsync(...) MUST remain pending when the peer's current stream limit for the requested direction is exhausted, and it MUST complete that pending open only after a later real MAX_STREAMS increase makes a stream of that direction available. Cancellation and terminal-state behavior remain governed by REQ-QUIC-API-0008, and the slice MUST not fabricate success, synthetic wake-up, STREAMS_BLOCKED emission, or broader stream-management parity.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0014")]
public sealed class REQ_QUIC_API_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStreamAsync_RemainsPendingAndResumesAfterLaterMaxStreamsGrowth()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 0;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        QuicStream? bidirectionalStream = null;
        QuicStream? unidirectionalStream = null;

        try
        {
            Task<QuicStream> bidirectionalOpenTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();
            Task<QuicStream> unidirectionalOpenTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional).AsTask();

            await Task.Delay(200);
            Assert.False(bidirectionalOpenTask.IsCompleted);
            Assert.False(unidirectionalOpenTask.IsCompleted);

            IPEndPoint clientLocalEndPoint = GetConnectionLocalEndPoint(clientConnection);
            SendLaterMaxStreamsFrame(listener, serverConnection, clientLocalEndPoint, 1, 1);

            Task completionTask = Task.WhenAll(bidirectionalOpenTask, unidirectionalOpenTask);
            Task completedTask = await Task.WhenAny(completionTask, Task.Delay(TimeSpan.FromSeconds(5)));
            if (completedTask != completionTask)
            {
                throw new TimeoutException(
                    $"Blocked outbound opens did not resume. Server runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(serverConnection)}; Client runtime: {QuicLoopbackEstablishmentTestSupport.DescribeConnection(clientConnection)}");
            }

            await completionTask;

            bidirectionalStream = await bidirectionalOpenTask;
            unidirectionalStream = await unidirectionalOpenTask;

            Assert.Equal(QuicStreamType.Bidirectional, bidirectionalStream.Type);
            Assert.Equal(QuicStreamType.Unidirectional, unidirectionalStream.Type);
            Assert.Equal(0, bidirectionalStream.Id);
            Assert.Equal(2, unidirectionalStream.Id);
        }
        finally
        {
            if (bidirectionalStream is not null)
            {
                await bidirectionalStream.DisposeAsync();
            }

            if (unidirectionalStream is not null)
            {
                await unidirectionalStream.DisposeAsync();
            }

            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenOutboundStreamAsync_HonorsCancellationWhileBlockedByPeerLimit()
    {
        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicServerConnectionOptions expectedServerOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate);
        expectedServerOptions.MaxInboundBidirectionalStreams = 0;
        expectedServerOptions.MaxInboundUnidirectionalStreams = 0;

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(expectedServerOptions),
        };

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port));

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions).AsTask();

        await Task.WhenAll(acceptTask, connectTask);

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            using CancellationTokenSource cancellationSource = new();
            Task<QuicStream> openTask = clientConnection.OpenOutboundStreamAsync(
                QuicStreamType.Bidirectional,
                cancellationSource.Token).AsTask();

            await Task.Delay(200);
            Assert.False(openTask.IsCompleted);

            cancellationSource.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => openTask);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(runtimeField);
        return Assert.IsType<QuicConnectionRuntime>(runtimeField!.GetValue(connection));
    }

    private static IPEndPoint GetConnectionLocalEndPoint(QuicConnection connection)
    {
        QuicConnectionRuntime runtime = GetRuntime(connection);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionPathIdentity identity = runtime.ActivePath!.Value.Identity;
        Assert.False(string.IsNullOrWhiteSpace(identity.LocalAddress));
        Assert.True(identity.LocalPort.HasValue);

        return new IPEndPoint(IPAddress.Parse(identity.LocalAddress!), identity.LocalPort.Value);
    }

    private static void SendLaterMaxStreamsFrame(
        QuicListener listener,
        QuicConnection senderConnection,
        IPEndPoint receiverLocalEndPoint,
        ulong bidirectionalMaximumStreams,
        ulong unidirectionalMaximumStreams)
    {
        QuicConnectionRuntime senderRuntime = GetRuntime(senderConnection);
        Socket listenerSocket = GetListenerSocket(listener);
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = GetHandshakeFlowCoordinator(senderRuntime);
        QuicTlsPacketProtectionMaterial? protectMaterial = senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial;
        Assert.NotNull(protectMaterial);

        Span<byte> applicationPayload = stackalloc byte[32];
        Assert.True(
            QuicFrameCodec.TryFormatMaxStreamsFrame(
                new QuicMaxStreamsFrame(true, bidirectionalMaximumStreams),
                applicationPayload,
                out int bidirectionalBytesWritten));
        Assert.True(
            QuicFrameCodec.TryFormatMaxStreamsFrame(
                new QuicMaxStreamsFrame(false, unidirectionalMaximumStreams),
                applicationPayload[bidirectionalBytesWritten..],
                out int unidirectionalBytesWritten));

        int payloadBytes = bidirectionalBytesWritten + unidirectionalBytesWritten;
        Assert.True(
            handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload[..payloadBytes],
                protectMaterial.Value,
                out byte[] protectedPacket));

        int bytesSent = listenerSocket.SendTo(protectedPacket, SocketFlags.None, receiverLocalEndPoint);
        Assert.Equal(protectedPacket.Length, bytesSent);
    }

    private static QuicHandshakeFlowCoordinator GetHandshakeFlowCoordinator(QuicConnectionRuntime runtime)
    {
        FieldInfo? handshakeFlowField = typeof(QuicConnectionRuntime).GetField(
            "handshakeFlowCoordinator",
            BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(handshakeFlowField);
        return Assert.IsType<QuicHandshakeFlowCoordinator>(handshakeFlowField!.GetValue(runtime));
    }

    private static Socket GetListenerSocket(QuicListener listener)
    {
        FieldInfo? hostField = typeof(QuicListener).GetField("host", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(hostField);
        QuicListenerHost host = Assert.IsType<QuicListenerHost>(hostField!.GetValue(listener));
        FieldInfo? socketField = typeof(QuicListenerHost).GetField("socket", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(socketField);
        return Assert.IsType<Socket>(socketField!.GetValue(host));
    }
}

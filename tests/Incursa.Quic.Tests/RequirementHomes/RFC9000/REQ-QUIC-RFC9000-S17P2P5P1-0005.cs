using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0005">A server MAY send Retry packets in response to Initial and 0-RTT packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0005">A server MAY send Retry packets in response to Initial and 0-RTT packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0005")]
    public async Task ListenerHostCanIssueRetryPacketsInResponseToInitialDatagrams()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                throw new InvalidOperationException("The retry-issuance slice must not admit the connection callback.");
            },
            listenBacklog: 1,
            retryBootstrapEnabled: true);

        using Socket clientSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        clientSocket.Connect(listenEndPoint);

        _ = listenerHost.RunAsync();
        await Task.Yield();

        byte[] initialDestinationConnectionId = QuicS17P2P2TestSupport.InitialDestinationConnectionId;
        byte[] initialSourceConnectionId = QuicS17P2P2TestSupport.InitialSourceConnectionId;
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(0x60, 16)));

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] initialPacket));

        int bytesSent = clientSocket.Send(initialPacket);
        Assert.Equal(initialPacket.Length, bytesSent);

        byte[] responseBuffer = new byte[256];
        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        int bytesReceived = await clientSocket.ReceiveAsync(responseBuffer.AsMemory(), SocketFlags.None, receiveTimeout.Token);

        Assert.True(listenerHost.RetryBootstrapIssued);
        Assert.False(callbackEntered.Task.IsCompleted);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            initialDestinationConnectionId,
            responseBuffer.AsSpan(0, bytesReceived),
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.NotEmpty(retryMetadata.RetrySourceConnectionId);
        Assert.NotEmpty(retryMetadata.RetryToken);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), listenerHost.RetryBootstrapTokenHex);
    }
}

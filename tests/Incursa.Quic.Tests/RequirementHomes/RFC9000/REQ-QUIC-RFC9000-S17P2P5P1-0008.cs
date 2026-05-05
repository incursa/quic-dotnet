using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0008">A server MUST NOT send more than one Retry packet in response to a single UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0008">A server MUST NOT send more than one Retry packet in response to a single UDP datagram.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0008")]
    public async Task ListenerHostIssuesOnlyOneRetryPacketForAnInitialDatagram()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                return ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate));
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
        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(0x60, 16)));

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] initialPacket));

        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        byte[] retryResponse = new byte[256];
        int bytesSent = clientSocket.Send(initialPacket);
        Assert.Equal(initialPacket.Length, bytesSent);

        int retryBytes = await clientSocket.ReceiveAsync(retryResponse.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            initialDestinationConnectionId,
            retryResponse.AsSpan(0, retryBytes),
            out QuicRetryBootstrapMetadata retryMetadata));

        using CancellationTokenSource secondRetryTimeout = new(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(new byte[256].AsMemory(), SocketFlags.None, secondRetryTimeout.Token));

        Assert.False(callbackEntered.Task.IsCompleted);
        await WaitForRetryBootstrapTokenAsync(listenerHost, retryMetadata.RetryToken);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), listenerHost.RetryBootstrapTokenHex);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0008">A server MUST NOT send more than one Retry packet in response to a single UDP datagram.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0008")]
    public async Task ListenerHostIssuesOnlyOneRetryPacketForAZeroRttDatagram()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                return ValueTask.FromResult(QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate));
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
        QuicHandshakeFlowCoordinator coordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out byte[] zeroRttPacket));

        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        byte[] retryResponse = new byte[256];
        int bytesSent = clientSocket.Send(zeroRttPacket);
        Assert.Equal(zeroRttPacket.Length, bytesSent);

        int retryBytes = await clientSocket.ReceiveAsync(retryResponse.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            initialDestinationConnectionId,
            retryResponse.AsSpan(0, retryBytes),
            out QuicRetryBootstrapMetadata retryMetadata));

        using CancellationTokenSource secondRetryTimeout = new(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await clientSocket.ReceiveAsync(new byte[256].AsMemory(), SocketFlags.None, secondRetryTimeout.Token));

        Assert.False(callbackEntered.Task.IsCompleted);
        await WaitForRetryBootstrapTokenAsync(listenerHost, retryMetadata.RetryToken);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), listenerHost.RetryBootstrapTokenHex);
    }

    private static async Task WaitForRetryBootstrapTokenAsync(
        QuicListenerHost listenerHost,
        ReadOnlyMemory<byte> retryToken)
    {
        string expectedTokenHex = Convert.ToHexString(retryToken.Span);
        DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            if (listenerHost.RetryBootstrapTokenHex == expectedTokenHex)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10));
        }

        Assert.Equal(expectedTokenHex, listenerHost.RetryBootstrapTokenHex);
    }
}

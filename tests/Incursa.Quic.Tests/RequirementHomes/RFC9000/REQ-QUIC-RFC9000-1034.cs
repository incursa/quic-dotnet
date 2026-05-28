// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1034">A server MAY send multiple Retry packets as it receives Initial or 0-RTT packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1034")]
public sealed class REQ_QUIC_RFC9000_1034
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1034">A server MAY send multiple Retry packets as it receives Initial or 0-RTT packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1034")]
    public async Task ListenerHostCanIssueRetryPacketsForSeparateInitialAndZeroRttDatagrams()
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

        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out byte[] zeroRttPacket));

        using CancellationTokenSource receiveTimeout = new(TimeSpan.FromSeconds(5));
        byte[] retryResponse1 = new byte[256];
        int bytesSent = clientSocket.Send(initialPacket);
        Assert.Equal(initialPacket.Length, bytesSent);

        int retryBytes1 = await clientSocket.ReceiveAsync(retryResponse1.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            initialDestinationConnectionId,
            retryResponse1.AsSpan(0, retryBytes1),
            out QuicRetryBootstrapMetadata retryMetadata));
        await WaitForRetryBootstrapTokenAsync(listenerHost, retryMetadata.RetryToken);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), listenerHost.RetryBootstrapTokenHex);
        Assert.False(callbackEntered.Task.IsCompleted);

        byte[] retryResponse2 = new byte[256];
        bytesSent = clientSocket.Send(zeroRttPacket);
        Assert.Equal(zeroRttPacket.Length, bytesSent);

        int retryBytes2 = await clientSocket.ReceiveAsync(retryResponse2.AsMemory(), SocketFlags.None, receiveTimeout.Token);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            initialDestinationConnectionId,
            retryResponse2.AsSpan(0, retryBytes2),
            out QuicRetryBootstrapMetadata retryMetadata2));
        Assert.Equal(retryMetadata.RetrySourceConnectionId, retryMetadata2.RetrySourceConnectionId);
        Assert.Equal(retryMetadata.RetryToken, retryMetadata2.RetryToken);
        Assert.Equal(retryBytes1, retryBytes2);
        Assert.Equal(retryResponse1.AsSpan(0, retryBytes1).ToArray(), retryResponse2.AsSpan(0, retryBytes2).ToArray());
        Assert.False(callbackEntered.Task.IsCompleted);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            retryMetadata.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryClientProtection));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            retryClientProtection,
            out byte[] replayPacket));

        bytesSent = clientSocket.Send(replayPacket);
        Assert.Equal(replayPacket.Length, bytesSent);

        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(listenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), listenerHost.RetryBootstrapReplayTokenHex);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1034">A server MAY send multiple Retry packets as it receives Initial or 0-RTT packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1034")]
    public async Task ListenerHostRejectsARetryReplayCandidateWithTheWrongToken()
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
        Assert.False(callbackEntered.Task.IsCompleted);

        byte[] wrongRetryToken = retryMetadata.RetryToken.ToArray();
        wrongRetryToken[^1] ^= 0x01;
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            retryMetadata.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryClientProtection));
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            wrongRetryToken,
            retryClientProtection,
            out byte[] wrongReplayPacket));

        bytesSent = clientSocket.Send(wrongReplayPacket);
        Assert.Equal(wrongReplayPacket.Length, bytesSent);

        await Task.Delay(TimeSpan.FromMilliseconds(250));
        Assert.False(callbackEntered.Task.IsCompleted);
        Assert.Equal(6, listenerHost.RetryBootstrapReplayValidationFailureCode);
        Assert.Equal(Convert.ToHexString(wrongRetryToken), listenerHost.RetryBootstrapReplayTokenHex);
        Assert.False(listenerHost.RetryBootstrapReplayValidated);
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

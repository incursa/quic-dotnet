// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-5-3-P4-S6-R01">A server MAY abort the connection if it detects that the client reset the packet number.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-5-3-P4-S6-R01")]
public sealed class REQ_QUIC_RFC9000_1055
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-3-P4-S6-R01">A server MAY abort the connection if it detects that the client reset the packet number.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-3-P4-S6-R01")]
    public async Task ListenerHostMayAbortARetryReplayCandidateThatResetsInitialPacketNumbers()
    {
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        TaskCompletionSource<bool> callbackEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) =>
            {
                callbackEntered.TrySetResult(true);
                throw new InvalidOperationException("The packet-number-reset slice must not admit the connection callback.");
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

        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(0x60, 16)));

        QuicHandshakeFlowCoordinator initialCoordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
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

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            retryMetadata.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryClientProtection));

        QuicHandshakeFlowCoordinator resetCoordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
        Assert.True(resetCoordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            retryClientProtection,
            out byte[] resetReplayPacket));

        bytesSent = clientSocket.Send(resetReplayPacket);
        Assert.Equal(resetReplayPacket.Length, bytesSent);

        await Task.Delay(TimeSpan.FromMilliseconds(250));
        Assert.False(callbackEntered.Task.IsCompleted);
        Assert.Equal(11, listenerHost.RetryBootstrapReplayValidationFailureCode);
        Assert.False(listenerHost.RetryBootstrapReplayValidated);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-3-P4-S6-R01">A server MAY abort the connection if it detects that the client reset the packet number.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-3-P4-S6-R01")]
    public async Task ListenerHostAllowsARetryReplayCandidateThatContinuesTheInitialPacketNumber()
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

        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(0x60, 16)));

        QuicHandshakeFlowCoordinator coordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
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
        Assert.Equal(0, listenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-5-3-P4-S6-R01">A server MAY abort the connection if it detects that the client reset the packet number.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-5-3-P4-S6-R01")]
    public async Task Fuzz_ListenerHostRejectsRetryReplayCandidatesThatResetInitialPacketNumbers()
    {
        foreach ((bool resetPacketNumber, byte cryptoSeed, int cryptoLength, bool expectReplayAdmitted) in new[]
        {
            (true, (byte)0x61, 16, false),
            (false, (byte)0x71, 19, true),
            (true, (byte)0x81, 23, false),
        })
        {
            await AssertRetryReplayPacketNumberOutcomeAsync(
                resetPacketNumber,
                cryptoSeed,
                cryptoLength,
                expectReplayAdmitted);
        }
    }

    private static async Task AssertRetryReplayPacketNumberOutcomeAsync(
        bool resetPacketNumber,
        byte cryptoSeed,
        int cryptoLength,
        bool expectReplayAdmitted)
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
                if (!expectReplayAdmitted)
                {
                    throw new InvalidOperationException("The packet-number-reset slice must not admit the connection callback.");
                }

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

        byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
            new QuicCryptoFrame(0, QuicS12P3TestSupport.CreateSequentialBytes(cryptoSeed, cryptoLength)));

        QuicHandshakeFlowCoordinator initialCoordinator = new(initialDestinationConnectionId, initialSourceConnectionId);
        Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
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

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            retryMetadata.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryClientProtection));

        QuicHandshakeFlowCoordinator replayCoordinator = resetPacketNumber
            ? new QuicHandshakeFlowCoordinator(initialDestinationConnectionId, initialSourceConnectionId)
            : initialCoordinator;
        Assert.True(replayCoordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            retryMetadata.RetrySourceConnectionId,
            retryMetadata.RetryToken,
            retryClientProtection,
            out byte[] replayPacket));

        bytesSent = clientSocket.Send(replayPacket);
        Assert.Equal(replayPacket.Length, bytesSent);

        if (expectReplayAdmitted)
        {
            await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(listenerHost.RetryBootstrapReplayValidated);
            Assert.Equal(0, listenerHost.RetryBootstrapReplayValidationFailureCode);
            return;
        }

        await Task.Delay(TimeSpan.FromMilliseconds(250));
        Assert.False(callbackEntered.Task.IsCompleted);
        Assert.Equal(11, listenerHost.RetryBootstrapReplayValidationFailureCode);
        Assert.False(listenerHost.RetryBootstrapReplayValidated);
    }
}

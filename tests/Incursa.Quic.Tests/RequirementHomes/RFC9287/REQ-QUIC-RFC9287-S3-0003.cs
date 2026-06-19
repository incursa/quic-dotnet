// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9287-S3-0003")]
public sealed class REQ_QUIC_RFC9287_S3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NegotiatedGreaseQuicBitAcceptsClearedFixedBitPacketsAfterTransportParameters()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x01, 0x02, 0x03];

        bool buildSucceeded = senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit,
            out ulong packetNumber,
            out byte[] protectedPacket);
        Assert.True(
            buildSucceeded,
            $"dest={senderCoordinator.DestinationConnectionId.Length}, source={senderCoordinator.SourceConnectionId.Length}, openMaterial={senderRuntime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue}, protectMaterial={senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue}, peerGrease={senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit}");

        Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.Equal(senderRuntime.TlsState.CurrentOneRttKeyPhaseBit, keyPhase);
        Assert.Equal(0, openedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.True(applicationPayload.SequenceEqual(openedPacket.AsSpan(payloadOffset, applicationPayload.Length)));
        Assert.True(openedPacket.AsSpan(
            payloadOffset + applicationPayload.Length,
            payloadLength - applicationPayload.Length).SequenceEqual(new byte[payloadLength - applicationPayload.Length]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeDispatchAcceptsClearedFixedBitShortHeaderPacketsAfterNegotiation()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        runtime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        runtime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        byte[] streamPayload = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 3, [0xA1, 0xA2]);
        Assert.True(runtime.HandshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            streamPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out _,
            out byte[] protectedPacket));
        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: runtime.Clock.Ticks + 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: runtime.Clock.Ticks + 1);

        Assert.True(result.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasContiguousReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0002")]
    [Trait("Category", "Positive")]
    public void EndpointRoutesClearedFixedBitLongHeaderPacketsToRegisteredConnection()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        byte[] datagram = QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        datagram[0] = (byte)(datagram[0] & ~QuicPacketHeaderBits.FixedBitMask);

        Assert.False(QuicPacketParser.TryParseLongHeader(datagram, out _));
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram, allowClearedFixedBit: true, out _));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            datagram,
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RuntimeDispatchAcceptsClearedFixedBitWhenLocalEndpointAdvertisedGreaseQuicBit()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        runtime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        runtime.TlsState.PeerTransportParameters!.GreaseQuicBit = false;

        byte[] streamPayload = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 3, [0xB1, 0xB2]);
        Assert.True(runtime.HandshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            streamPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out _,
            out byte[] protectedPacket));
        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: runtime.Clock.Ticks + 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: runtime.Clock.Ticks + 1);

        Assert.True(result.StateChanged);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(3, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasContiguousReadableBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RuntimeAcceptQueueSurfacesClearedFixedBitPeerRequestStream()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(
            initializeActivePath: true);

        runtime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        runtime.TlsState.PeerTransportParameters!.GreaseQuicBit = false;

        byte[] streamPayload = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 0, [0xC1, 0xC2]);
        Assert.True(runtime.HandshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            streamPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out _,
            out byte[] protectedPacket));
        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: runtime.Clock.Ticks + 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: runtime.Clock.Ticks + 1);

        Assert.True(result.StateChanged);
        QuicStream stream = await runtime.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal(0, stream.Id);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RuntimeAcceptQueueSurfacesPeerStreamsImplicitlyOpenedByHigherStreamId()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(
            initializeActivePath: true);

        runtime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        runtime.TlsState.PeerTransportParameters!.GreaseQuicBit = false;

        byte[] streamPayload =
        [
            ..QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 10, [0x03]),
            ..QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 6, [0x02]),
            ..QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 0, [0xC1, 0xC2]),
        ];
        Assert.True(runtime.HandshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            streamPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out _,
            out byte[] protectedPacket));
        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.NotNull(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: runtime.Clock.Ticks + 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: runtime.Clock.Ticks + 1);

        Assert.True(result.StateChanged);
        QuicStream first = await runtime.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        QuicStream second = await runtime.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
        QuicStream third = await runtime.AcceptInboundStreamAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal([10, 6, 0], [first.Id, second.Id, third.Id]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StrictOpenRejectsFixedBitZeroPacketsWithoutNegotiation()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x04, 0x05, 0x06];

        Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.False(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: false,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NegotiatedGreaseQuicBitAcceptsClearedFixedBitPacketsAtTheShortestPayload()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x01];

        Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.Equal(senderRuntime.TlsState.CurrentOneRttKeyPhaseBit, keyPhase);
        Assert.True(applicationPayload.SequenceEqual(openedPacket.AsSpan(payloadOffset, applicationPayload.Length)));
        Assert.True(openedPacket.AsSpan(
            payloadOffset + applicationPayload.Length,
            payloadLength - applicationPayload.Length).SequenceEqual(new byte[payloadLength - applicationPayload.Length]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NegotiatedGreaseQuicBit_AcceptsClearedFixedBitPacketsAcrossRepresentativePayloads()
    {
        QuicGreaseQuicBitFuzzSupport.FuzzGreasedPacketAcceptancePolicy();
    }
}

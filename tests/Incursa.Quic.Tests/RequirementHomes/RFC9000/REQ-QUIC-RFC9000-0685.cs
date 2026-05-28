// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0685">Senders MUST NOT coalesce QUIC packets with different connection IDs into a single UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0685")]
public sealed class REQ_QUIC_RFC9000_0685
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0685")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram_RewritesBothPacketsToTheCurrentPeerDestinationConnectionIdAfterRotation()
    {
        (ReadOnlyMemory<byte> datagram, byte[] originalDestinationConnectionId, byte[] rotatedDestinationConnectionId) =
            BuildRotatedCoalescedProbeDatagram();

        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.True(handshakeHeader.DestinationConnectionId.SequenceEqual(rotatedDestinationConnectionId));
        Assert.False(handshakeHeader.DestinationConnectionId.SequenceEqual(originalDestinationConnectionId));

        // The trailing packet is the coalesced 1-RTT short-header packet.
        Assert.True(applicationPacket.Span.Length > 1 + rotatedDestinationConnectionId.Length);
        Assert.True(applicationPacket.Span.Slice(1, rotatedDestinationConnectionId.Length).SequenceEqual(rotatedDestinationConnectionId));
        Assert.False(applicationPacket.Span.Slice(1, rotatedDestinationConnectionId.Length).SequenceEqual(originalDestinationConnectionId));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0685")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram_DoesNotRetainTheStaleDestinationConnectionIdInEitherPacket()
    {
        (ReadOnlyMemory<byte> datagram, byte[] originalDestinationConnectionId, _) =
            BuildRotatedCoalescedProbeDatagram();

        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.False(handshakeHeader.DestinationConnectionId.SequenceEqual(originalDestinationConnectionId));

        // The trailing packet is the coalesced 1-RTT short-header packet.
        Assert.True(applicationPacket.Span.Length > 1 + originalDestinationConnectionId.Length);
        Assert.False(applicationPacket.Span.Slice(1, originalDestinationConnectionId.Length).SequenceEqual(originalDestinationConnectionId));
    }

    private static (ReadOnlyMemory<byte> Datagram, byte[] OriginalDestinationConnectionId, byte[] RotatedDestinationConnectionId)
        BuildRotatedCoalescedProbeDatagram()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] rotatedDestinationConnectionId =
        [
            0x82, 0x5F, 0xC9, 0x1F, 0xA1, 0xB2, 0xC3, 0xD4,
        ];

        QuicConnectionTransitionResult newConnectionIdResult = ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 1,
            connectionId: rotatedDestinationConnectionId,
            statelessResetToken: [0x93, 0xCA, 0x79, 0x2B, 0xDC, 0xF0, 0xA9, 0x2A, 0x83, 0xF3, 0x64, 0x93, 0xE1, 0x0D, 0xBD, 0x47],
            observedAtTicks: 10);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(rotatedDestinationConnectionId));

        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));
        byte[] handshakeCrypto = QuicS12P3TestSupport.CreateSequentialBytes(0x70, 36);
        QuicHandshakeFlowCoordinator handshakeCoordinator = new(
            originalDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId.ToArray());
        Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
            handshakeCrypto,
            cryptoPayloadOffset: 0,
            handshakeMaterial,
            out ulong handshakePacketNumber,
            out byte[] handshakePacketBytes));

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.Handshake,
            handshakePacketNumber,
            PayloadBytes: (ulong)handshakePacketBytes.Length,
            SentAtMicros: 11,
            ProbePacket: false,
            PacketBytes: handshakePacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Handshake));

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /sharp-fast-singer\r\n");
        byte[] requestFrame = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: 0,
            requestPayload,
            offset: 0);
        QuicHandshakeFlowCoordinator applicationCoordinator = new(rotatedDestinationConnectionId);
        Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
            requestFrame,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            keyPhase: false,
            out ulong applicationPacketNumber,
            out byte[] applicationPacketBytes));

        runtime.SendRuntime.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            applicationPacketNumber,
            PayloadBytes: (ulong)applicationPacketBytes.Length,
            SentAtMicros: 12,
            ProbePacket: false,
            PacketBytes: applicationPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: [0UL],
            PlaintextPayload: requestFrame));

        List<QuicConnectionEffect>? effects = [];
        Assert.True(InvokeTrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
            runtime,
            nowTicks: 13,
            ref effects));

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            effects!.OfType<QuicConnectionSendDatagramEffect>());
        return (sendEffect.Datagram, originalDestinationConnectionId, rotatedDestinationConnectionId);
    }

    private static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> statelessResetToken,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            statelessResetToken));

        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static bool InvokeTrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
        QuicConnectionRuntime runtime,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return runtime.TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(nowTicks, ref effects);
    }

    private static (ReadOnlyMemory<byte> HandshakePacket, ReadOnlyMemory<byte> ApplicationPacket)
        SplitCoalescedHandshakeAndApplicationProbeDatagram(ReadOnlyMemory<byte> datagram)
    {
        Assert.True(QuicPacketParser.TryGetPacketLength(datagram.Span, out int handshakePacketLength));
        ReadOnlyMemory<byte> handshakePacket = datagram[..handshakePacketLength];
        ReadOnlyMemory<byte> applicationPacket = datagram[handshakePacketLength..];
        Assert.False(applicationPacket.IsEmpty);
        return (handshakePacket, applicationPacket);
    }
}

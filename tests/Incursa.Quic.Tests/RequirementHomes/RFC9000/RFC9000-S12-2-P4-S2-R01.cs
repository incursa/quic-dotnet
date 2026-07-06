// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S12-2-P4-S2-R01">Receivers SHOULD ignore any subsequent packets with a different Destination Connection ID than the first packet in the datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S12-2-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0686
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CoalescedHandshakeAndApplicationProbeUsesTheCurrentPeerDestinationConnectionIdForBothPacketsAfterPeerRotation()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-083251153-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 16/50 opened the request stream and sent "GET /sharp-fast-singer\r\n",
        //     then timed out waiting for response bytes or EOF.
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go later parsed a coalesced client packet where the first 79-byte Handshake part
        //     still targeted 4a335afb while the remaining 81-byte 1-RTT part targeted 825fc91f,
        //     so it ignored the request-bearing second packet.
        // When a client coalesces a Handshake repair with a 1-RTT repair after NEW_CONNECTION_ID
        // advances the peer-facing destination CID, both packets in that datagram need to target
        // the same current peer connection ID so the peer does not discard the later packet.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] rotatedDestinationConnectionId = [0x82, 0x5F, 0xC9, 0x1F];

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
        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(sendEffect.Datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.True(handshakeHeader.DestinationConnectionId.SequenceEqual(rotatedDestinationConnectionId));

        Assert.True(applicationPacket.Span.Length > 1 + rotatedDestinationConnectionId.Length);
        Assert.True(applicationPacket.Span.Slice(1, rotatedDestinationConnectionId.Length).SequenceEqual(rotatedDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CoalescedHandshakeAndApplicationProbeKeepsTheSharedDestinationConnectionIdWhenThePeerDoesNotRotateIt()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] currentDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();

        Assert.True(runtime.TlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial));
        byte[] handshakeCrypto = QuicS12P3TestSupport.CreateSequentialBytes(0x30, 16);
        QuicHandshakeFlowCoordinator handshakeCoordinator = new(
            currentDestinationConnectionId,
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

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /steady-shared-cid\r\n");
        byte[] requestFrame = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: 0,
            requestPayload,
            offset: 0);
        QuicHandshakeFlowCoordinator applicationCoordinator = new(currentDestinationConnectionId);
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
        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(sendEffect.Datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.True(handshakeHeader.DestinationConnectionId.SequenceEqual(currentDestinationConnectionId));

        Assert.True(applicationPacket.Span.Length > 1 + currentDestinationConnectionId.Length);
        Assert.True(applicationPacket.Span.Slice(1, currentDestinationConnectionId.Length).SequenceEqual(currentDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CoalescedHandshakeAndApplicationProbeUsesAMaximumLengthCurrentPeerDestinationConnectionIdAfterPeerRotation()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] rotatedDestinationConnectionId = new byte[QuicConnectionIdKey.MaximumLength];

        for (int index = 0; index < rotatedDestinationConnectionId.Length; index++)
        {
            rotatedDestinationConnectionId[index] = (byte)(0x80 + index);
        }

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

        byte[] requestPayload = Encoding.ASCII.GetBytes("GET /maximum-length-dcid\r\n");
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
        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(sendEffect.Datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.True(handshakeHeader.DestinationConnectionId.SequenceEqual(rotatedDestinationConnectionId));

        Assert.True(applicationPacket.Span.Length > 1 + rotatedDestinationConnectionId.Length);
        Assert.True(applicationPacket.Span.Slice(1, rotatedDestinationConnectionId.Length).SequenceEqual(rotatedDestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CoalescedHandshakeAndApplicationProbeUsesTheCurrentPeerDestinationConnectionIdAfterPeerRotation()
    {
        foreach ((byte[] rotatedDestinationConnectionId, string requestPath) in new[]
        {
            (new byte[] { 0x82 }, "/cid-1"),
            (new byte[] { 0x82, 0x5F, 0xC9, 0x1F }, "/cid-4"),
            (new byte[] { 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 }, "/cid-8"),
            (Enumerable.Range(0, QuicConnectionIdKey.MaximumLength).Select(index => (byte)(0xA0 + index)).ToArray(), "/cid-20"),
        })
        {
            AssertCoalescedProbeUsesCurrentPeerDestinationConnectionIdAfterPeerRotation(
                rotatedDestinationConnectionId,
                requestPath);
        }
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

    private static void AssertCoalescedProbeUsesCurrentPeerDestinationConnectionIdAfterPeerRotation(
        byte[] rotatedDestinationConnectionId,
        string requestPath)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();

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

        byte[] requestPayload = Encoding.ASCII.GetBytes($"GET {requestPath}\r\n");
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
        (ReadOnlyMemory<byte> handshakePacket, ReadOnlyMemory<byte> applicationPacket) =
            SplitCoalescedHandshakeAndApplicationProbeDatagram(sendEffect.Datagram);

        Assert.True(QuicPacketParser.TryParseLongHeader(handshakePacket.Span, out QuicLongHeaderPacket handshakeHeader));
        Assert.True(handshakeHeader.DestinationConnectionId.SequenceEqual(rotatedDestinationConnectionId));

        Assert.True(applicationPacket.Span.Length > 1 + rotatedDestinationConnectionId.Length);
        Assert.True(applicationPacket.Span.Slice(1, rotatedDestinationConnectionId.Length).SequenceEqual(rotatedDestinationConnectionId));
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

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P6-0004">This can mean that the client is unable to use these acknowledgments if the server cryptographic handshake messages are delayed or lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P6-0004")]
public sealed class REQ_QUIC_RFC9000_S13P2P6_0004
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientCannotUseOneRttAckPacketsWithoutOneRttMaterial()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial oneRttMaterial));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong zeroRttPacketNumber,
            out _));

        QuicSenderFlowController sender = new();
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            zeroRttPacketNumber,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame ackFrame));

        byte[] ackPayload = QuicFrameTestData.BuildAckFrame(ackFrame);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            ackPayload,
            oneRttMaterial,
            out byte[] oneRttAckPacket));

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            oneRttAckPacket,
            zeroRttMaterial,
            out _,
            out _,
            out _));

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            oneRttAckPacket,
            oneRttMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(payloadLength >= ackPayload.Length);

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out _));
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            openedPacket,
            out QuicPacketNumberSpace ackPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, ackPacketNumberSpace);

        Assert.True(QuicFrameCodec.TryParseAckFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicAckFrame parsedAckFrame,
            out int bytesConsumed));
        Assert.Equal(ackPayload.Length, bytesConsumed);
        Assert.Equal(zeroRttPacketNumber, parsedAckFrame.LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P6-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientCanUseOneRttAckPacketsWhenOneRttMaterialIsAvailable()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial oneRttMaterial));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            zeroRttMaterial,
            out ulong zeroRttPacketNumber,
            out byte[] zeroRttPacket));

        Assert.True(QuicPacketParser.TryParseLongHeader(zeroRttPacket, out QuicLongHeaderPacket zeroRttHeader));
        Assert.Equal(QuicLongPacketTypeBits.ZeroRtt, zeroRttHeader.LongPacketTypeBits);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            zeroRttPacket,
            out QuicPacketNumberSpace zeroRttPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, zeroRttPacketNumberSpace);

        QuicSenderFlowController sender = new();
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            zeroRttPacketNumber,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_500,
            out QuicAckFrame ackFrame));
        Assert.Equal(zeroRttPacketNumber, ackFrame.LargestAcknowledged);
        Assert.Equal(500UL, ackFrame.AckDelay);

        byte[] ackPayload = QuicFrameTestData.BuildAckFrame(ackFrame);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            ackPayload,
            oneRttMaterial,
            out ulong ackPacketNumber,
            out byte[] oneRttAckPacket));
        Assert.Equal(1UL, ackPacketNumber);

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            oneRttAckPacket,
            oneRttMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(payloadLength >= ackPayload.Length);

        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out _));
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            openedPacket,
            out QuicPacketNumberSpace ackPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, ackPacketNumberSpace);

        Assert.True(QuicFrameCodec.TryParseAckFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicAckFrame parsedAckFrame,
            out int bytesConsumed));
        Assert.Equal(ackPayload.Length, bytesConsumed);
        Assert.Equal(zeroRttPacketNumber, parsedAckFrame.LargestAcknowledged);
        Assert.Equal(ackFrame.AckDelay, parsedAckFrame.AckDelay);
        Assert.Equal(ackFrame.FirstAckRange, parsedAckFrame.FirstAckRange);
    }

    private static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(InitialDestinationConnectionId, SourceConnectionId);
    }
}

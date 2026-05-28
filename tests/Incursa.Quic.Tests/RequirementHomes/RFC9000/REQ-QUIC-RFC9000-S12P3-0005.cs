// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0005">Handshake packets MUST be sent at the Handshake encryption level and be acknowledged only in Handshake packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0005")]
public sealed class REQ_QUIC_RFC9000_S12P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakePacketsStayBoundToHandshakeAcknowledgments()
    {
        byte[] destinationConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];
        byte[] sourceConnectionId =
        [
            0x31, 0x32, 0x33, 0x34,
        ];

        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId, sourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
            cryptoPayloadOffset: 0,
            material,
            out ulong packetNumber,
            out byte[] protectedPacket));
        Assert.Equal(0UL, packetNumber);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            protectedPacket,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = packetNumber,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        };

        QuicSenderFlowController wrongSpaceSender = new();
        wrongSpaceSender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber,
            sentBytes: (ulong)protectedPacket.Length,
            sentAtMicros: 1_000,
            ackEliciting: true);
        Assert.False(wrongSpaceSender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.True(wrongSpaceSender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber,
            sentAtMicros: 1_000));

        QuicSenderFlowController rightSpaceSender = new();
        rightSpaceSender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber,
            sentBytes: (ulong)protectedPacket.Length,
            sentAtMicros: 1_000,
            ackEliciting: true);
        Assert.True(rightSpaceSender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.False(rightSpaceSender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber,
            sentAtMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialAcksDoNotAcknowledgeHandshakePackets()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 0,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        };

        Assert.False(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 0,
            sentAtMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void HandshakeAndInitialSpacesCanUsePacketNumberZeroIndependently()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 0,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 0,
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            ackEliciting: true);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        };

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 3_000,
            pathValidated: true));
        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 0,
            sentAtMicros: 1_000));

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            ackFrame,
            ackReceivedAtMicros: 4_000,
            pathValidated: true));
        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber: 0,
            sentAtMicros: 2_000));
    }
}

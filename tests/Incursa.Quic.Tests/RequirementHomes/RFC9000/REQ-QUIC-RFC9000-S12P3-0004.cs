namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P3-0004">Initial packets MUST only be sent with Initial packet protection keys and acknowledged in packets that are also Initial packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P3-0004")]
public sealed class REQ_QUIC_RFC9000_S12P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPacketsStayBoundToInitialAcknowledgments()
    {
        byte[] initialDcid =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId =
        [
            0x01, 0x02, 0x03, 0x04,
        ];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDcid,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(initialDcid, sourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x10, 20),
            cryptoPayloadOffset: 0,
            protection,
            out ulong packetNumber,
            out byte[] protectedPacket));
        Assert.Equal(0UL, packetNumber);
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            protectedPacket,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);

        QuicAckFrame ackFrame = new()
        {
            LargestAcknowledged = packetNumber,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        };

        QuicSenderFlowController wrongSpaceSender = new();
        wrongSpaceSender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber,
            sentBytes: (ulong)protectedPacket.Length,
            sentAtMicros: 1_000,
            ackEliciting: true);
        Assert.False(wrongSpaceSender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.True(wrongSpaceSender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber,
            sentAtMicros: 1_000));

        QuicSenderFlowController rightSpaceSender = new();
        rightSpaceSender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber,
            sentBytes: (ulong)protectedPacket.Length,
            sentAtMicros: 1_000,
            ackEliciting: true);
        Assert.True(rightSpaceSender.TryProcessAckFrame(
            QuicPacketNumberSpace.Initial,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.False(rightSpaceSender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber,
            sentAtMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakeAcksDoNotAcknowledgeInitialPackets()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
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
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber: 0,
            sentAtMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void InitialAndHandshakeSpacesCanUsePacketNumberZeroIndependently()
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 0,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);
        sender.RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
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
            QuicPacketNumberSpace.Initial,
            ackFrame,
            ackReceivedAtMicros: 3_000,
            pathValidated: true));
        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            packetNumber: 0,
            sentAtMicros: 1_000));

        Assert.True(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 4_000,
            pathValidated: true));
        Assert.False(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 0,
            sentAtMicros: 2_000));
    }
}

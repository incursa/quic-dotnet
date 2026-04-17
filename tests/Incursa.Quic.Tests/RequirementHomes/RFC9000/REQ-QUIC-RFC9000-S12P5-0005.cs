namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P5-0005")]
public sealed class REQ_QUIC_RFC9000_S12P5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessAckFrame_AcknowledgesPacketsOnlyWithinTheMatchingPacketNumberSpace()
    {
        QuicAckFrame ackFrame = CreateAckFrame(7);

        AssertAckedInSpace(QuicPacketNumberSpace.Initial, ackFrame, packetNumber: 7);
        AssertAckedInSpace(QuicPacketNumberSpace.Handshake, ackFrame, packetNumber: 7);
        AssertAckedInSpace(QuicPacketNumberSpace.ApplicationData, ackFrame, packetNumber: 7);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessAckFrame_DoesNotAcknowledgePacketsFromADifferentPacketNumberSpace()
    {
        QuicAckFrame ackFrame = CreateAckFrame(1);
        QuicSenderFlowController sender = new();

        sender.RecordPacketSent(
            QuicPacketNumberSpace.Initial,
            packetNumber: 1,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        Assert.False(sender.TryProcessAckFrame(
            QuicPacketNumberSpace.Handshake,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.True(sender.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            1,
            sentAtMicros: 1_000));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessAckFrame_AcknowledgesPacketNumberZeroIndependentlyInEachPacketNumberSpace()
    {
        AssertAckedInSpace(QuicPacketNumberSpace.Initial, CreateAckFrame(0), packetNumber: 0);
        AssertAckedInSpace(QuicPacketNumberSpace.Handshake, CreateAckFrame(0), packetNumber: 0);
        AssertAckedInSpace(QuicPacketNumberSpace.ApplicationData, CreateAckFrame(0), packetNumber: 0);
    }

    private static QuicAckFrame CreateAckFrame(ulong largestAcknowledged)
    {
        return new QuicAckFrame
        {
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        };
    }

    private static void AssertAckedInSpace(
        QuicPacketNumberSpace packetNumberSpace,
        QuicAckFrame ackFrame,
        ulong packetNumber)
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(
            packetNumberSpace,
            ackFrame,
            ackReceivedAtMicros: 2_000,
            pathValidated: true));
        Assert.False(sender.TryRegisterLoss(
            packetNumberSpace,
            packetNumber,
            sentAtMicros: 1_000));
    }
}

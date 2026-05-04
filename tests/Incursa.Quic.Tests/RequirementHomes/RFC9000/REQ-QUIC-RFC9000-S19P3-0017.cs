namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
public sealed class REQ_QUIC_RFC9000_S19P3_0017
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildAckFrame_EncodesAckDelayInMicroseconds()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_250,
            out QuicAckFrame frame));

        Assert.Equal(250UL, frame.AckDelay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsTruncatedMicrosecondAckDelay()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x02],
                QuicS19P3AckFrameTestSupport.Varint(4),
                [0x40]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0017")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildAckFrame_UsesZeroAckDelayWhenBuiltAtReceiveTime()
    {
        QuicAckGenerationState state = new();
        state.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 4,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(state.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_000,
            out QuicAckFrame frame));

        Assert.Equal(0UL, frame.AckDelay);
    }
}

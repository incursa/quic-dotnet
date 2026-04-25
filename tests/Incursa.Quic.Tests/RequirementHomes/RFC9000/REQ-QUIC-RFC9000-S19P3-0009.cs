namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
public sealed class REQ_QUIC_RFC9000_S19P3_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_AcceptsAckFrameTypes02And03()
    {
        Assert.True(QuicFrameCodec.TryParseAckFrame(
            [0x02, 0x04, 0x01, 0x00, 0x00],
            out QuicAckFrame ackFrame,
            out int ackBytesConsumed));
        Assert.Equal(0x02, ackFrame.FrameType);
        Assert.Equal(5, ackBytesConsumed);

        Assert.True(QuicFrameCodec.TryParseAckFrame(
            [0x03, 0x04, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03],
            out QuicAckFrame ackEcnFrame,
            out int ackEcnBytesConsumed));
        Assert.Equal(0x03, ackEcnFrame.FrameType);
        Assert.Equal(8, ackEcnBytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsUnsupportedAckFrameType()
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(
            [0x04, 0x04, 0x01, 0x00, 0x00],
            out _,
            out _));
    }
}

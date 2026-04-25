namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0001")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_Type03IndicatesEcnFeedback()
    {
        QuicAckFrame frame = QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
            ect0Count: 1,
            ect1Count: 2,
            ecnCeCount: 3);

        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(frame);

        Assert.Equal(0x03, encoded[0]);
        QuicAckFrame parsed = QuicAckEcnFrameCodecTestSupport.ParseAckFrame(encoded);
        Assert.NotNull(parsed.EcnCounts);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatAckFrame_RejectsMismatchedEcnFeedbackTypeAndCounts()
    {
        QuicAckFrame ackWithoutEcnCounts = new()
        {
            FrameType = 0x03,
            LargestAcknowledged = 4,
            AckDelay = 1,
            FirstAckRange = 0,
        };

        QuicAckFrame ackWithUnexpectedEcnCounts = new()
        {
            FrameType = 0x02,
            LargestAcknowledged = 4,
            AckDelay = 1,
            FirstAckRange = 0,
            EcnCounts = new QuicEcnCounts(1, 2, 3),
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.False(QuicFrameCodec.TryFormatAckFrame(ackWithoutEcnCounts, destination, out _));
        Assert.False(QuicFrameCodec.TryFormatAckFrame(ackWithUnexpectedEcnCounts, destination, out _));
    }
}

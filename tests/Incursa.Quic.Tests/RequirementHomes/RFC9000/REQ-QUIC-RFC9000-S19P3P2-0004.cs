namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEcnCeCountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 1,
                ect1Count: 2,
                ecnCeCount: 0x4000));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 2);

        Assert.Equal(0x4000UL, value);
        Assert.Equal(4, bytesConsumed);
    }
}

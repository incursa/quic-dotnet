namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEct0CountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 0x40,
                ect1Count: 1,
                ecnCeCount: 2));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 0);

        Assert.Equal(0x40UL, value);
        Assert.Equal(2, bytesConsumed);
    }
}

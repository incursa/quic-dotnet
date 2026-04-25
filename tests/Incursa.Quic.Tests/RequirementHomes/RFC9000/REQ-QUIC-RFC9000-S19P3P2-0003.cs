namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEct1CountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 1,
                ect1Count: 0x40,
                ecnCeCount: 2));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 1);

        Assert.Equal(0x40UL, value);
        Assert.Equal(2, bytesConsumed);
    }
}

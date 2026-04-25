namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
public sealed class REQ_QUIC_RFC9000_S19P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_Type03CarriesEcnCounts()
    {
        QuicAckEcnFrameCodecTestSupport.AssertEcnCountsRoundTrip(
            ect0Count: 7,
            ect1Count: 11,
            ecnCeCount: 13);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_Type03RejectsMissingEcnCountFields()
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(
            [0x03, 0x04, 0x01, 0x00, 0x00],
            out _,
            out _));

        Assert.False(QuicFrameCodec.TryParseAckFrame(
            [0x03, 0x04, 0x01, 0x00, 0x00, 0x01],
            out _,
            out _));

        Assert.False(QuicFrameCodec.TryParseAckFrame(
            [0x03, 0x04, 0x01, 0x00, 0x00, 0x01, 0x02],
            out _,
            out _));
    }
}

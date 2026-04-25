namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0005")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_PreservesEct0CountValue()
    {
        QuicAckEcnFrameCodecTestSupport.AssertEcnCountsRoundTrip(
            ect0Count: 123,
            ect1Count: 2,
            ecnCeCount: 3);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0006")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_PreservesEct1CountValue()
    {
        QuicAckEcnFrameCodecTestSupport.AssertEcnCountsRoundTrip(
            ect0Count: 1,
            ect1Count: 123,
            ecnCeCount: 3);
    }
}

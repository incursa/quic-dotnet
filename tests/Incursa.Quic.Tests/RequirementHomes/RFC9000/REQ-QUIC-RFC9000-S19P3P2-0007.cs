namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0007")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAckFrame_PreservesEcnCeCountValue()
    {
        QuicAckEcnFrameCodecTestSupport.AssertEcnCountsRoundTrip(
            ect0Count: 1,
            ect1Count: 2,
            ecnCeCount: 123);
    }
}

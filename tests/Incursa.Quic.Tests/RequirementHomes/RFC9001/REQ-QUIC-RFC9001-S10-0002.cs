namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S10-0002")]
public sealed class REQ_QUIC_RFC9001_S10_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicTransportParametersCodec_MarksTheRegistryRecommendedColumnYes()
    {
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersRecommended);
    }
}

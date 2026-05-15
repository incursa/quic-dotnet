namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P7-0004")]
public sealed class REQ_QUIC_RFC9000_S9P7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ChangingTheConnectionSeedChangesTheIpv6FlowLabel()
    {
        uint firstFlowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.PrimaryPath);
        uint secondFlowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedB,
            QuicS9P7FlowLabelTestSupport.PrimaryPath);

        Assert.NotEqual(firstFlowLabel, secondFlowLabel);
        Assert.NotEqual(0U, firstFlowLabel);
        Assert.NotEqual(0U, secondFlowLabel);
    }
}

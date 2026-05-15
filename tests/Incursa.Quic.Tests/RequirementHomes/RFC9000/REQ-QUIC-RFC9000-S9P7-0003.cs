using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P7-0003")]
public sealed class REQ_QUIC_RFC9000_S9P7_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AlternateIpv6SendMetadataAlsoResolvesAFlowLabel()
    {
        Assert.True(QuicS9P7FlowLabelTestSupport.TryResolveSourceAddress(
            QuicS9P7FlowLabelTestSupport.AlternateLocalPath,
            out IPAddress sourceAddress));
        Assert.Equal(IPAddress.Parse("2001:db8::11"), sourceAddress);

        uint flowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.AlternateLocalPath);

        Assert.NotEqual(0U, flowLabel);
        Assert.Equal(flowLabel, QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.AlternateLocalPath));
    }
}

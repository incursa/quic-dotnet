namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7-0001")]
public sealed class REQ_QUIC_RFC9002_S7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SenderFlowControllerUsesTheBuiltInRfc9002ControllerWhenNoAlternateControllerSurfaceExists()
    {
        QuicSenderFlowController sender = new();

        Assert.NotNull(sender.CongestionControlState);
        Assert.DoesNotContain(
            typeof(QuicConnection).Assembly.GetExportedTypes(),
            type => type.Name.Contains("CongestionController", StringComparison.OrdinalIgnoreCase)
                || type.Name.Contains("CongestionControlProvider", StringComparison.OrdinalIgnoreCase));
    }
}

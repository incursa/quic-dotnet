namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1422")]
public sealed class REQ_QUIC_RFC9000_1422
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_ValidatesQuotedPacketBeforeReducingTheActivePath()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);

        Assert.True(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            1_300));
        Assert.Equal(1_300UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(1_300UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14P2P1-0001")]
public sealed class REQ_QUIC_RFC9000_S14P2P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyProvisionalIcmpMaximumDatagramSizeReduction_IgnoresClaimsBelowTheMinimum()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));

        byte[] quotedPacket = QuicS14P2P1TestSupport.BuildQuotedInitialPacket(runtime);
        ulong minimumAllowedMaximumDatagramSizeBytes = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        Assert.False(runtime.TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            runtime.ActivePath!.Value.Identity,
            quotedPacket,
            minimumAllowedMaximumDatagramSizeBytes - 1));
        Assert.Equal(1_400UL, runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.False(runtime.ActivePath.Value.MaximumDatagramSizeState.IsProvisional);
        Assert.Equal(1_400UL, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
    }
}

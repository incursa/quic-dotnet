namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P2-0004")]
public sealed class REQ_QUIC_RFC9002_S7P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void UpdateMaxDatagramSize_ResetsTheWindowAfterReducingTheDatagramSize()
    {
        QuicCongestionControlState state = new(1_500);
        state.RegisterPacketSent(1_500);

        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);

        state.UpdateMaxDatagramSize(1_200, resetToInitialWindow: true);

        Assert.Equal(1_200UL, state.MaxDatagramSizeBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Null(state.RecoveryStartTimeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void UpdateMaxDatagramSize_DoesNotResetTheWindowWhenResetToInitialWindowIsFalse()
    {
        QuicCongestionControlState state = new(1_500);
        state.RegisterPacketSent(1_500);

        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);

        state.UpdateMaxDatagramSize(1_200, resetToInitialWindow: false);

        Assert.Equal(1_200UL, state.MaxDatagramSizeBytes);
        Assert.Equal(14_720UL, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Null(state.RecoveryStartTimeMicros);
    }

    [Theory]
    [InlineData(1_472UL, 14_720UL)]
    [InlineData(1_471UL, 14_710UL)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void UpdateMaxDatagramSize_ResetsToTheTransitionPointInitialWindow(
        ulong maxDatagramSizeBytes,
        ulong expectedInitialWindowBytes)
    {
        QuicCongestionControlState state = new(1_500);
        state.RegisterPacketSent(1_500);

        state.UpdateMaxDatagramSize(maxDatagramSizeBytes, resetToInitialWindow: true);

        Assert.Equal(maxDatagramSizeBytes, state.MaxDatagramSizeBytes);
        Assert.Equal(expectedInitialWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.Null(state.RecoveryStartTimeMicros);
    }
}

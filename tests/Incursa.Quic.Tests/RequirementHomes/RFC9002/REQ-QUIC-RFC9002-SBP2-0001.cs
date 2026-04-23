namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP2-0001")]
public sealed class REQ_QUIC_RFC9002_SBP2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstructorUsesThePathMtuForRecoveryMaxDatagramSize()
    {
        QuicCongestionControlState state = new(maxDatagramSizeBytes: 1_350);

        Assert.Equal(1_350UL, state.MaxDatagramSizeBytes);
        Assert.Equal(1_350UL, state.RecoveryMaxDatagramSizeBytes);
        Assert.Equal(QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_350), state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructorDoesNotUseARecoveryMaxDatagramSizeBelowTheQuicMinimum()
    {
        ulong belowMinimum = QuicCongestionControlState.MinimumMaxDatagramSizeBytes - 1;

        QuicCongestionControlState state = new(maxDatagramSizeBytes: belowMinimum);

        Assert.Equal(belowMinimum, state.MaxDatagramSizeBytes);
        Assert.Equal(QuicCongestionControlState.MinimumMaxDatagramSizeBytes, state.RecoveryMaxDatagramSizeBytes);
        Assert.Equal(
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(QuicCongestionControlState.MinimumMaxDatagramSizeBytes),
            state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void UpdateMaxDatagramSizeClampsTheRecoveryFormulaWithoutChangingThePathValue()
    {
        QuicCongestionControlState state = new(maxDatagramSizeBytes: 1_350);
        ulong belowMinimum = QuicCongestionControlState.MinimumMaxDatagramSizeBytes - 1;

        state.UpdateMaxDatagramSize(belowMinimum, resetToInitialWindow: true);

        Assert.Equal(belowMinimum, state.MaxDatagramSizeBytes);
        Assert.Equal(QuicCongestionControlState.MinimumMaxDatagramSizeBytes, state.RecoveryMaxDatagramSizeBytes);
        Assert.Equal(
            QuicCongestionControlState.ComputeInitialCongestionWindowBytes(QuicCongestionControlState.MinimumMaxDatagramSizeBytes),
            state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NormalizeMaxDatagramSizeForRecoveryRejectsZero()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => QuicCongestionControlState.NormalizeMaxDatagramSizeForRecovery(0));
    }
}

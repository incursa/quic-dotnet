namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP8-0001">GetLossTimeAndSpace MUST return the earliest nonzero loss_time across the packet number spaces together with the corresponding packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP8-0001")]
public sealed class REQ_QUIC_RFC9002_SAP8_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrySelectLossTimeAndSpaceMicros_ChoosesTheEarliestNonZeroLossTime()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: 2_500,
            handshakeLossTimeMicros: 1_800,
            applicationDataLossTimeMicros: 3_000,
            out ulong selectedLossTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(1_800UL, selectedLossTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrySelectLossTimeAndSpaceMicros_ReturnsFalseWhenNoLossTimesArePending()
    {
        Assert.False(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: null,
            handshakeLossTimeMicros: null,
            applicationDataLossTimeMicros: null,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TrySelectLossTimeAndSpaceMicros_IgnoresZeroLossTimesAtTheBoundary()
    {
        Assert.True(QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
            initialLossTimeMicros: 0,
            handshakeLossTimeMicros: 1,
            applicationDataLossTimeMicros: 1,
            out ulong selectedLossTimeMicros,
            out QuicPacketNumberSpace selectedPacketNumberSpace));

        Assert.Equal(1UL, selectedLossTimeMicros);
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
    }
}

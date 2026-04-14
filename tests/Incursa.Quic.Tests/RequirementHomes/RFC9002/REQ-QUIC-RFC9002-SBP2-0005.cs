namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP2-0005">The sender MUST track the highest ECN-CE counter value reported by the peer for each packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP2-0005")]
public sealed class REQ_QUIC_RFC9002_SBP2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessEcn_TracksIncreasingCeCountsForEachPacketNumberSpace()
    {
        QuicCongestionControlState state = new();

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.Initial,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_000,
            pathValidated: false));

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.Handshake,
            reportedEcnCeCount: 2,
            largestAcknowledgedPacketSentAtMicros: 2_000,
            pathValidated: false));

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 3,
            largestAcknowledgedPacketSentAtMicros: 3_000,
            pathValidated: false));

        Assert.Equal([1UL, 2UL, 3UL], GetEcnCeCounters(state));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryProcessEcn_DoesNotAdvanceTheSamePacketNumberSpaceForARepeatedCeCount()
    {
        QuicCongestionControlState state = new();

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 1_000,
            pathValidated: false));

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 2_000,
            pathValidated: false));

        Assert.Equal([0UL, 0UL, 1UL], GetEcnCeCounters(state));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryProcessEcn_TracksTheMaximumReportedCeCountInTheHighestPacketNumberSpace()
    {
        QuicCongestionControlState state = new();

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.ApplicationData,
            reportedEcnCeCount: ulong.MaxValue,
            largestAcknowledgedPacketSentAtMicros: 1_000,
            pathValidated: false));

        Assert.False(state.TryProcessEcn(
            QuicPacketNumberSpace.Initial,
            reportedEcnCeCount: 1,
            largestAcknowledgedPacketSentAtMicros: 2_000,
            pathValidated: false));

        Assert.Equal([1UL, 0UL, ulong.MaxValue], GetEcnCeCounters(state));
    }

    private static ulong[] GetEcnCeCounters(QuicCongestionControlState state)
    {
        System.Reflection.FieldInfo field = typeof(QuicCongestionControlState).GetField(
            "ecnCeCounters",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Missing ecnCeCounters field.");

        return Assert.IsType<ulong[]>(field.GetValue(state));
    }
}

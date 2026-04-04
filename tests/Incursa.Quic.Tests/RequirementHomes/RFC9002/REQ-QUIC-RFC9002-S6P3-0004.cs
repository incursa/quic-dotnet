namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P3-0004">The client MAY compute an RTT estimate to the server as the time period from when the first Initial packet was sent to when a Retry or Version Negotiation packet is received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P3-0004")]
public sealed class REQ_QUIC_RFC9002_S6P3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryMeasureRetryRoundTripMicros_RejectsRetryPacketsThatPrecedeTheFirstInitialPacket()
    {
        Assert.False(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
            firstInitialPacketSentAtMicros: 2_000,
            retryReceivedAtMicros: 1_999,
            out ulong roundTripMicros));

        Assert.Equal(0UL, roundTripMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryMeasureRetryRoundTripMicros_AllowsAZeroLengthRoundTripAtTheBoundary()
    {
        Assert.True(QuicRecoveryTiming.TryMeasureRetryRoundTripMicros(
            firstInitialPacketSentAtMicros: 2_000,
            retryReceivedAtMicros: 2_000,
            out ulong roundTripMicros));

        Assert.Equal(0UL, roundTripMicros);
    }
}

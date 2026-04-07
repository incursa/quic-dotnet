namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0003">A connection MAY use the delay between sending a PATH_CHALLENGE and receiving a PATH_RESPONSE to set the initial RTT for a new path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P2-0003")]
public sealed class REQ_QUIC_RFC9002_S6P2P2_0003
{
    public static TheoryData<PathChallengeRoundTripEdgeCase> PathChallengeRoundTripEdgeCases => new()
    {
        new(0, 0, 0),
        new(ulong.MaxValue - 1, ulong.MaxValue, 1),
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryMeasurePathChallengeRoundTripMicros_RejectsResponsesThatArriveBeforeTheirChallenge()
    {
        Assert.False(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
            pathChallengeSentAtMicros: 2_000,
            pathResponseReceivedAtMicros: 1_999,
            out ulong roundTripMicros));

        Assert.Equal(0UL, roundTripMicros);
    }

    [Theory]
    [MemberData(nameof(PathChallengeRoundTripEdgeCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryMeasurePathChallengeRoundTripMicros_HandlesBoundaryIntervals(PathChallengeRoundTripEdgeCase scenario)
    {
        Assert.True(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
            scenario.PathChallengeSentAtMicros,
            scenario.PathResponseReceivedAtMicros,
            out ulong roundTripMicros));

        Assert.Equal(scenario.ExpectedRoundTripMicros, roundTripMicros);
    }

    public sealed record PathChallengeRoundTripEdgeCase(
        ulong PathChallengeSentAtMicros,
        ulong PathResponseReceivedAtMicros,
        ulong ExpectedRoundTripMicros);

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryMeasurePathChallengeRoundTripMicros_ComputesTheElapsedTimeWithoutUpdatingRttState()
    {
        Assert.True(QuicPathValidation.TryMeasurePathChallengeRoundTripMicros(
            pathChallengeSentAtMicros: 1_000,
            pathResponseReceivedAtMicros: 2_750,
            out ulong roundTripMicros));

        Assert.Equal(1_750UL, roundTripMicros);

        QuicRttEstimator estimator = new(initialRttMicros: roundTripMicros);
        Assert.False(estimator.HasRttSample);
        Assert.Equal(roundTripMicros, estimator.SmoothedRttMicros);
        Assert.Equal(roundTripMicros / 2, estimator.RttVarMicros);
    }
}

namespace Incursa.Quic.Tests;

public sealed class QuicPathValidationTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0004">The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer&apos;s response with the corresponding PATH_CHALLENGE.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0008">To initiate path validation, an endpoint MUST send a PATH_CHALLENGE frame containing an unpredictable payload on the path to be validated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0027">PATH_CHALLENGE frames MUST include a different payload each time they are sent.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGeneratePathChallengeData_WritesDistinctPayloadsThatRoundTripThroughTheFrameCodec()
    {
        Span<byte> challengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Span<byte> nextChallengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];

        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int bytesWritten));
        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(nextChallengeData, out int nextBytesWritten));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, bytesWritten);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, nextBytesWritten);
        Assert.False(challengeData[..bytesWritten].SequenceEqual(nextChallengeData[..nextBytesWritten]));

        QuicPathChallengeFrame frame = new(challengeData[..bytesWritten]);
        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(frame, encoded, out int encodedBytesWritten));
        Assert.Equal(9, encodedBytesWritten);

        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded[..encodedBytesWritten], out QuicPathChallengeFrame parsed, out int bytesConsumed));
        Assert.Equal(encodedBytesWritten, bytesConsumed);
        Assert.True(challengeData[..bytesWritten].SequenceEqual(parsed.Data));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0004">The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer&apos;s response with the corresponding PATH_CHALLENGE.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGeneratePathChallengeData_RejectsShortDestinations()
    {
        Assert.False(QuicPathValidation.TryGeneratePathChallengeData(stackalloc byte[7], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0001">On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing the data contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPathResponseFrame_EchoesChallengeData()
    {
        Span<byte> challengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int challengeBytesWritten));

        QuicPathResponseFrame frame = new(challengeData[..challengeBytesWritten]);
        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(frame, encoded, out int encodedBytesWritten));
        Assert.Equal(9, encodedBytesWritten);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(encoded[..encodedBytesWritten], out QuicPathResponseFrame parsed, out int bytesConsumed));
        Assert.Equal(encodedBytesWritten, bytesConsumed);
        Assert.True(challengeData[..challengeBytesWritten].SequenceEqual(parsed.Data));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0003">A connection MAY use the delay between sending a PATH_CHALLENGE and receiving a PATH_RESPONSE to set the initial RTT for a new path.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P2-0004">That delay SHOULD NOT be considered an RTT sample.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0004")]
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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0005">An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit sending a datagram of this size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0005">An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0006">However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPathValidationDatagramPadding_WritesRepeatedPaddingFramesWhenAmplificationBudgetAllows()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));

        Span<byte> destination = stackalloc byte[13];
        Assert.True(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            1187,
            budget,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P1-0005">An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit sending a datagram of this size.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0005">An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed maximum datagram size of 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P2P2-0006">However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data exceeds the anti-amplification limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P3P1-0001">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P1-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatPathValidationDatagramPadding_RejectsWhenAmplificationBudgetWouldBeExceeded()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(QuicPathValidation.TryFormatPathValidationDatagramPadding(
            1199,
            budget,
            stackalloc byte[1],
            out _));
    }
}

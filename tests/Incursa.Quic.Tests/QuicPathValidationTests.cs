namespace Incursa.Quic.Tests;

public sealed class QuicPathValidationTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0004")]
    [Trait("Category", "Negative")]
    public void TryGeneratePathChallengeData_RejectsShortDestinations()
    {
        Assert.False(QuicPathValidation.TryGeneratePathChallengeData(stackalloc byte[7], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0001")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2-0004")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0006")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S8P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S8P2P2-0006")]
    [Trait("Category", "Negative")]
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

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
public sealed class REQ_QUIC_RFC9000_S13P3_0027
{
    [Fact]
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
    [Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGeneratePathChallengeData_RejectsShortDestinations()
    {
        Assert.False(QuicPathValidation.TryGeneratePathChallengeData(stackalloc byte[7], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryGeneratePathChallengeData_ProducesDistinctPayloadsAcrossRepeatedCalls()
    {
        Span<byte> current = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Span<byte> previous = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Span<byte> encoded = stackalloc byte[16];
        bool hasPrevious = false;

        for (int iteration = 0; iteration < 128; iteration++)
        {
            Assert.True(QuicPathValidation.TryGeneratePathChallengeData(current, out int bytesWritten));
            Assert.Equal(QuicPathValidation.PathChallengeDataLength, bytesWritten);

            if (hasPrevious)
            {
                Assert.False(previous[..bytesWritten].SequenceEqual(current[..bytesWritten]));
            }

            QuicPathChallengeFrame frame = new(current[..bytesWritten]);
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(frame, encoded, out int encodedBytesWritten));
            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded[..encodedBytesWritten], out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.Equal(encodedBytesWritten, bytesConsumed);
            Assert.True(current[..bytesWritten].SequenceEqual(parsed.Data));

            current[..bytesWritten].CopyTo(previous);
            hasPrevious = true;
        }
    }
}

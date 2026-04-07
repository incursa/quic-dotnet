namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P3-0027")]
public sealed class REQ_QUIC_RFC9000_S13P3_0027
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0027">PATH_CHALLENGE frames MUST include a different payload each time they are sent.</workbench-requirement>
    /// </workbench-requirements>
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
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S12P4-0009")]
public sealed class REQ_QUIC_RFC9000_S12P4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void FixedTypeFramesUseTheFrameTypeOnlyToIdentifyTheFrameKind()
    {
        byte[] padding = QuicFrameTestData.BuildPaddingFrame();
        Assert.Equal(0x00, padding[0]);
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(padding, out int paddingBytesConsumed));
        Assert.Equal(1, paddingBytesConsumed);

        byte[] ping = QuicFrameTestData.BuildPingFrame();
        Assert.Equal(0x01, ping[0]);
        Assert.True(QuicFrameCodec.TryParsePingFrame(ping, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);

        byte[] pathChallengeData = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] pathChallenge = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(pathChallengeData));
        Assert.Equal(0x1A, pathChallenge[0]);
        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(pathChallenge, out QuicPathChallengeFrame parsedPathChallenge, out int pathChallengeBytesConsumed));
        Assert.Equal(pathChallenge.Length, pathChallengeBytesConsumed);
        Assert.True(pathChallengeData.AsSpan().SequenceEqual(parsedPathChallenge.Data));
    }
}

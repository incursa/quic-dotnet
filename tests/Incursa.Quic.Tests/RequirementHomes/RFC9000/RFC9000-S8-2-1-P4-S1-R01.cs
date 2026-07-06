// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-1-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P1_0004
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S8-2-1-P4-S1-R01">The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer&apos;s response with the corresponding PATH_CHALLENGE.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-2-1-P4-S1-R01")]
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
    ///   <workbench-requirement requirementId="RFC9000-S8-2-1-P4-S1-R01">The endpoint MUST use unpredictable data in every PATH_CHALLENGE frame so that it can associate the peer&apos;s response with the corresponding PATH_CHALLENGE.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-2-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGeneratePathChallengeData_RejectsShortDestinations()
    {
        Assert.False(QuicPathValidation.TryGeneratePathChallengeData(stackalloc byte[7], out _));
    }

    [Fact]
    [Requirement("RFC9000-S8-2-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryGeneratePathChallengeDataFuzz_WritesDistinctPayloadsThatRoundTrip()
    {
        HashSet<string> generatedPayloads = [];

        for (int index = 0; index < 8; index++)
        {
            byte[] challengeData = new byte[QuicPathValidation.PathChallengeDataLength];

            Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int bytesWritten));
            Assert.Equal(QuicPathValidation.PathChallengeDataLength, bytesWritten);
            Assert.True(generatedPayloads.Add(Convert.ToHexString(challengeData)));

            byte[] encoded = new byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(
                new QuicPathChallengeFrame(challengeData),
                encoded,
                out int encodedBytesWritten));
            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
                encoded.AsSpan(0, encodedBytesWritten),
                out QuicPathChallengeFrame parsed,
                out int bytesConsumed));
            Assert.Equal(encodedBytesWritten, bytesConsumed);
            Assert.True(challengeData.AsSpan().SequenceEqual(parsed.Data));
        }
    }
}

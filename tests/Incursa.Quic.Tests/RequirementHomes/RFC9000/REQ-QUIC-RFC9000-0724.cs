// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0724">For all other frames, the Frame Type field MUST simply identify the frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0724")]
public sealed class REQ_QUIC_RFC9000_0724
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FixedTypeFrames_DoNotIgnoreTheFrameTypeWhenPayloadShapeMatchesAnotherFrame()
    {
        byte[] pathData = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] pathResponsePayload = [0x1B, .. pathData];

        Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(pathResponsePayload, out _, out _));
        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(
            pathResponsePayload,
            out QuicPathResponseFrame parsedPathResponse,
            out int bytesConsumed));
        Assert.Equal(pathResponsePayload.Length, bytesConsumed);
        Assert.True(pathData.AsSpan().SequenceEqual(parsedPathResponse.Data));
    }
}

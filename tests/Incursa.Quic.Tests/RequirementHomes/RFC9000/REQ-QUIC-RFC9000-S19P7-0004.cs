// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
public sealed class REQ_QUIC_RFC9000_S19P7_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseNewTokenFrame_UsesTheTokenLengthFieldToRecoverTheWholeToken()
    {
        byte[] token = QuicS19P7NewTokenFrameTestSupport.CreateSequentialToken(64);

        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.Equal(token.Length, parsed.Token.Length);
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsTokenLengthThatExceedsRemainingPayload()
    {
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrameWithTokenLength(
            4,
            [0xAA, 0xBB, 0xCC]);

        QuicS19P7NewTokenFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_UsesOneByteTokenLengthAtTheShortestValidBoundary()
    {
        byte[] token = [0xA5];
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(encoded, token, expectedBytesConsumed: encoded.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzNewTokenFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzNewTokenFrame();
    }
}

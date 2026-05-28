// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
public sealed class REQ_QUIC_RFC9000_S19P7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_PreservesTheOpaqueTokenBytes()
    {
        byte[] token = [0x00, 0xFF, 0x11, 0x7E, 0x80, 0x01];
        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ParsedDifferentNewTokenValuesRemainDifferentOpaqueBlobs()
    {
        byte[] firstEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);
        byte[] secondEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.AlternateToken);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out _));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(secondEncoded, out QuicNewTokenFrame secondParsed, out _));
        Assert.False(firstParsed.Token.SequenceEqual(secondParsed.Token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_PreservesBytesThatCouldAppearInAFutureInitialToken()
    {
        byte[] token = [0x00, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xC0, 0xFF];
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(encoded, token, expectedBytesConsumed: encoded.Length);
    }
}

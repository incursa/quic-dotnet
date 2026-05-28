// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
public sealed class REQ_QUIC_RFC9000_S19P7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatNewTokenFrame_EncodesTheTokenLengthAsAVariableLengthInteger()
    {
        byte[] token = QuicS19P7NewTokenFrameTestSupport.CreateSequentialToken(64);

        QuicNewTokenFrame frame = new(token);
        Span<byte> destination = stackalloc byte[128];

        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(frame, destination, out int bytesWritten));
        Assert.Equal(67, bytesWritten);
        Assert.Equal(0x07, destination[0]);
        Assert.Equal(0x40, destination[1]);
        Assert.Equal(0x40, destination[2]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsTruncatedTokenLengthVariableInteger()
    {
        byte[] encoded = [0x07, 0x40];

        QuicS19P7NewTokenFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseNewTokenFrame_AcceptsTheTwoByteTokenLengthBoundary()
    {
        byte[] token = QuicS19P7NewTokenFrameTestSupport.CreateSequentialToken(64);
        byte[] encoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);

        QuicS19P7NewTokenFrameTestSupport.AssertParses(encoded, token, expectedBytesConsumed: encoded.Length);
        Assert.Equal(0x40, encoded[1]);
        Assert.Equal(0x40, encoded[2]);
    }
}

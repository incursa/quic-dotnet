// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
public sealed class REQ_QUIC_RFC9000_S19P4_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatResetStreamFrame_EncodesTypeAs04()
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(
            new QuicResetStreamFrame(streamId: 0x40, applicationProtocolErrorCode: 0x41, finalSize: 0x42),
            destination,
            out int bytesWritten));

        Assert.True(bytesWritten > 0);
        Assert.Equal(0x04, destination[0]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseResetStreamFrame_RejectsNonResetStreamType()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildResetStreamPayload(
            QuicVarintTestData.EncodeMinimal(0x05),
            QuicVarintTestData.EncodeMinimal(0x40),
            QuicVarintTestData.EncodeMinimal(0x41),
            QuicVarintTestData.EncodeMinimal(0x42));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseResetStreamFrame_AcceptsType04WithZeroFields()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(
            new QuicResetStreamFrame(streamId: 0, applicationProtocolErrorCode: 0, finalSize: 0));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0UL, parsed.StreamId);
        Assert.Equal(0UL, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, parsed.FinalSize);
    }
}

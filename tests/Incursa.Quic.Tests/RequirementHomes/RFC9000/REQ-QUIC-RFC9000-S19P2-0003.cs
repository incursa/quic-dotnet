// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P2-0003")]
public sealed class REQ_QUIC_RFC9000_S19P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_EncodesTypeAsVarintValue01()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.Equal((byte)0x01, destination[0]);

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination[..bytesWritten], out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParsePingFrame_RejectsNonPingTypeValue()
    {
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x00], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParsePingFrame_RejectsNonMinimalVarintEncodingOfType01()
    {
        Assert.False(QuicFrameCodec.TryParsePingFrame([0x40, 0x01], out _));
    }
}

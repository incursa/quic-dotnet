// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0365")]
public sealed class REQ_QUIC_RFC9000_0365
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_BuffersWhenCapacityIsExpanded()
    {
        QuicCryptoBuffer buffer = new(8192);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[5000]), out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
        Assert.Equal(5000, buffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAddFrame_ClosesWithBufferExceededWhenCapacityIsNotExpanded()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult firstResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, firstResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult secondResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, secondResult);
    }
}

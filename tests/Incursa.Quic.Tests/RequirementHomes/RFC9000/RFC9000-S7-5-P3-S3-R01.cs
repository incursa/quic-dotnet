// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-5-P3-S3-R01")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryAddFrame_ReportsBufferExceededWhenHandshakeCryptoCapacityWouldBeExceeded()
    {
        foreach ((ulong firstOffset, int firstLength, ulong secondOffset, int secondLength) in new[]
        {
            (0UL, 4095, 4095UL, 2),
            (0UL, 4080, 4080UL, 17),
            (0UL, 3072, 3072UL, 1025),
            (0UL, 1, 1UL, 4096),
        })
        {
            QuicCryptoBuffer buffer = new();

            Assert.True(buffer.TryAddFrame(
                new QuicCryptoFrame(firstOffset, new byte[firstLength]),
                out QuicCryptoBufferResult firstResult));
            Assert.Equal(QuicCryptoBufferResult.Buffered, firstResult);

            Assert.True(buffer.TryAddFrame(
                new QuicCryptoFrame(secondOffset, new byte[secondLength]),
                out QuicCryptoBufferResult secondResult));

            Assert.Equal(QuicCryptoBufferResult.BufferExceeded, secondResult);
            Assert.False(buffer.HandshakeComplete);
            Assert.False(buffer.DiscardingFutureFrames);
        }
    }
}

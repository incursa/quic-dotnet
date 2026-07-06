// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-5-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S7P5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_CanDiscardOverflowFramesAfterHandshakeCompletion()
    {
        QuicCryptoBuffer discardBuffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(discardBuffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult initialResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, initialResult);

        Assert.True(discardBuffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
        Assert.True(discardBuffer.DiscardingFutureFrames);

        Assert.True(discardBuffer.TryAddFrame(new QuicCryptoFrame(4097, [0xBB]), out QuicCryptoBufferResult futureResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, futureResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryAddFrame_DiscardsAndAcknowledgesOverflowFramesAfterHandshakeCompletion()
    {
        foreach ((ulong firstOffset, int firstLength, ulong overflowOffset, int overflowLength) in new[]
        {
            (0UL, 4095, 4095UL, 2),
            (0UL, 4080, 4080UL, 17),
            (0UL, 3072, 3072UL, 1025),
            (0UL, 1, 1UL, 4096),
        })
        {
            QuicCryptoBuffer discardBuffer = new()
            {
                HandshakeComplete = true,
            };

            Assert.True(discardBuffer.TryAddFrame(
                new QuicCryptoFrame(firstOffset, new byte[firstLength]),
                out QuicCryptoBufferResult firstResult));
            Assert.Equal(QuicCryptoBufferResult.Buffered, firstResult);

            Assert.True(discardBuffer.TryAddFrame(
                new QuicCryptoFrame(overflowOffset, new byte[overflowLength]),
                out QuicCryptoBufferResult overflowResult));

            Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
            Assert.True(discardBuffer.DiscardingFutureFrames);

            Assert.True(discardBuffer.TryAddFrame(
                new QuicCryptoFrame(overflowOffset + (ulong)overflowLength, [0xCC]),
                out QuicCryptoBufferResult futureResult));
            Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, futureResult);
        }
    }
}

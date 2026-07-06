// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P5-0004")]
public sealed class REQ_QUIC_RFC9000_S7P5_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAddFrame_DiscardsOverflowFramesAfterHandshakeCompletionWhenConfigured()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult initialResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, initialResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
        Assert.True(buffer.DiscardingFutureFrames);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_CanCloseAfterHandshakeCompletionInsteadOfDiscarding()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
            DiscardOverflowFramesAfterHandshakeComplete = false,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult initialResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, initialResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xCC]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, overflowResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAddFrame_ClosesAfterHandshakeCompletionAtTheOverflowBoundary()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
            DiscardOverflowFramesAfterHandshakeComplete = false,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult initialResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, initialResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xCC]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, overflowResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0004")]
    public void Fuzz_TryAddFrame_AppliesConfiguredPostHandshakeCryptoOverflowPolicy()
    {
        int[] capacities = [4096, 4101, 8192];
        bool[] discardModes = [true, false];

        foreach (int capacity in capacities)
        {
            foreach (bool discardOverflow in discardModes)
            {
                QuicCryptoBuffer buffer = new(capacity)
                {
                    HandshakeComplete = true,
                    DiscardOverflowFramesAfterHandshakeComplete = discardOverflow,
                };

                Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[capacity]), out QuicCryptoBufferResult initialResult));
                Assert.Equal(QuicCryptoBufferResult.Buffered, initialResult);

                Assert.True(buffer.TryAddFrame(new QuicCryptoFrame((ulong)capacity, [0xA5]), out QuicCryptoBufferResult overflowResult));

                if (discardOverflow)
                {
                    Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
                    Assert.True(buffer.DiscardingFutureFrames);

                    Assert.True(buffer.TryAddFrame(
                        new QuicCryptoFrame((ulong)capacity + 1, [0x5A]),
                        out QuicCryptoBufferResult laterResult));
                    Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, laterResult);
                }
                else
                {
                    Assert.Equal(QuicCryptoBufferResult.BufferExceeded, overflowResult);
                    Assert.False(buffer.DiscardingFutureFrames);
                }
            }
        }
    }
}

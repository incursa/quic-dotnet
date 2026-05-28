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
}

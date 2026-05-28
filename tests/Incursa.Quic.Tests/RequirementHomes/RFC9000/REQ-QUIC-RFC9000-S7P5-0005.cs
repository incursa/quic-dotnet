// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P5-0005")]
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
}

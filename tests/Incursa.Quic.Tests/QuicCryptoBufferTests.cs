namespace Incursa.Quic.Tests;

public sealed class QuicCryptoBufferTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAddFrame_BuffersOutOfOrderFramesAndDequeuesContiguousBytes()
    {
        QuicCryptoBuffer buffer = new();

        byte[] tail = [0x05, 0x06];
        byte[] head = [0x01, 0x02, 0x03, 0x04];

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4, tail), out QuicCryptoBufferResult tailResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, tailResult);
        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, head), out QuicCryptoBufferResult headResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, headResult);
        Assert.Equal(6, buffer.BufferedBytes);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(buffer.TryDequeueContiguousData(destination, out int bytesWritten));
        Assert.Equal(6, bytesWritten);
        Assert.True(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(0, buffer.BufferedBytes);
        Assert.False(buffer.TryDequeueContiguousData(destination, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryAddFrame_AllowsConfiguredCapacityDuringHandshake()
    {
        QuicCryptoBuffer buffer = new(8192);
        byte[] cryptoData = new byte[5000];

        Assert.Equal(8192, buffer.Capacity);
        Assert.False(buffer.HandshakeComplete);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, cryptoData), out QuicCryptoBufferResult result));
        Assert.Equal(QuicCryptoBufferResult.Buffered, result);
        Assert.Equal(5000, buffer.BufferedBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAddFrame_ClosesWithBufferExceededWhenCapacityIsNotExpanded()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult firstResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, firstResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult secondResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, secondResult);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
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

        Assert.True(discardBuffer.TryAddFrame(new QuicCryptoFrame(4097, [0xBB]), out QuicCryptoBufferResult futureResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, futureResult);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
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
}

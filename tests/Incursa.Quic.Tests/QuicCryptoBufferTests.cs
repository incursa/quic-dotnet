namespace Incursa.Quic.Tests;

public sealed class QuicCryptoBufferTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0001">Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0005">QUIC implementations SHOULD provide an interface for the cryptographic protocol implementation to communicate its buffering limits.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0001">Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0002">Endpoints MAY choose to allow more data to be buffered during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0005">QUIC implementations SHOULD provide an interface for the cryptographic protocol implementation to communicate its buffering limits.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0001">Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0003">If an endpoint does not expand its buffer, it MUST close the connection with a CRYPTO_BUFFER_EXCEEDED error code.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0005">QUIC implementations SHOULD provide an interface for the cryptographic protocol implementation to communicate its buffering limits.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0004">Once the handshake completes, if an endpoint is unable to buffer all data in a CRYPTO frame, it MAY discard that CRYPTO frame and all future CRYPTO frames or close the connection with a CRYPTO_BUFFER_EXCEEDED error code.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0005">Packets containing discarded CRYPTO frames MUST be acknowledged because the packet has been received and processed by the transport even though the CRYPTO frame was discarded.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0005">QUIC implementations SHOULD provide an interface for the cryptographic protocol implementation to communicate its buffering limits.</workbench-requirement>
    /// </workbench-requirements>
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P5-0004">Once the handshake completes, if an endpoint is unable to buffer all data in a CRYPTO frame, it MAY discard that CRYPTO frame and all future CRYPTO frames or close the connection with a CRYPTO_BUFFER_EXCEEDED error code.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0005">QUIC implementations SHOULD provide an interface for the cryptographic protocol implementation to communicate its buffering limits.</workbench-requirement>
    /// </workbench-requirements>
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

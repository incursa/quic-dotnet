namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P4-0004">Initial and Handshake secrets MUST be discarded as soon as Handshake and 1-RTT keys are proven to be available to both client and server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P4-0004")]
public sealed class REQ_QUIC_RFC9002_S6P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAddFrame_DiscardOverflowFramesAsSoonAsReplacementKeysExist()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xAA]), out QuicCryptoBufferResult discardedResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, discardedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4097, [0xBB]), out QuicCryptoBufferResult futureResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, futureResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAddFrame_ClosesWithBufferExceededBeforeReplacementKeysExist()
    {
        QuicCryptoBuffer buffer = new();

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4096]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xCC]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.BufferExceeded, overflowResult);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAddFrame_TransitionsFromBufferingToDiscardingAtTheHandshakeCompleteBoundary()
    {
        QuicCryptoBuffer buffer = new()
        {
            HandshakeComplete = true,
        };

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(0, new byte[4095]), out QuicCryptoBufferResult bufferedResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, bufferedResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4095, [0xDD]), out QuicCryptoBufferResult boundaryResult));
        Assert.Equal(QuicCryptoBufferResult.Buffered, boundaryResult);

        Assert.True(buffer.TryAddFrame(new QuicCryptoFrame(4096, [0xEE]), out QuicCryptoBufferResult overflowResult));
        Assert.Equal(QuicCryptoBufferResult.DiscardedAndAcknowledged, overflowResult);
    }
}

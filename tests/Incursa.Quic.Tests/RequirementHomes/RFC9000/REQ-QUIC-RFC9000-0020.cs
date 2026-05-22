namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0020")]
public sealed class REQ_QUIC_RFC9000_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteStreamAsync_CreatesTheNextLocalStreamWhenDataIsWrittenBeforeAnExplicitOpen()
    {
        (QuicConnectionRuntime runtime, _) = CreateRuntimeWithEffectCapture();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId.Value, out _));

        byte[] payload =
        [
            0x21,
            0x22,
            0x23,
            0x24,
        ];

        await runtime.WriteStreamAsync(streamId.Value, payload);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            streamId.Value,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.Equal((ulong)payload.Length, snapshot.UniqueBytesSent);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteStreamAsync_DoesNotCreateANonNextLocalStream()
    {
        (QuicConnectionRuntime runtime, List<QuicConnectionEffect> effects) = CreateRuntimeWithEffectCapture();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId nextStreamId,
            out _));
        ulong skippedStreamId = nextStreamId.Value + 4;

        byte[] payload =
        [
            0x31,
            0x32,
        ];

        await Assert.ThrowsAsync<InvalidOperationException>(() => runtime.WriteStreamAsync(skippedStreamId, payload).AsTask());

        Assert.Empty(effects);
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(skippedStreamId, out _));
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(nextStreamId.Value, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task WriteStreamAsync_DoesNotCreateAStreamForAnEmptyPayload()
    {
        (QuicConnectionRuntime runtime, List<QuicConnectionEffect> effects) = CreateRuntimeWithEffectCapture();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryPeekLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out _));

        await runtime.WriteStreamAsync(streamId.Value, ReadOnlyMemory<byte>.Empty);

        Assert.Empty(effects);
        Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId.Value, out _));
    }

    private static (QuicConnectionRuntime Runtime, List<QuicConnectionEffect> Effects) CreateRuntimeWithEffectCapture()
    {
        QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        // Initialize a sendable active path without going through path-migration validation.
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 8,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 8).StateChanged);
        List<QuicConnectionEffect> effects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            effects.AddRange(transition.Effects);
            return true;
        });

        return (runtime, effects);
    }
}

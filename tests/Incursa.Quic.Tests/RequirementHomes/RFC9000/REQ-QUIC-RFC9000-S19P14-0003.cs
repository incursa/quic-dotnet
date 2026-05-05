namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0003">A STREAMS_BLOCKED frame MUST NOT open the stream, but informs the peer that a new stream was needed and the stream limit prevented the creation of the stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P14-0003")]
public sealed class REQ_QUIC_RFC9000_S19P14_0003
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStreamAsync_EmitsStreamsBlockedWithoutOpeningTheBlockedStream(bool bidirectional)
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        List<QuicStream> openedStreams = [];
        using CancellationTokenSource cancellationSource = new();
        try
        {
            QuicStreamType streamType = StreamTypeForDirection(bidirectional);
            await ExhaustOutboundStreamLimitAsync(runtime, streamType, openedStreams);
            outboundEffects.Clear();

            Task<QuicStream> blockedOpenTask = runtime.OpenOutboundStreamAsync(
                streamType,
                cancellationSource.Token).AsTask();

            await Task.Delay(100);
            Assert.False(blockedOpenTask.IsCompleted);

            QuicConnectionSendDatagramEffect sendEffect = Assert.IsType<QuicConnectionSendDatagramEffect>(
                Assert.Single(outboundEffects));
            QuicStreamsBlockedFrame blockedFrame = OpenStreamsBlockedFrame(runtime, sendEffect.Datagram.Span);

            Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
            Assert.Equal(4UL, blockedFrame.MaximumStreams);
            Assert.False(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
                bidirectional ? 16UL : 18UL,
                out _));

            cancellationSource.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blockedOpenTask);
        }
        finally
        {
            cancellationSource.Cancel();
            foreach (QuicStream stream in openedStreams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotOpenAnotherLocalStreamWhenItReturnsStreamsBlocked(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);
        Assert.Equal(bidirectional ? 0UL : 2UL, firstStreamId.Value);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot initialSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, initialSnapshot.SendState);

        Assert.False(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot afterSnapshot));
        Assert.Equal(initialSnapshot, afterSnapshot);
        Assert.False(state.TryGetStreamSnapshot(firstStreamId.Value + 4UL, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryOpenLocalStream_DoesNotCreateAStreamAtZeroPeerStreamLimit(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 0UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 0UL);

        Assert.False(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));

        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);
        Assert.False(state.TryGetStreamSnapshot(bidirectional ? 0UL : 2UL, out _));
    }

    private static async Task ExhaustOutboundStreamLimitAsync(
        QuicConnectionRuntime runtime,
        QuicStreamType streamType,
        List<QuicStream> openedStreams)
    {
        for (int index = 0; index < 4; index++)
        {
            openedStreams.Add(await runtime.OpenOutboundStreamAsync(streamType));
            AcknowledgeTrackedPackets(runtime);
        }
    }

    private static QuicStreamType StreamTypeForDirection(bool bidirectional)
    {
        return bidirectional
            ? QuicStreamType.Bidirectional
            : QuicStreamType.Unidirectional;
    }

    private static QuicStreamsBlockedFrame OpenStreamsBlockedFrame(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStreamsBlockedFrame blockedFrame,
            out int bytesConsumed));

        Assert.True(bytesConsumed > 0);
        Assert.True(bytesConsumed <= payloadLength);
        return blockedFrame;
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }
}

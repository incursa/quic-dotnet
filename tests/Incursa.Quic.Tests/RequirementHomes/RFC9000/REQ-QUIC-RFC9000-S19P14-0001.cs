namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0001">A sender SHOULD send a STREAMS_BLOCKED frame (type=0x16 or 0x17) when it wishes to open a stream but is unable to do so due to the maximum stream limit set by its peer; see Section 19.11.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P14-0001")]
public sealed class REQ_QUIC_RFC9000_S19P14_0001
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_ReturnsStreamsBlockedWhenThePeerLimitIsReached(bool bidirectional)
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

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);

        Assert.False(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0022")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0023")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStreamAsync_EmitsStreamsBlockedWhenStreamLimitIsExhausted(bool bidirectional)
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
            await ExhaustOutboundStreamLimitAsync(runtime, StreamTypeForDirection(bidirectional), openedStreams);
            outboundEffects.Clear();

            Task<QuicStream> blockedOpenTask = runtime.OpenOutboundStreamAsync(
                StreamTypeForDirection(bidirectional),
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

            KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> blockedPacket = Assert.Single(
                runtime.SendRuntime.SentPackets,
                entry => entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
            Assert.True(runtime.SendRuntime.TryRegisterLoss(
                blockedPacket.Key.PacketNumberSpace,
                blockedPacket.Key.PacketNumber,
                handshakeConfirmed: true));
            Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
            Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
            Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
            Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));

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
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenOutboundStreamAsync_DoesNotEmitStreamsBlockedWhileAckElicitingPacketIsInFlight(bool bidirectional)
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
            for (int index = 0; index < 4; index++)
            {
                openedStreams.Add(await runtime.OpenOutboundStreamAsync(streamType));
                if (index < 3)
                {
                    AcknowledgeTrackedPackets(runtime);
                }
            }

            outboundEffects.Clear();
            Task<QuicStream> blockedOpenTask = runtime.OpenOutboundStreamAsync(
                streamType,
                cancellationSource.Token).AsTask();

            await Task.Delay(100);
            Assert.False(blockedOpenTask.IsCompleted);
            Assert.Empty(outboundEffects);

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

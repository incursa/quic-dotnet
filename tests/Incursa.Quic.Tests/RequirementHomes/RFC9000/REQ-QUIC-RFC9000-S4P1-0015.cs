namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0015">A sender that is flow control limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it has no ack-eliciting packets in flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
public sealed class REQ_QUIC_RFC9000_S4P1_0015
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_ReemitsBlockedFramesWhileTheLimitRemainsClosed()
    {
        QuicConnectionStreamState connectionBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(connectionBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId connectionBlockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame firstDataBlockedFrame,
            out QuicStreamDataBlockedFrame firstStreamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, firstDataBlockedFrame.MaximumData);
        Assert.Equal(default, firstStreamDataBlockedFrame);

        Assert.False(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame repeatedDataBlockedFrame,
            out QuicStreamDataBlockedFrame repeatedStreamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, repeatedDataBlockedFrame.MaximumData);
        Assert.Equal(default, repeatedStreamDataBlockedFrame);

        Assert.True(connectionBlockedState.TryApplyMaxDataFrame(new QuicMaxDataFrame(2)));
        Assert.True(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out firstDataBlockedFrame,
            out firstStreamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, firstDataBlockedFrame);
        Assert.Equal(default, firstStreamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        QuicConnectionStreamState streamBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalStreamLimit: 1);

        Assert.True(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamBlockedStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame firstStreamsBlockedFrame));
        Assert.True(firstStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, firstStreamsBlockedFrame.MaximumStreams);

        Assert.False(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame repeatedStreamsBlockedFrame));
        Assert.True(repeatedStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, repeatedStreamsBlockedFrame.MaximumStreams);

        Assert.True(streamBlockedState.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.True(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId reopenedStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.NotEqual(streamBlockedStreamId, reopenedStreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_EmitsStreamDataBlockedWhenTheSenderIsFlowControlLimitedAndNothingAckElicitingIsInFlight()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            openPacket.Key.PacketNumberSpace,
            openPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        outboundEffects.Clear();

        byte[] payload = new byte[100];
        NotSupportedException exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => stream.WriteAsync(payload, 0, payload.Length));

        Assert.Contains("flow-control credit", exception.Message);

        Assert.Single(outboundEffects);
        QuicConnectionSendDatagramEffect sendEffect = Assert.IsType<QuicConnectionSendDatagramEffect>(
            outboundEffects[0]);

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStreamDataBlockedFrame blockedFrame,
            out int bytesConsumed));

        Assert.True(bytesConsumed > 0);
        Assert.True(bytesConsumed <= payloadLength);
        Assert.Equal((ulong)stream.Id, blockedFrame.StreamId);
        Assert.Equal(8UL, blockedFrame.MaximumStreamData);

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
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_DoesNotEmitABlockedSignalWhileAnAckElicitingPacketIsStillInFlight()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = new byte[100];
        NotSupportedException exception = await Assert.ThrowsAsync<NotSupportedException>(
            () => stream.WriteAsync(payload, 0, payload.Length));

        Assert.Contains("flow-control credit", exception.Message);
        Assert.Empty(outboundEffects);
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

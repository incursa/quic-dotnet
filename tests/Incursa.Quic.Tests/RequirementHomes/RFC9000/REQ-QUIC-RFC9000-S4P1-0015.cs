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

    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0008">An endpoint in the Send state MUST generate STREAM_DATA_BLOCKED frames if it is blocked from sending by stream flow control limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0014">A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver that it has data to write but is blocked by flow control limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0015">A sender that is flow control limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it has no ack-eliciting packets in flight.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0022">Blocked signals MUST be carried in DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0023">DATA_BLOCKED, STREAM_DATA_BLOCKED, and STREAMS_BLOCKED frames MUST use connection, stream, and stream-type scope respectively.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0024">A new frame MUST be sent if a packet containing the most recent frame for a scope is lost, but only while the endpoint is blocked on the corresponding limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0025">These frames MUST always include the limit that is causing blocking at the time that they are transmitted.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0001">A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes to send data but is unable to do so due to stream-level flow control.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0006">STREAM_DATA_BLOCKED frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0007">The Stream ID field MUST be variable-length integer indicating the stream that is blocked due to flow control.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0008">The Maximum Stream Data field MUST be variable-length integer indicating the offset of the stream at which the blocking occurred.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0022")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0023")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0024")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0025")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
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
    [Requirement("REQ-QUIC-RFC9000-S19P12-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_EmitsDataBlockedWhenConnectionFlowControlLimitedAndNothingAckElicitingIsInFlight()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);
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

        byte[] payload = new byte[2];
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

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicDataBlockedFrame blockedFrame,
            out int bytesConsumed));

        Assert.True(bytesConsumed > 0);
        Assert.True(bytesConsumed <= payloadLength);
        Assert.Equal(1UL, blockedFrame.MaximumData);

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

    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0015">A sender that is flow control limited SHOULD periodically send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame when it has no ack-eliciting packets in flight.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P2-0004">A blocked sender MUST NOT be required to send STREAM_DATA_BLOCKED or DATA_BLOCKED frames.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S4P2-0004")]
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_DoesNotEmitDataBlockedWhileAnAckElicitingPacketIsStillInFlight()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);
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

        byte[] payload = new byte[2];
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

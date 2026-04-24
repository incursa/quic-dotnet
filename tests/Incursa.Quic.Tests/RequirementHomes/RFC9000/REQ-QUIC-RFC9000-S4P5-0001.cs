namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0001">A sender MUST always communicate the final size of a stream to the receiver reliably, no matter how the stream is terminated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
public sealed class REQ_QUIC_RFC9000_S4P5_0001
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_CommunicatesFinalSizeWhenTerminatedWithFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x33, 0x44], offset: 2),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveResetStreamFrame_CommunicatesFinalSizeWhenTerminatedWithReset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(5UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_CommunicatesFinalSizeWhenTerminatedWithFin()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 32,
            peerUnidirectionalStreamLimit: 1,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamSendState.DataSent, snapshot.SendState);
        Assert.Equal(2UL, snapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAbortLocalStreamWrites_CommunicatesFinalSizeWhenTerminatedWithReset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 32,
            peerUnidirectionalStreamLimit: 1,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 3,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3UL, finalSize);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(3UL, snapshot.FinalSize);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(3UL, snapshot.UniqueBytesSent);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task TryRegisterLoss_RetransmitsFinTerminationWithTheSameFinalSize()
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
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] payload = [0x11, 0x22, 0x33];
        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect dataSendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);
        StreamFrameView dataFrame = OpenFirstStreamFrame(runtime, dataSendEffect.Datagram);
        Assert.Equal((ulong)stream.Id, dataFrame.StreamId);
        Assert.Equal(0UL, dataFrame.Offset);
        Assert.False(dataFrame.IsFin);
        Assert.True(dataFrame.StreamData.AsSpan().SequenceEqual(payload));

        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();

        QuicConnectionSendDatagramEffect finSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        StreamFrameView finFrame = OpenFirstStreamFrame(runtime, finSendEffect.Datagram);
        Assert.Equal((ulong)stream.Id, finFrame.StreamId);
        Assert.Equal((ulong)payload.Length, finFrame.Offset);
        Assert.True(finFrame.IsFin);
        Assert.Empty(finFrame.StreamData);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> finPacket = FindSentPacket(
            runtime,
            finSendEffect);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            finPacket.Key.PacketNumberSpace,
            finPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(finSendEffect.Datagram.Span));
        Assert.NotNull(retransmission.StreamIds);
        Assert.Equal([(ulong)stream.Id], retransmission.StreamIds);

        StreamFrameView retransmittedFrame = ParseFirstStreamFrame(retransmission.PlaintextPayload);
        Assert.Equal(finFrame.StreamId, retransmittedFrame.StreamId);
        Assert.Equal(finFrame.Offset, retransmittedFrame.Offset);
        Assert.True(retransmittedFrame.IsFin);
        Assert.Empty(retransmittedFrame.StreamData);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task TryRegisterLoss_RetransmitsResetTerminationWithTheSameFinalSize()
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
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] payload = [0x44, 0x55];
        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect dataSendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);
        StreamFrameView dataFrame = OpenFirstStreamFrame(runtime, dataSendEffect.Datagram);
        Assert.Equal((ulong)stream.Id, dataFrame.StreamId);
        Assert.Equal(0UL, dataFrame.Offset);
        Assert.False(dataFrame.IsFin);
        Assert.True(dataFrame.StreamData.AsSpan().SequenceEqual(payload));

        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        await runtime.AbortStreamWritesAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect resetSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        QuicResetStreamFrame resetFrame = OpenFirstResetStreamFrame(runtime, resetSendEffect.Datagram);
        Assert.Equal((ulong)stream.Id, resetFrame.StreamId);
        Assert.Equal(0x99UL, resetFrame.ApplicationProtocolErrorCode);
        Assert.Equal((ulong)payload.Length, resetFrame.FinalSize);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = FindSentPacket(
            runtime,
            resetSendEffect);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(resetSendEffect.Datagram.Span));

        QuicResetStreamFrame retransmittedResetFrame = ParseFirstResetStreamFrame(retransmission.PlaintextPayload);
        Assert.Equal(resetFrame.StreamId, retransmittedResetFrame.StreamId);
        Assert.Equal(resetFrame.ApplicationProtocolErrorCode, retransmittedResetFrame.ApplicationProtocolErrorCode);
        Assert.Equal(resetFrame.FinalSize, retransmittedResetFrame.FinalSize);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task TryAcknowledgePacket_KeepsQueuedFinalSizeRetransmissionAfterUnrelatedAcknowledgment()
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
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask();

        QuicConnectionSendDatagramEffect finSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        StreamFrameView finFrame = OpenFirstStreamFrame(runtime, finSendEffect.Datagram);
        Assert.Equal((ulong)stream.Id, finFrame.StreamId);
        Assert.Equal(0UL, finFrame.Offset);
        Assert.True(finFrame.IsFin);
        Assert.Empty(finFrame.StreamData);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> finPacket = FindSentPacket(
            runtime,
            finSendEffect);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            finPacket.Key.PacketNumberSpace,
            finPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.False(runtime.SendRuntime.TryAcknowledgePacket(
            finPacket.Key.PacketNumberSpace,
            finPacket.Key.PacketNumber + 1,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        StreamFrameView retransmittedFrame = ParseFirstStreamFrame(retransmission.PlaintextPayload);
        Assert.Equal(finFrame.StreamId, retransmittedFrame.StreamId);
        Assert.Equal(finFrame.Offset, retransmittedFrame.Offset);
        Assert.True(retransmittedFrame.IsFin);
        Assert.Empty(retransmittedFrame.StreamData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FinalSizeRemainsStableAcrossSupportedTerminationOrders()
    {
        Random random = new(0x45F1_9000);

        for (int iteration = 0; iteration < 96; iteration++)
        {
            int payloadLength = random.Next(1, 9);
            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            ulong streamId = 1;
            ulong finalSize = (ulong)payloadLength;

            QuicConnectionStreamState finThenResetState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                peerBidirectionalReceiveLimit: 8);
            ReceiveDataPrefix(finThenResetState, streamId, payload);
            ReceiveFinAtFinalSize(finThenResetState, streamId, finalSize);
            AssertFinalSize(finThenResetState, streamId, finalSize);

            Assert.True(finThenResetState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationProtocolErrorCode: 0x99, finalSize),
                out QuicMaxDataFrame maxDataFrame,
                out QuicTransportErrorCode errorCode));
            _ = maxDataFrame;
            Assert.Equal(default, errorCode);
            AssertFinalSize(finThenResetState, streamId, finalSize);

            QuicConnectionStreamState resetThenFinState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                peerBidirectionalReceiveLimit: 8);
            ReceiveDataPrefix(resetThenFinState, streamId, payload);
            Assert.True(resetThenFinState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationProtocolErrorCode: 0x99, finalSize),
                out maxDataFrame,
                out errorCode));
            _ = maxDataFrame;
            Assert.Equal(default, errorCode);
            AssertFinalSize(resetThenFinState, streamId, finalSize);
            ReceiveFinAtFinalSize(resetThenFinState, streamId, finalSize);
            AssertFinalSize(resetThenFinState, streamId, finalSize);

            QuicConnectionStreamState sendResetState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 256,
                peerUnidirectionalStreamLimit: 1,
                localUnidirectionalSendLimit: 64);
            Assert.True(sendResetState.TryOpenLocalStream(
                bidirectional: false,
                out QuicStreamId localStreamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);
            Assert.True(sendResetState.TryReserveSendCapacity(
                localStreamId.Value,
                offset: 0,
                length: payloadLength,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.True(sendResetState.TryAbortLocalStreamWrites(localStreamId.Value, out ulong resetFinalSize, out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)payloadLength, resetFinalSize);
            AssertFinalSize(sendResetState, localStreamId.Value, resetFinalSize);

            Assert.False(sendResetState.TryAbortLocalStreamWrites(localStreamId.Value, out _, out errorCode));
            Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
            AssertFinalSize(sendResetState, localStreamId.Value, resetFinalSize);
        }
    }

    private static void ReceiveDataPrefix(
        QuicConnectionStreamState state,
        ulong streamId,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, payload, offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    private static void ReceiveFinAtFinalSize(
        QuicConnectionStreamState state,
        ulong streamId,
        ulong finalSize)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [], offset: finalSize),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
    }

    private static void AssertFinalSize(
        QuicConnectionStreamState state,
        ulong streamId,
        ulong expectedFinalSize)
    {
        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(expectedFinalSize, snapshot.FinalSize);
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

    private static QuicConnectionSendDatagramEffect GetSingleStreamSendEffect(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionEffect> outboundEffects)
    {
        QuicConnectionSendDatagramEffect[] sendEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        if (sendEffects.Length == 1)
        {
            return sendEffects[0];
        }

        Assert.Empty(sendEffects);
        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);

        return Assert.Single(timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
    }

    private static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> FindSentPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect)
    {
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
    }

    private static StreamFrameView OpenFirstStreamFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        return ParseFirstStreamFrame(openedPacket.AsMemory(payloadOffset, payloadLength));
    }

    private static QuicResetStreamFrame OpenFirstResetStreamFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        return ParseFirstResetStreamFrame(openedPacket.AsMemory(payloadOffset, payloadLength));
    }

    private static StreamFrameView ParseFirstStreamFrame(ReadOnlyMemory<byte> payload)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload.Span, out QuicStreamFrame frame));
        AssertOnlyPadding(payload.Span[frame.ConsumedLength..]);
        return new StreamFrameView(
            frame.StreamId.Value,
            frame.Offset,
            frame.IsFin,
            frame.StreamData.ToArray());
    }

    private static QuicResetStreamFrame ParseFirstResetStreamFrame(ReadOnlyMemory<byte> payload)
    {
        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
            payload.Span,
            out QuicResetStreamFrame frame,
            out int bytesConsumed));
        AssertOnlyPadding(payload.Span[bytesConsumed..]);
        return frame;
    }

    private static void AssertOnlyPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            Assert.Equal(0x00, payload[0]);
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            payload = payload[paddingBytesConsumed..];
        }
    }

    private readonly record struct StreamFrameView(
        ulong StreamId,
        ulong Offset,
        bool IsFin,
        byte[] StreamData);
}

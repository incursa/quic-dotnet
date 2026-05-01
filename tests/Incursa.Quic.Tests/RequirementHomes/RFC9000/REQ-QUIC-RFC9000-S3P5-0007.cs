namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0007">If any outstanding data is declared lost, the endpoint SHOULD send a RESET_STREAM frame instead of retransmitting the data.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0007")]
public sealed class REQ_QUIC_RFC9000_S3P5_0007
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task TryRegisterLoss_QueuesStreamDataForRepairBeforeTheStreamIsAborted()
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

        byte[] payload = [0x11];

        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect sendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> streamPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.Equal(0UL, streamFrame.Offset);
        Assert.True(streamFrame.StreamData.SequenceEqual(payload));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            streamPacket.Key.PacketNumberSpace,
            streamPacket.Key.PacketNumber,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AbortStreamWrites_ReplacesQueuedStreamDataRetransmissionWithResetStream()
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

        byte[] payload = [0x33];

        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect streamSendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> streamPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(streamSendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            streamPacket.Key.PacketNumberSpace,
            streamPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        outboundEffects.Clear();
        await runtime.AbortStreamWritesAsync((ulong)stream.Id, 0x99);

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));

        QuicConnectionSendDatagramEffect resetSendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);
        Assert.False(resetSendEffect.Datagram.Span.SequenceEqual(streamSendEffect.Datagram.Span));

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(resetSendEffect.Datagram.Span));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            resetSendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedResetPacket,
            out int resetPayloadOffset,
            out int resetPayloadLength,
            out bool resetKeyPhase));
        Assert.False(resetKeyPhase);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
            openedResetPacket.AsSpan(resetPayloadOffset, resetPayloadLength),
            out QuicResetStreamFrame resetStreamFrame,
            out _,
            out _));
        Assert.Equal((ulong)stream.Id, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal((ulong)payload.Length, resetStreamFrame.FinalSize);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(resetSendEffect.Datagram.Span));
        Assert.False(retransmission.PacketBytes.Span.SequenceEqual(streamSendEffect.Datagram.Span));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortStreamWrites_RemovesTheQueuedStreamDataRetransmission()
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

        byte[] payload = [0x22];

        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect sendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> streamPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            streamPacket.Key.PacketNumberSpace,
            streamPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        outboundEffects.Clear();
        await runtime.AbortStreamWritesAsync((ulong)stream.Id, 0x99);

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
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
}

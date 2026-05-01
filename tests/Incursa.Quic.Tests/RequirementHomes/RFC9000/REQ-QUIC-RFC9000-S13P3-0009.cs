namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0009">Once an endpoint sends a RESET_STREAM frame, it MAY omit further STREAM frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0009")]
public sealed class REQ_QUIC_RFC9000_S13P3_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ResetStreamActionRemovesQueuedStreamDataRetransmission()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 96,
            localBidirectionalSendLimit: 96);
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

        byte[] payload = new byte[32];
        payload.AsSpan().Fill(0x37);

        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect streamSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> streamPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, streamSend.Datagram);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            streamPacket.Key.PacketNumberSpace,
            streamPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        outboundEffects.Clear();
        await runtime.AbortStreamWritesAsync((ulong)stream.Id, applicationErrorCode: 0x99);

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));

        QuicConnectionSendDatagramEffect resetSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] resetPlaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, resetSend);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
            resetPlaintext,
            out QuicResetStreamFrame resetStreamFrame,
            out _,
            out _));
        Assert.Equal((ulong)stream.Id, resetStreamFrame.StreamId);
        Assert.False(TryFindStreamFrame(resetPlaintext, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ResetStreamActionSuppressesQueuedDelayedStreamFrames()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 96,
            localBidirectionalSendLimit: 96);
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

        byte[] payload = [0x44];

        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        long? delayedSendDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(delayedSendDueTicks);
        ulong delayedSendGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        await runtime.AbortStreamWritesAsync((ulong)stream.Id, applicationErrorCode: 0x99);

        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        QuicConnectionSendDatagramEffect resetSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] resetPlaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, resetSend);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
            resetPlaintext,
            out QuicResetStreamFrame resetStreamFrame,
            out int resetFrameOffset,
            out int resetBytesConsumed));
        Assert.Equal((ulong)stream.Id, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.False(TryFindStreamFrame(resetPlaintext, out _));

        ReadOnlySpan<byte> afterReset = QuicS13AckPiggybackTestSupport.SkipPadding(
            resetPlaintext.AsSpan(resetFrameOffset + resetBytesConsumed));
        Assert.True(afterReset.IsEmpty);

        QuicConnectionTransitionResult staleTimerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                delayedSendDueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                delayedSendGeneration),
            nowTicks: delayedSendDueTicks.Value);

        Assert.DoesNotContain(
            staleTimerResult.Effects,
            effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static bool TryFindStreamFrame(ReadOnlySpan<byte> payload, out QuicStreamFrame frame)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicStreamParser.TryParseStreamFrame(remaining, out frame))
            {
                return true;
            }

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed)
                || QuicFrameCodec.TryParseResetStreamFrame(remaining, out _, out ackBytesConsumed)
                || QuicFrameCodec.TryParseStopSendingFrame(remaining, out _, out ackBytesConsumed)
                || QuicFrameCodec.TryParsePingFrame(remaining, out ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            break;
        }

        frame = default;
        return false;
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

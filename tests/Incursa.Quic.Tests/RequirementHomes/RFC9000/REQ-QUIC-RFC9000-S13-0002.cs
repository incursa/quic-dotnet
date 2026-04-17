namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0002">A sender MAY wait for a short period of time to collect multiple frames before sending a packet that is not maximally packed, to avoid sending out large numbers of small packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0002")]
public sealed class REQ_QUIC_RFC9000_S13_0002
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_CoalescesMultipleSmallWritesAfterTheSendDelayExpires()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        byte[] firstPayload = [0xA1];
        byte[] secondPayload = [0xB2];

        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);

        bool sawQueuedStreamFrame = false;
        foreach (QuicConnectionSendDatagramEffect queuedSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator queuedApplicationCoordinator = new(PacketConnectionId);
            if (!queuedApplicationCoordinator.TryOpenProtectedApplicationDataPacket(
                queuedSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] queuedOpenedPacket,
                out int queuedPayloadOffset,
                out int queuedPayloadLength,
                out bool queuedKeyPhase))
            {
                continue;
            }

            Assert.False(queuedKeyPhase);
            ReadOnlySpan<byte> packetPayload = queuedOpenedPacket.AsSpan(queuedPayloadOffset, queuedPayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(firstPayload))
            {
                sawQueuedStreamFrame = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrame);

        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);
        bool sawQueuedStreamFrameAfterSecondWrite = false;
        foreach (QuicConnectionSendDatagramEffect secondWriteSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator secondWriteCoordinator = new(PacketConnectionId);
            if (!secondWriteCoordinator.TryOpenProtectedApplicationDataPacket(
                secondWriteSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] secondWriteOpenedPacket,
                out int secondWritePayloadOffset,
                out int secondWritePayloadLength,
                out bool secondWriteKeyPhase))
            {
                continue;
            }

            Assert.False(secondWriteKeyPhase);
            ReadOnlySpan<byte> packetPayload = secondWriteOpenedPacket.AsSpan(secondWritePayloadOffset, secondWritePayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == (ulong)firstPayload.Length
                && frame.StreamData.SequenceEqual(secondPayload))
            {
                sawQueuedStreamFrameAfterSecondWrite = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrameAfterSecondWrite);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame firstFrame));
        Assert.Equal((ulong)stream.Id, firstFrame.StreamId.Value);
        Assert.Equal(0UL, firstFrame.Offset);
        Assert.True(firstFrame.StreamData.SequenceEqual(firstPayload));

        ReadOnlySpan<byte> remainder = SkipPadding(payload[firstFrame.ConsumedLength..]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainder, out QuicStreamFrame secondFrame));
        Assert.Equal((ulong)stream.Id, secondFrame.StreamId.Value);
        Assert.Equal((ulong)firstPayload.Length, secondFrame.Offset);
        Assert.True(secondFrame.StreamData.SequenceEqual(secondPayload));

        ReadOnlySpan<byte> tail = SkipPadding(remainder[secondFrame.ConsumedLength..]);
        Assert.True(tail.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_DoesNotSendTheQueuedPacketBeforeTheDelayExpires()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        byte[] payload = [0xCC];
        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);

        bool sawQueuedStreamFrame = false;
        foreach (QuicConnectionSendDatagramEffect queuedSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator queuedApplicationCoordinator = new(PacketConnectionId);
            if (!queuedApplicationCoordinator.TryOpenProtectedApplicationDataPacket(
                queuedSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] queuedOpenedPacket,
                out int queuedPayloadOffset,
                out int queuedPayloadLength,
                out bool queuedKeyPhase))
            {
                continue;
            }

            Assert.False(queuedKeyPhase);
            ReadOnlySpan<byte> packetPayload = queuedOpenedPacket.AsSpan(queuedPayloadOffset, queuedPayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(payload))
            {
                sawQueuedStreamFrame = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrame);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    private static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            if (payload[0] != 0x00)
            {
                return payload;
            }

            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            payload = payload[paddingBytesConsumed..];
        }

        return payload;
    }
}

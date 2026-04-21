namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0005">Implementations are advised to include as few streams as necessary in outgoing packets without losing transmission efficiency to underfilled packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0005")]
public sealed class REQ_QUIC_RFC9000_S13_0005
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_EmitsASingleStreamFrameWithPaddingOnlyInTheRemainder()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = [0xAB];
        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect sendEffect = GetSingleStreamSendEffect(runtime, outboundEffects);

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> packetPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.False(streamFrame.HasOffset);
        Assert.True(streamFrame.HasLength);
        Assert.Equal((ulong)payload.Length, streamFrame.Length);
        Assert.False(streamFrame.IsFin);
        Assert.Equal(0UL, streamFrame.Offset);
        Assert.Equal(payload.Length, streamFrame.StreamDataLength);
        Assert.True(streamFrame.StreamData.SequenceEqual(payload));

        ReadOnlySpan<byte> remainder = packetPayload[streamFrame.ConsumedLength..];
        while (!remainder.IsEmpty)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(remainder, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            remainder = remainder[paddingBytesConsumed..];
        }

        await stream.DisposeAsync();
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

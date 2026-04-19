namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0008">When there is no data to send, the sender SHOULD send a PING or other ack-eliciting frame in a single packet, rearming the PTO timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0008")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatPingFrame_ProvidesTheFallbackProbeWhenNoDataIsAvailable()
    {
        Span<byte> destination = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPingFrame(destination, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(0x01));

        Assert.True(QuicFrameCodec.TryParsePingFrame(destination, out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_ArmsRecoveryPtoAndFallsBackToAPingProbeWhenItExpires()
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
        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = Enumerable.Range(0, 21).Select(value => (byte)value).ToArray();
        await stream.WriteAsync(payload, 0, payload.Length);

        long? recoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery);
        Assert.NotNull(recoveryDueTicks);
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);
        outboundEffects.Clear();

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: recoveryDueTicks.Value,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: recoveryDueTicks.Value);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.False(keyPhase);

        ReadOnlySpan<byte> packetPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload, out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);

        for (int index = pingBytesConsumed; index < packetPayload.Length; index++)
        {
            Assert.Equal(0x00, packetPayload[index]);
        }

        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
        Assert.True(runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery) > recoveryGeneration);
        Assert.Contains(timerResult.Effects, effect => effect is QuicConnectionArmTimerEffect arm && arm.TimerKind == QuicConnectionTimerKind.Recovery);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatPingFrame_RejectsInsufficientSpaceForTheFallbackProbe()
    {
        Assert.False(QuicFrameCodec.TryFormatPingFrame(stackalloc byte[0], out _));
    }
}

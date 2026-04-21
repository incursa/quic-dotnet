using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0056")]
public sealed class REQ_QUIC_CRT_0056
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IdleTimeoutExpiresAfterTheRuntimeArmsAndRestartsTheIdleTimer()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                ReadOnlyMemory<byte>.Empty),
            nowTicks: MicrosecondsToTicks(50));

        long idleDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        ulong idleGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.IdleTimeout);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: idleDueTicks,
                QuicConnectionTimerKind.IdleTimeout,
                idleGeneration),
            nowTicks: idleDueTicks);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.IdleTimeout, runtime.TerminalState?.Origin);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void OnlyAllowedLifecycleEventsRearmTheIdleTimer()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = CreateRuntime(clock);

        long initialDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;

        runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 0),
            nowTicks: MicrosecondsToTicks(25));

        Assert.Equal(initialDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout));

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                ReadOnlyMemory<byte>.Empty),
            nowTicks: MicrosecondsToTicks(50));

        long restartedDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        Assert.True(restartedDueTicks > initialDueTicks);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task FirstAckElicitingLocalSendAfterPeerActivityRearmsTheIdleTimer()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(clock: clock);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity activePathIdentity = runtime.ActivePath.Value.Identity;
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        long idleDueTicksBeforeSend = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        outboundEffects.Clear();
        clock.Advance(MicrosecondsToTicks(50));

        _ = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        long idleDueTicksAfterSend = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        Assert.True(idleDueTicksAfterSend > idleDueTicksBeforeSend);
        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.IdleTimeout
            && arm.Priority.DueTicks == idleDueTicksAfterSend);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RecoveryBackoffKeepsTheIdleTimeoutAtLeastThreeTimesTheCurrentPto()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(clock: clock);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = Enumerable.Range(0, 24)
            .Select(index => unchecked((byte)(0x30 + index)))
            .ToArray();
        await stream.WriteAsync(payload, 0, payload.Length);
        outboundEffects.Clear();
        await stream.CompleteWritesAsync().AsTask();
        _ = GetSingleStreamSendEffect(runtime, outboundEffects);
        outboundEffects.Clear();

        byte[] peerPingPacket = BuildProtectedPeerPingPacket(runtime);
        QuicConnectionTransitionResult peerPacketResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 100,
                runtime.ActivePath!.Value.Identity,
                peerPingPacket),
            nowTicks: 100);
        Assert.True(peerPacketResult.StateChanged);

        long initialRecoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery)!.Value;
        ulong recoveryGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.Recovery);

        QuicConnectionTransitionResult recoveryResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: initialRecoveryDueTicks,
                QuicConnectionTimerKind.Recovery,
                recoveryGeneration),
            nowTicks: initialRecoveryDueTicks);

        Assert.True(recoveryResult.StateChanged);
        long nextRecoveryDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery)!.Value;
        long nextIdleDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.IdleTimeout)!.Value;
        long currentPtoTicks = nextRecoveryDueTicks - initialRecoveryDueTicks;
        long idleRemainingTicks = nextIdleDueTicks - initialRecoveryDueTicks;

        Assert.True(currentPtoTicks > 0);
        Assert.True(
            idleRemainingTicks >= checked(currentPtoTicks * 3),
            $"idleRemainingTicks={idleRemainingTicks} currentPtoTicks={currentPtoTicks} nextIdleDueTicks={nextIdleDueTicks} nextRecoveryDueTicks={nextRecoveryDueTicks}");
    }

    private static byte[] BuildProtectedPeerPingPacket(QuicConnectionRuntime runtime)
    {
        Span<byte> pingPayload = stackalloc byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(pingPayload, out int pingBytesWritten));

        QuicHandshakeFlowCoordinator coordinator = new(new byte[] { 0x0A, 0x0B, 0x0C });
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            pingPayload[..pingBytesWritten],
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));

        return protectedPacket;
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

    private static QuicConnectionRuntime CreateRuntime(FakeMonotonicClock clock)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            currentProbeTimeoutMicros: 200);

        runtime.Transition(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: 0,
                TransportFlags: QuicConnectionTransportState.PeerTransportParametersCommitted,
                LocalMaxIdleTimeoutMicros: 300,
                PeerMaxIdleTimeoutMicros: 400,
                CurrentProbeTimeoutMicros: 200),
            nowTicks: 0);

        return runtime;
    }

    private static long MicrosecondsToTicks(ulong micros)
    {
        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + 999_999UL;

        ulong ticks = roundedUp / 1_000_000UL;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }
}

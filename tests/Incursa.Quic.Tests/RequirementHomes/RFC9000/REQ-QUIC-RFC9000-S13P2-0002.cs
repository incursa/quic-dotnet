namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2-0002">Only ack-eliciting packets MUST cause an ACK frame to be sent within the maximum ack delay.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckElicitingApplicationDataPacketSchedulesAckAtAdvertisedMaxAckDelay()
    {
        using QuicConnectionRuntime runtime =
            QuicS13AckPiggybackTestSupport.CreateAckDelayRuntimeWithValidatedActivePath(
                localMaxAckDelayMicros: 12_000);

        QuicConnectionTransitionResult receiveResult = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1);

        Assert.Empty(receiveResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        long expectedDueTicks = 10 + StopwatchTicksFromMicros(12_000);
        Assert.Equal(expectedDueTicks, runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                expectedDueTicks,
                QuicConnectionTimerKind.AckDelay,
                runtime.TimerState.GetGeneration(QuicConnectionTimerKind.AckDelay)),
            nowTicks: expectedDueTicks);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        Assert.True(QuicFrameCodec.TryParseAckFrame(
            payloadBytes,
            out QuicAckFrame ackFrame,
            out int ackBytesConsumed));
        Assert.Equal(1UL, ackFrame.LargestAcknowledged);
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(payloadBytes.AsSpan(ackBytesConsumed)).IsEmpty);

        QuicConnectionSentPacket sentPacket = Assert.Single(runtime.SendRuntime.SentPackets.Values);
        Assert.True(sentPacket.AckOnlyPacket);
        Assert.False(sentPacket.AckEliciting);
        Assert.False(sentPacket.Retransmittable);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    private static long StopwatchTicksFromMicros(ulong micros)
    {
        const ulong MicrosecondsPerSecond = 1_000_000UL;

        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)System.Diagnostics.Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;
        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + (MicrosecondsPerSecond - 1);
        ulong ticks = roundedUp / MicrosecondsPerSecond;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }
}

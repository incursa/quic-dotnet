namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0012">In that case, an endpoint MUST NOT send an ack-eliciting frame in all packets that would otherwise be non-ack-eliciting.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0012")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedPingArmsAckDelayTimerWithoutImmediateAckOnlyPacket()
    {
        using QuicConnectionRuntime runtime = CreateAckDelayRuntime();

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

        Assert.Empty(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(
            10 + (25 * TimeSpan.TicksPerMillisecond),
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
        Assert.Contains(result.Effects, effect => effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.AckDelay);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReceivedPingArmsAckDelayTimerAtAdvertisedMaxAckDelay()
    {
        using QuicConnectionRuntime runtime = CreateAckDelayRuntime(localMaxAckDelayMicros: 12_000);

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

        Assert.Empty(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(
            10 + (12 * TimeSpan.TicksPerMillisecond),
            runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AckDelayTimerExpirySendsAckOnlyPacketWithoutInjectedAckElicitingFrame()
    {
        using QuicConnectionRuntime runtime = CreateAckDelayRuntime();

        _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

        QuicConnectionTransitionResult result = ExpireAckDelayTimer(runtime);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(1UL, ackFrame.LargestAcknowledged);
        Assert.False(QuicFrameCodec.TryParsePingFrame(payload[ackBytesConsumed..], out _));

        ReadOnlySpan<byte> tail = QuicS13AckPiggybackTestSupport.SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(tail.IsEmpty);

        QuicConnectionSentPacket sentPacket = Assert.Single(runtime.SendRuntime.SentPackets.Values);
        Assert.True(sentPacket.AckOnlyPacket);
        Assert.False(sentPacket.AckEliciting);
        Assert.False(sentPacket.Retransmittable);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonAckElicitingApplicationDataPacketDoesNotArmAckDelayTimer()
    {
        using QuicConnectionRuntime runtime = CreateAckDelayRuntime();

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10);

        Assert.Empty(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SecondAckElicitingPacketBeforeAckDelayExpiresSendsOneAckOnlyPacketAndCancelsTimer()
    {
        using QuicConnectionRuntime runtime = CreateAckDelayRuntime();

        _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay).HasValue);

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 20,
            packetNumber: 2);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);

        Assert.True(QuicFrameCodec.TryParseAckFrame(payloadBytes, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(2UL, ackFrame.LargestAcknowledged);
        Assert.False(QuicFrameCodec.TryParsePingFrame(payloadBytes[ackBytesConsumed..], out _));
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckDelayTimerEmitsAckOnlyPacketAfterDeadline()
    {
        for (int sample = 0; sample < 8; sample++)
        {
            using QuicConnectionRuntime runtime = CreateAckDelayRuntime();

            long observedAtTicks = 10 + sample;
            _ = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
                runtime,
                observedAtTicks,
                packetNumber: (ulong)(sample + 1));

            long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay)!.Value;
            Assert.True(dueTicks > observedAtTicks);

            QuicConnectionTransitionResult result = ExpireAckDelayTimer(runtime);

            QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
                result.Effects.OfType<QuicConnectionSendDatagramEffect>());
            byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);

            Assert.True(QuicFrameCodec.TryParseAckFrame(payloadBytes, out QuicAckFrame ackFrame, out _));
            Assert.Equal((ulong)(sample + 1), ackFrame.LargestAcknowledged);
            Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task OpenOutboundStreamAsync_DoesNotPiggybackAckAfterTheSameAckTriggerWasAlreadySent()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicS13AckPiggybackTestSupport.RecordPendingApplicationAck(
            runtime,
            packetNumber: 3,
            receivedAtMicros: 9);
        Assert.True(runtime.SendRuntime.FlowController.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 9,
            out QuicAckFrame ackFrame));
        runtime.SendRuntime.FlowController.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackFrame,
            sentAtMicros: 9,
            ackOnlyPacket: false);

        _ = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);

        Assert.False(QuicFrameCodec.TryParseAckFrame(payloadBytes, out _, out _));
        Assert.True(QuicStreamParser.TryParseStreamFrame(payloadBytes, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PiggybackedAckSuppressesFeedbackLoopUntilANewerAckElicitingPacketArrives()
    {
        for (ulong packetNumber = 1; packetNumber < 96; packetNumber += 7)
        {
            QuicSenderFlowController sender = new();
            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: packetNumber);
            Assert.True(sender.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: packetNumber,
                out QuicAckFrame ackFrame));

            sender.MarkAckFrameSent(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber: 1000 + packetNumber,
                ackFrame,
                sentAtMicros: packetNumber,
                ackOnlyPacket: false);

            Assert.False(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: packetNumber + 1,
                maxAckDelayMicros: 0));
            Assert.False(sender.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: packetNumber + 1,
                maxAckDelayMicros: 0));

            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber + 1,
                ackEliciting: true,
                receivedAtMicros: packetNumber + 1);

            Assert.True(sender.CanSendAckOnlyPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: packetNumber + 1,
                maxAckDelayMicros: 0));
            Assert.True(sender.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: packetNumber + 1,
                maxAckDelayMicros: 0));
        }
    }

    private static QuicConnectionTransitionResult ExpireAckDelayTimer(QuicConnectionRuntime runtime)
    {
        long dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay)!.Value;
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.AckDelay);
        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks,
                QuicConnectionTimerKind.AckDelay,
                generation),
            nowTicks: dueTicks);
    }

    private static QuicConnectionRuntime CreateAckDelayRuntime(ulong? localMaxAckDelayMicros = null)
    {
        return QuicS13AckPiggybackTestSupport.CreateAckDelayRuntimeWithValidatedActivePath(localMaxAckDelayMicros);
    }
}

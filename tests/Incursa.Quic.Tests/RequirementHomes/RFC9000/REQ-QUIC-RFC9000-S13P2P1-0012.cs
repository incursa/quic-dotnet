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
    public void ReceivedPingTriggersAckOnlyPacketWithoutInjectedAckElicitingFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();

        QuicConnectionTransitionResult result = QuicS13AckPiggybackTestSupport.ReceiveOneRttPing(
            runtime,
            observedAtTicks: 10);

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
}

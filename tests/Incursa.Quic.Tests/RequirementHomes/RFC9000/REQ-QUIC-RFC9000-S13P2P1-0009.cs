namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0009">An endpoint that is only sending ACK frames will not receive acknowledgments from its peer unless those acknowledgments MUST be included in packets with ack-eliciting frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0009")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OpenOutboundStreamAsync_PiggybacksPendingAckOnAckElicitingPacket()
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
            packetNumber: 7,
            receivedAtMicros: 9);

        Assert.True(runtime.SendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 9,
            maxAckDelayMicros: 0));

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(7UL, ackFrame.LargestAcknowledged);

        ReadOnlySpan<byte> streamPayload = QuicS13AckPiggybackTestSupport.SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(streamPayload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);

        Assert.False(runtime.SendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 10,
            maxAckDelayMicros: 0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MarkAckFrameSent_DoesNotPermitDuplicateAckOnlyTriggerForTheSameAckElicitingPacket()
    {
        QuicSenderFlowController sender = new();
        sender.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 11,
            ackEliciting: true,
            receivedAtMicros: 1_000);

        Assert.True(sender.TryBuildAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_000,
            out QuicAckFrame ackFrame));

        sender.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            ackFrame,
            sentAtMicros: 1_000,
            ackOnlyPacket: false);

        Assert.False(sender.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: 1_001,
            maxAckDelayMicros: 0));
    }
}

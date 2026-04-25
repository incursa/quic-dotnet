namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P1-0010">An endpoint SHOULD send an ACK frame with other frames when there are new ack-eliciting packets to acknowledge.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P1-0010")]
public sealed class REQ_QUIC_RFC9000_S13P2P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_IncludesPendingAckFrameWithOutboundStreamFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        QuicS13AckPiggybackTestSupport.RecordPendingApplicationAck(
            runtime,
            packetNumber: 9,
            receivedAtMicros: 10);

        byte[] streamData = Enumerable.Range(0, 40).Select(value => (byte)value).ToArray();
        await stream.WriteAsync(streamData, 0, streamData.Length);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(9UL, ackFrame.LargestAcknowledged);

        ReadOnlySpan<byte> streamPayload = QuicS13AckPiggybackTestSupport.SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(streamPayload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.True(streamFrame.StreamData.SequenceEqual(streamData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task WriteAsync_DoesNotInventAckFrameWhenThereIsNoPendingAck()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] streamData = Enumerable.Range(0, 40).Select(value => (byte)(value + 1)).ToArray();
        await stream.WriteAsync(streamData, 0, streamData.Length);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payloadBytes = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> payload = payloadBytes;

        Assert.False(QuicFrameCodec.TryParseAckFrame(payload, out _, out _));
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame streamFrame));
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.True(streamFrame.StreamData.SequenceEqual(streamData));
    }
}

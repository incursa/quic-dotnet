namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0008">Application data sent in STREAM frames MUST be retransmitted in new STREAM frames unless the endpoint has sent a RESET_STREAM for that stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0008")]
public sealed class REQ_QUIC_RFC9000_S13P3_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LostStreamDataIsRebuiltInANewStreamFrameBeforeReset()
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
        payload.AsSpan().Fill(0x58);

        await stream.WriteAsync(payload, 0, payload.Length);

        QuicConnectionSendDatagramEffect originalSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, originalSend.Datagram);

        byte[] originalPlaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, originalSend);
        QuicStreamFrame originalStreamFrame = AssertSingleStreamFrame(originalPlaintext);
        Assert.Equal((ulong)stream.Id, originalStreamFrame.StreamId.Value);
        Assert.Equal(0UL, originalStreamFrame.Offset);
        Assert.True(originalStreamFrame.StreamData.SequenceEqual(payload));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            originalPacket.Key.PacketNumberSpace,
            originalPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        List<QuicConnectionEffect>? retransmissionEffects = [];
        Assert.True(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            nowTicks: 20,
            probePacket: false,
            ref retransmissionEffects));

        QuicConnectionSendDatagramEffect retransmissionSend = Assert.Single(
            retransmissionEffects!.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> retransmittedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, retransmissionSend.Datagram);

        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.NotEqual(originalPacket.Key.PacketNumber, retransmittedPacket.Key.PacketNumber);
        Assert.False(retransmissionSend.Datagram.Span.SequenceEqual(originalSend.Datagram.Span));

        byte[] retransmittedPlaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, retransmissionSend);
        QuicStreamFrame retransmittedStreamFrame = AssertSingleStreamFrame(retransmittedPlaintext);
        Assert.Equal(originalStreamFrame.StreamId.Value, retransmittedStreamFrame.StreamId.Value);
        Assert.Equal(originalStreamFrame.Offset, retransmittedStreamFrame.Offset);
        Assert.True(retransmittedStreamFrame.StreamData.SequenceEqual(payload));
    }

    private static QuicStreamFrame AssertSingleStreamFrame(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame));
        remaining = QuicS13AckPiggybackTestSupport.SkipPadding(remaining[streamFrame.ConsumedLength..]);
        Assert.True(remaining.IsEmpty);
        return streamFrame;
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

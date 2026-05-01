namespace Incursa.Quic.Tests;

internal readonly record struct QuicS13StreamDataSend(
    QuicConnectionRuntime Runtime,
    QuicConnectionSendDatagramEffect SendEffect,
    QuicConnectionSentPacketKey PacketKey,
    QuicConnectionSentPacket Packet,
    QuicS13StreamFrameSnapshot StreamFrame,
    byte[] Payload);

internal readonly record struct QuicS13StreamDataRetransmission(
    QuicConnectionSendDatagramEffect SendEffect,
    QuicConnectionSentPacketKey PacketKey,
    QuicConnectionSentPacket Packet,
    QuicS13StreamFrameSnapshot StreamFrame,
    byte[] PlaintextPayload);

internal readonly record struct QuicS13StreamFrameSnapshot(
    ulong StreamId,
    ulong Offset,
    int StreamDataLength,
    byte[] StreamData);

internal static class QuicS13RetransmissionTestSupport
{
    internal static async Task<QuicS13StreamDataSend> SendSingleStreamDataPacketAsync()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
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

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);

        byte[] plaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        QuicStreamFrame streamFrame = AssertSingleStreamFrame(plaintext);
        Assert.Equal((ulong)stream.Id, streamFrame.StreamId.Value);
        Assert.Equal(0UL, streamFrame.Offset);
        Assert.True(streamFrame.StreamData.SequenceEqual(payload));

        return new QuicS13StreamDataSend(
            runtime,
            sendEffect,
            sentPacket.Key,
            sentPacket.Value,
            Snapshot(streamFrame),
            payload);
    }

    internal static QuicS13StreamDataRetransmission FlushSingleApplicationRetransmission(
        QuicConnectionRuntime runtime)
    {
        List<QuicConnectionEffect>? retransmissionEffects = [];
        Assert.True(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            nowTicks: 20,
            probePacket: false,
            ref retransmissionEffects));

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            retransmissionEffects!.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);

        byte[] plaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        QuicStreamFrame streamFrame = AssertSingleStreamFrame(plaintext);

        return new QuicS13StreamDataRetransmission(
            sendEffect,
            sentPacket.Key,
            sentPacket.Value,
            Snapshot(streamFrame),
            plaintext);
    }

    internal static QuicStreamFrame AssertSingleStreamFrame(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame));
        remaining = QuicS13AckPiggybackTestSupport.SkipPadding(remaining[streamFrame.ConsumedLength..]);
        Assert.True(remaining.IsEmpty);
        return streamFrame;
    }

    private static QuicS13StreamFrameSnapshot Snapshot(QuicStreamFrame streamFrame)
    {
        return new QuicS13StreamFrameSnapshot(
            streamFrame.StreamId.Value,
            streamFrame.Offset,
            streamFrame.StreamDataLength,
            streamFrame.StreamData.ToArray());
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

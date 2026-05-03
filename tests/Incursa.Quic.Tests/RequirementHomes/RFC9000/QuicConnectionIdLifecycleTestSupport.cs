namespace Incursa.Quic.Tests;

internal static class QuicConnectionIdLifecycleTestSupport
{
    internal static QuicConnectionTransitionResult ProcessNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        long observedAtTicks,
        byte statelessResetTokenStart = 0x60)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            CreateStatelessResetToken(statelessResetTokenStart)));

        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            payload,
            observedAtTicks);
    }

    internal static ulong[] GetRetiredSequenceNumbers(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;
        List<ulong> retiredSequenceNumbers = [];

        foreach (QuicConnectionSendDatagramEffect effect in result.Effects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                    effect.Datagram.Span,
                    material,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out _))
            {
                continue;
            }

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            int frameOffset = 0;
            while (frameOffset < payload.Length)
            {
                ReadOnlySpan<byte> remaining = payload[frameOffset..];
                if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed)
                    && paddingBytesConsumed > 0)
                {
                    frameOffset += paddingBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed)
                    && ackBytesConsumed > 0)
                {
                    frameOffset += ackBytesConsumed;
                    continue;
                }

                if (QuicFrameCodec.TryParseRetireConnectionIdFrame(
                        remaining,
                        out QuicRetireConnectionIdFrame frame,
                        out int retireBytesConsumed)
                    && retireBytesConsumed > 0)
                {
                    retiredSequenceNumbers.Add(frame.SequenceNumber);
                    frameOffset += retireBytesConsumed;
                    continue;
                }

                break;
            }
        }

        return retiredSequenceNumbers.ToArray();
    }

    internal static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}

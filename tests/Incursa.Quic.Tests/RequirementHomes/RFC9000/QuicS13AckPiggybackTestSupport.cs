namespace Incursa.Quic.Tests;

internal static class QuicS13AckPiggybackTestSupport
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    internal static void RecordPendingApplicationAck(
        QuicConnectionRuntime runtime,
        ulong packetNumber,
        ulong receivedAtMicros)
    {
        runtime.SendRuntime.FlowController.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros);
    }

    internal static byte[] OpenOutgoingApplicationPayload(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    internal static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            if (payload[0] != 0x00)
            {
                return payload;
            }

            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            payload = payload[paddingBytesConsumed..];
        }

        return payload;
    }

    internal static QuicConnectionTransitionResult ReceiveOneRttPing(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out _));
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket));

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}

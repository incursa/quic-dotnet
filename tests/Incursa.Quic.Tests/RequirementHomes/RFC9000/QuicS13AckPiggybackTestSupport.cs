using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicS13AckPiggybackTestSupport
{
    internal static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));
        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0).StateChanged);

        return runtime;
    }

    internal static QuicConnectionRuntime CreateAckDelayRuntimeWithValidatedActivePath(
        ulong? localMaxAckDelayMicros = null)
    {
        QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
                localMaxAckDelayMicros: localMaxAckDelayMicros);
        runtime.SendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData);
        long? existingAckDelayDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay);
        if (existingAckDelayDueTicks.HasValue)
        {
            _ = runtime.Transition(
                new QuicConnectionTimerExpiredEvent(
                    existingAckDelayDueTicks.Value,
                    QuicConnectionTimerKind.AckDelay,
                    runtime.TimerState.GetGeneration(QuicConnectionTimerKind.AckDelay)),
                nowTicks: existingAckDelayDueTicks.Value);
        }

        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.AckDelay));
        return runtime;
    }

    internal static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

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

    internal static void RecordPendingAck(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong receivedAtMicros)
    {
        runtime.SendRuntime.FlowController.RecordIncomingPacket(
            packetNumberSpace,
            packetNumber,
            ackEliciting: true,
            receivedAtMicros);
    }

    internal static byte[] CreateAckFramePayload(ulong largestAcknowledged)
    {
        byte[] payload = new byte[32];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(
            new QuicAckFrame
            {
                FrameType = 0x02,
                LargestAcknowledged = largestAcknowledged,
                AckDelay = 0,
                FirstAckRange = 0,
            },
            payload,
            out int bytesWritten));

        return payload.AsSpan(0, bytesWritten).ToArray();
    }

    internal static byte[] OpenOutgoingApplicationPayload(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect)
    {
        Assert.False(runtime.CurrentPeerDestinationConnectionId.IsEmpty);
        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
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

    internal static KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> FindTrackedPacket(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        return Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(datagram.Span));
    }

    internal static bool InvokeTryFlushPendingRetransmissions(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TryFlushPendingRetransmissions",
            BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(
                nameof(QuicConnectionRuntime),
                "TryFlushPendingRetransmissions");
        object?[] arguments =
        [
            packetNumberSpace,
            nowTicks,
            probePacket,
            effects,
        ];

        bool result = (bool)method.Invoke(runtime, arguments)!;
        effects = (List<QuicConnectionEffect>?)arguments[3];
        return result;
    }

    internal static ulong ReadLongHeaderPacketNumber(byte[] openedPacket, int payloadOffset)
    {
        return QuicS17P1TestSupport.ReadPacketNumber(openedPacket.AsSpan(
            payloadOffset - sizeof(uint),
            sizeof(uint)));
    }

    internal static void AssertPayloadStartsWithAckThenCrypto(
        ReadOnlySpan<byte> payload,
        ulong expectedLargestAcknowledged,
        ReadOnlySpan<byte> expectedCryptoPayload,
        ulong expectedCryptoOffset)
    {
        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(expectedLargestAcknowledged, ackFrame.LargestAcknowledged);

        ReadOnlySpan<byte> cryptoPayload = SkipPadding(payload[ackBytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            cryptoPayload,
            out QuicCryptoFrame cryptoFrame,
            out int cryptoBytesConsumed));
        Assert.Equal(expectedCryptoOffset, cryptoFrame.Offset);
        if (!expectedCryptoPayload.IsEmpty)
        {
            Assert.True(cryptoFrame.CryptoData.SequenceEqual(expectedCryptoPayload));
        }
        else
        {
            Assert.False(cryptoFrame.CryptoData.IsEmpty);
        }

        Assert.True(SkipPadding(cryptoPayload[cryptoBytesConsumed..]).IsEmpty);
    }

    internal static void AssertPayloadStartsWithCryptoWithoutAck(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> expectedCryptoPayload,
        ulong expectedCryptoOffset)
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(payload, out _, out _));
        ReadOnlySpan<byte> cryptoPayload = SkipPadding(payload);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            cryptoPayload,
            out QuicCryptoFrame cryptoFrame,
            out int cryptoBytesConsumed));
        Assert.Equal(expectedCryptoOffset, cryptoFrame.Offset);
        Assert.True(cryptoFrame.CryptoData.SequenceEqual(expectedCryptoPayload));
        Assert.True(SkipPadding(cryptoPayload[cryptoBytesConsumed..]).IsEmpty);
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
        long observedAtTicks,
        ulong packetNumber = 1)
    {
        byte[] protectedPacket = BuildProtectedOneRttPacket(
            runtime,
            QuicS12P3TestSupport.CreatePingPayload(),
            packetNumber);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static QuicConnectionTransitionResult ReceiveOneRttAckOnly(
        QuicConnectionRuntime runtime,
        long observedAtTicks,
        ulong packetNumber = 1)
    {
        byte[] protectedPacket = BuildProtectedOneRttPacket(
            runtime,
            CreateAckFramePayload(largestAcknowledged: 0),
            packetNumber);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static byte[] BuildProtectedOneRttPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        ulong packetNumber)
    {
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = new(runtime.CurrentPeerDestinationConnectionId);
        byte[] protectedPacket = [];
        for (ulong currentPacketNumber = 0; currentPacketNumber <= packetNumber; currentPacketNumber++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                payload,
                runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
                runtime.TlsState.CurrentOneRttKeyPhaseBit,
                out protectedPacket));
        }

        return protectedPacket;
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

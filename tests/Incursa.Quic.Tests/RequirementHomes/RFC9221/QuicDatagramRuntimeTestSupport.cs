namespace Incursa.Quic.Tests;

internal static class QuicDatagramRuntimeTestSupport
{
    internal static QuicConnectionRuntime CreateFinishedRuntime(
        ulong? localMaxDatagramFrameSize = null,
        ulong? peerMaxDatagramFrameSize = null,
        ulong connectionSendLimit = 64)
    {
        return QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: connectionSendLimit,
            localMaxDatagramFrameSize: localMaxDatagramFrameSize,
            peerMaxDatagramFrameSize: peerMaxDatagramFrameSize);
    }

    internal static async Task<QuicDatagramSendResult> SendDatagramAsync(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagramData)
    {
        List<QuicConnectionEffect> effects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            effects.AddRange(transition.Effects);
            return true;
        });

        await runtime.SendDatagramAsync(datagramData);

        QuicConnectionSendDatagramEffect? sendEffect = effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .SingleOrDefault();
        QuicConnectionSentPacket? trackedPacket = null;
        if (sendEffect is not null)
        {
            KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> tracked =
                QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);
            trackedPacket = tracked.Value;
        }

        return new QuicDatagramSendResult(effects.ToArray(), sendEffect, trackedPacket);
    }

    internal static QuicDatagramFrame ParseFirstOutgoingDatagramFrame(
        QuicConnectionRuntime runtime,
        QuicConnectionSendDatagramEffect sendEffect)
    {
        byte[] payload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        ReadOnlySpan<byte> remaining = SkipAckAndPadding(payload);

        Assert.True(QuicFrameCodec.TryParseDatagramFrame(
            remaining,
            out QuicDatagramFrame frame,
            out int bytesConsumed));
        Assert.True(bytesConsumed > 0);
        return frame;
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedDatagramFrame(
        QuicConnectionRuntime runtime,
        QuicDatagramFrame frame,
        long observedAtTicks = 20)
    {
        byte[] applicationPayload = QuicFrameTestData.BuildDatagramFrame(frame);
        byte[] protectedPacket = CreateProtectedApplicationPacket(runtime, applicationPayload);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> applicationPayload,
        long observedAtTicks = 20)
    {
        byte[] protectedPacket = CreateProtectedApplicationPacket(runtime, applicationPayload);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                observedAtTicks,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    private static byte[] CreateProtectedApplicationPacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> applicationPayload)
    {
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x01],
            applicationPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 4);
    }

    private static ReadOnlySpan<byte> SkipAckAndPadding(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> remaining = SkipPadding(payload);
        if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
        {
            remaining = SkipPadding(remaining[ackBytesConsumed..]);
        }

        return remaining;
    }

    private static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length && payload[offset] == 0)
        {
            offset++;
        }

        return payload[offset..];
    }
}

internal sealed record QuicDatagramSendResult(
    QuicConnectionEffect[] Effects,
    QuicConnectionSendDatagramEffect? SendEffect,
    QuicConnectionSentPacket? TrackedPacket);

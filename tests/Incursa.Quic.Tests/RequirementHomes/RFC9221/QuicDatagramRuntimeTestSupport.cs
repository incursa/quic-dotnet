// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicDatagramRuntimeTestSupport
{
    internal static QuicConnectionRuntime CreateFinishedRuntime(
        IMonotonicClock? clock = null,
        ulong? localMaxDatagramFrameSize = null,
        ulong? peerMaxDatagramFrameSize = null,
        ulong connectionSendLimit = 64,
        ulong localBidirectionalSendLimit = 32,
        int maximumInboundDatagramQueueSize = 1024)
    {
        return QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            clock: clock,
            connectionSendLimit: connectionSendLimit,
            localBidirectionalSendLimit: localBidirectionalSendLimit,
            localMaxDatagramFrameSize: localMaxDatagramFrameSize,
            peerMaxDatagramFrameSize: peerMaxDatagramFrameSize,
            maximumInboundDatagramQueueSize: maximumInboundDatagramQueueSize);
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
        int datagramFrameOffset = SkipAckAndPaddingLength(payload);
        ReadOnlyMemory<byte> remaining = payload.AsMemory(datagramFrameOffset);

        Assert.True(QuicFrameCodec.TryParseDatagramFrame(
            remaining,
            out QuicDatagramFrame frame,
            out int bytesConsumed));
        Assert.True(bytesConsumed > 0);
        return frame;
    }

    internal static ReadOnlySpan<byte> SkipAckAndPaddingFromPayload(ReadOnlySpan<byte> payload)
    {
        return SkipAckAndPadding(payload);
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
        return payload[SkipAckAndPaddingLength(payload)..];
    }

    private static int SkipAckAndPaddingLength(ReadOnlySpan<byte> payload)
    {
        int skippedLength = CountPadding(payload);
        ReadOnlySpan<byte> remaining = payload[skippedLength..];
        if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
        {
            skippedLength += ackBytesConsumed;
            skippedLength += CountPadding(payload[skippedLength..]);
        }

        return skippedLength;
    }

    private static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        return payload[CountPadding(payload)..];
    }

    private static int CountPadding(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length && payload[offset] == 0)
        {
            offset++;
        }

        return offset;
    }
}

internal sealed record QuicDatagramSendResult(
    QuicConnectionEffect[] Effects,
    QuicConnectionSendDatagramEffect? SendEffect,
    QuicConnectionSentPacket? TrackedPacket);

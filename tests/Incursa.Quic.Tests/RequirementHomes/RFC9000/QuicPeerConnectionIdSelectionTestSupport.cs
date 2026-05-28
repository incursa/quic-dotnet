// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicPeerConnectionIdSelectionTestSupport
{
    internal static async Task<QuicConnectionSendDatagramEffect> OpenOutboundStreamAndCaptureSingleSendAsync(
        QuicConnectionRuntime runtime)
    {
        QuicConnectionEffect[] outboundEffects = await OpenOutboundStreamAndCaptureEffectsAsync(runtime);
        return Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
    }

    internal static async Task<QuicConnectionEffect[]> OpenOutboundStreamAndCaptureEffectsAsync(
        QuicConnectionRuntime runtime)
    {
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.NotNull(stream);
        return outboundEffects.ToArray();
    }

    internal static void AssertApplicationDataDatagramOpensWithDestination(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        AssertApplicationDataDatagramUsesDestinationConnectionId(datagram, destinationConnectionId);
        Assert.True(TryOpenApplicationDataDatagram(
            runtime,
            datagram,
            destinationConnectionId,
            out _,
            out _,
            out _));
    }

    internal static void AssertApplicationDataDatagramUsesDestinationConnectionId(
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.True(ApplicationDataDatagramUsesDestinationConnectionId(datagram, destinationConnectionId));
    }

    internal static void AssertApplicationDataDatagramDoesNotUseDestinationConnectionId(
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.False(ApplicationDataDatagramUsesDestinationConnectionId(datagram, destinationConnectionId));
    }

    internal static void AssertApplicationDataDatagramDoesNotOpenWithDestination(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.False(TryOpenApplicationDataDatagram(
            runtime,
            datagram,
            destinationConnectionId,
            out _,
            out _,
            out _));
    }

    internal static bool ApplicationDataDatagramUsesDestinationConnectionId(
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        int destinationConnectionIdOffset = 1;
        return datagram.Length >= destinationConnectionIdOffset + destinationConnectionId.Length
            && datagram.Span.Slice(destinationConnectionIdOffset, destinationConnectionId.Length)
                .SequenceEqual(destinationConnectionId.Span);
    }

    private static bool TryOpenApplicationDataDatagram(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId);
        return coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out openedPacket,
            out payloadOffset,
            out payloadLength);
    }
}

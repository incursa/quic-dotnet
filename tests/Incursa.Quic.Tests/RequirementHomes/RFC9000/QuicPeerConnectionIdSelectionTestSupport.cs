namespace Incursa.Quic.Tests;

internal static class QuicPeerConnectionIdSelectionTestSupport
{
    internal static async Task<QuicConnectionSendDatagramEffect> OpenOutboundStreamAndCaptureSingleSendAsync(
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
        return Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
    }

    internal static void AssertApplicationDataDatagramOpensWithDestination(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram,
        ReadOnlyMemory<byte> destinationConnectionId)
    {
        Assert.True(TryOpenApplicationDataDatagram(
            runtime,
            datagram,
            destinationConnectionId,
            out _,
            out _,
            out _));
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

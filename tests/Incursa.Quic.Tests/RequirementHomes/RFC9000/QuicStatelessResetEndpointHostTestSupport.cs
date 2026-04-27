namespace Incursa.Quic.Tests;

internal static class QuicStatelessResetEndpointHostTestSupport
{
    internal static void ConfigureDiscardedRetainedRouteEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        ReadOnlySpan<byte> token,
        int enteredAtTicks)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
        Assert.True(endpoint.TryApplyEffect(handle, new QuicConnectionDiscardConnectionStateEffect(CreateAeadLimitTerminalState(enteredAtTicks))));
    }

    internal static byte[] CreateRetainedRouteShortHeaderDatagram(
        ReadOnlySpan<byte> routeConnectionId,
        int triggeringPacketLength)
    {
        Assert.True(triggeringPacketLength > 1 + routeConnectionId.Length);

        byte[] remainder = new byte[triggeringPacketLength - 1];
        routeConnectionId.CopyTo(remainder);
        for (int offset = routeConnectionId.Length; offset < remainder.Length; offset++)
        {
            remainder[offset] = unchecked((byte)(0xA0 + offset));
        }

        return QuicHeaderTestData.BuildShortHeader(0x00, remainder);
    }

    internal static byte[] CreateRetainedRouteLongHeaderDatagram(ReadOnlySpan<byte> routeConnectionId)
    {
        byte[] protectedPayload = new byte[24];
        for (int offset = 0; offset < protectedPayload.Length; offset++)
        {
            protectedPayload[offset] = unchecked((byte)(0x90 + offset));
        }

        return QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: routeConnectionId.ToArray(),
            sourceConnectionId: [0x61, 0x62],
            protectedPayload: protectedPayload);
    }

    private static QuicConnectionTerminalState CreateAeadLimitTerminalState(int enteredAtTicks)
    {
        return new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            QuicConnectionCloseOrigin.Local,
            new QuicConnectionCloseMetadata(
                QuicTransportErrorCode.AeadLimitReached,
                ApplicationErrorCode: null,
                TriggeringFrameType: null,
                ReasonPhrase: "The connection reached the AEAD limit."),
            enteredAtTicks);
    }
}

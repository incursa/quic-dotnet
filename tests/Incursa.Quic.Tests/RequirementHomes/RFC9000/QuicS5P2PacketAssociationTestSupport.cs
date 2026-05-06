namespace Incursa.Quic.Tests;

internal static class QuicS5P2PacketAssociationTestSupport
{
    internal static readonly byte[] RouteConnectionId = [0x30, 0x31];

    internal static (
        QuicConnectionRuntime Runtime,
        QuicConnectionRuntimeEndpoint Endpoint,
        QuicConnectionHandle Handle) CreateRegisteredEndpoint(
            ReadOnlySpan<byte> connectionId,
            QuicConnectionPathIdentity? pathIdentity = null)
    {
        QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();
        QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        if (pathIdentity.HasValue)
        {
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity.Value));
        }

        Assert.True(endpoint.TryRegisterConnectionId(handle, connectionId));
        return (runtime, endpoint, handle);
    }

    internal static byte[] BuildHandshakeDatagram(ReadOnlySpan<byte> destinationConnectionId)
    {
        return QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram(destinationConnectionId);
    }

    internal static byte[] BuildShortHeaderDatagram(ReadOnlySpan<byte> destinationConnectionId)
    {
        return QuicHeaderTestData.BuildShortHeader(0x00, destinationConnectionId);
    }

    internal static byte[] BuildMaximumLengthConnectionId()
    {
        byte[] connectionId = new byte[QuicConnectionIdKey.MaximumLength];
        for (int i = 0; i < connectionId.Length; i++)
        {
            connectionId[i] = unchecked((byte)(0xA0 + i));
        }

        return connectionId;
    }
}

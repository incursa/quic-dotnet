namespace Incursa.Quic.Tests;

internal static class QuicS14P2P1TestSupport
{
    internal static byte[] BuildQuotedInitialPacket(
        QuicConnectionRuntime runtime,
        byte[]? destinationConnectionId = null,
        byte[]? sourceConnectionId = null)
    {
        byte[] effectiveDestinationConnectionId = destinationConnectionId ?? runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] effectiveSourceConnectionId = sourceConnectionId ?? runtime.CurrentHandshakeSourceConnectionId.ToArray();

        return QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: effectiveDestinationConnectionId,
            sourceConnectionId: effectiveSourceConnectionId,
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: [0x02]));
    }
}

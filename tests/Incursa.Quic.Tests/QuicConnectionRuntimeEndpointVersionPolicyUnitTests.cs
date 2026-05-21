namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimeEndpointVersionPolicyUnitTests
{
    [Fact]
    public void ReceiveDatagram_RejectsVersion1InitialPacketsBelowTheMinimumPayloadSize()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], []));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(packet, new QuicConnectionPathIdentity("127.0.0.1"));

        Assert.Equal(QuicConnectionIngressDisposition.Malformed, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    public void ReceiveDatagram_DoesNotApplyTheVersion1InitialFloorToNonVersion1LongHeaders()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 0x11223344,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x01]);

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(packet, new QuicConnectionPathIdentity("127.0.0.1"));

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P2-0009")]
public sealed class REQ_QUIC_RFC9000_S5P2P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_DropsPrematureClientHandshakePackets()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram();

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
    }
}

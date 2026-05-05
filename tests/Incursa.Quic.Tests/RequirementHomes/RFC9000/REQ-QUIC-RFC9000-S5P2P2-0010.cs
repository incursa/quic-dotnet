namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P2-0010")]
public sealed class REQ_QUIC_RFC9000_S5P2P2_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClassifyUnroutedDatagram_DropsShortHeaderPacketsThatDoNotMatchAConnection()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram([0x90, 0x91]);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
    }
}

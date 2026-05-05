namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S5P2P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_AllowsSuppressingRepeatedResponses()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
            hasAlreadySentVersionNegotiation: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClassifyUnroutedDatagram_DropsLargeUnsupportedPacketsAfterTheLimitIsReached()
    {
        byte[] datagram = QuicS5P2P2ServerPreAcceptanceTestSupport.BuildUnsupportedVersionDatagram(
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        QuicListenerPreAcceptanceDatagramAction action =
            QuicListenerPreAcceptanceIngressPolicy.ClassifyUnroutedDatagram(
                datagram,
                QuicS5P2P2ServerPreAcceptanceTestSupport.SupportedVersions,
                retryBootstrapEnabled: false,
                hasAlreadySentVersionNegotiation: true);

        Assert.Equal(QuicListenerPreAcceptanceDatagramAction.Drop, action);
    }
}

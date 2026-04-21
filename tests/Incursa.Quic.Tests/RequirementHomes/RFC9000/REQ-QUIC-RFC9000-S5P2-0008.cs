namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0008")]
public sealed class REQ_QUIC_RFC9000_S5P2_0008
{
    private static readonly byte[] CapturedQuicGoMulticonnectServerHandshakeRetransmission = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-multiconnect-post-secondprobe\20260421-095240783-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-262f5a0c379c4af090592bdcaccd1988.qlog
        // Event time=8 quic:packet_received raw payload, corresponding to the quic-go server's 747-byte
        // Handshake retransmission that arrived during the failing multiconnect attempt.
        "E5000000010876D623AA2D90132A04E32BA73B42D6FC46386A4BEC3BE7179BE5861734E8DBDCD89433981ED4FA3232CB2B91EEC3220C329618CA1D73EE3E337B26D27683D27E61E5C8341392225B41B8C2A22D5F85C2F09CCE84B6F386C75C4DFC3824AE15CD45E2073339C65921A3088A79A04FD61FA1DBCC51A9931947110D65D92C0F57818A4E3772F5DA24250EFC317D5D1CA6FF1666BFC036273B04637F597207A5AD82D44843EFD6BEEA0278D1CDD8C46B5FDB9430A59C9B43AEDF383A873C4114FE555808EBB9D70A2385FA4C978BA24E8D8985EA4B0100B0D7E6537EBC8E5223BEBF24765088EE6700EDCA832C44E03D7C34CAF8E79E0446CF4B21641EE360AD3654F7D55787614105EE0DE8928301B1E668837DB3EADD983CF3041E6CC4F04C0065DE3DAF7CD3650A5AD3603EB76A47E27E52F98113B9A2FB3F9713932045D02AADD31A18208C0E725BC4415A795E9CEFBE0AE554CC5C071E36A33056B4D41D1CD582FDF92B8DD792D3EC1D27D2CF994EBDD6F9A815108ACA1D69FF3FA31C56655AD112557EB438FD1DF5231E65AFFF58C5D26F6A24062F439C9DB24961F0D2DC94C827C26E281E671701482086BAF0E848247539E57D8769169A546BC5ACFA4F08F602CFA6D8CE0F400EB6DED839A94280FA3A120BDFC094FA5EBD3475CA9F7F97B0AE9D6C66558A345AEB066907592BC281556378089EEBDAE0F9E9AF2F31FC0F64F424E8D8B03F63F01ADE28AE6DC1242863543F43FAA428DBAB26DB42BD3D81E597E9AA8C345AD5503F676B4FEE07A7A5BBC0D444678B9287A3EDBEB4F4E47886F128DE8185A60DB6D41C56456D4EB866D7945DBE86BFB870AC6BC2F9243CC1D718512DFF2FF72150B8CC1B805E2687ED8941F2CCC42E000B8A8C754A2EB512F625DC26108207C3AC13017B1C562281B0D43EA905BC1E116F8D3B8EF83C381F6903E14947E1EC4AF18BC3D496EF5BE03E5AB5D51280E34F1C886A329B2104356119CED35B9798BC0BB6501AC0B3216F461CD3A100441B7E3B25BB92823923CA89FBC53476");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_MapsSupportedPacketFormsToTheExpectedSpaces()
    {
        byte[] shortHeaderPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
            0x40,
            1,
            [0x10],
            [0x20],
            QuicHeaderTestData.BuildInitialVersionSpecificData([0x01], [0x02], [0xAA]));
        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket();

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(shortHeaderPacket, out QuicPacketNumberSpace shortHeaderSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, shortHeaderSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_ClassifiesTheCapturedQuicGoMulticonnectHandshakeRetransmissionAsHandshake()
    {
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            CapturedQuicGoMulticonnectServerHandshakeRetransmission,
            out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsVersionNegotiationAndRetryPackets()
    {
        byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x4A,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            supportedVersions: [1, 2]);

        byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x70,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x30]);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace([], out _));
    }
}

using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

internal static class QuicCapturedInteropReplayTestSupport
{
    // Captured from:
    // C:\src\incursa\quic-dotnet.local\interop-evidence\debug-deterministic-refresh\20260420-133311751-client-chrome\
    //   runner-logs\quic-go_chrome\handshake\client\qlog\client-handshake-fb34586af28d4221b2a7747f5e5ccda8.qlog
    //
    // Capture setup:
    // - local managed endpoint ran in the client role against quic-go
    // - test case: handshake
    // - deterministic local P-256 handshake scalar injected via:
    //   CLIENT_PARAMS=local_handshake_private_key_hex=0000000000000000000000000000000000000000000000000000000000000011
    //
    // Event mapping:
    // - time=0  quic:packet_sent     => CapturedClientInitialDatagram
    // - time=1  quic:packet_received => CapturedServerInitialPacket
    // - time=4  quic:packet_received => CapturedServerHandshakePacket

    internal static CapturedInteropHandshakeScenario CreateDeterministicQuicGoClientHandshakeScenario()
    {
        byte[] initialDestinationConnectionId = DecodeHex("AB5029C31A04246D");
        byte[] clientSourceConnectionId = DecodeHex("EFC9F7EB01F51BE5");
        byte[] localHandshakePrivateKey = DecodeHex("0000000000000000000000000000000000000000000000000000000000000011");
        byte[] capturedClientInitialDatagram = DecodeHex(
            """
            CB0000000108AB5029C31A04246D08EFC9F7EB01F51BE5004496107E75326BE6
            683C03CDD5F65098645407688A26B0153489B7681FE9616F6B96709F8218A8CC
            81D1453C59E7A72F364B14FCCEFF1D48B0913326324302DF33AC6780501E639B
            DEB2B9651979AFC4DE51A0097D6D6776ED923AA92268F1331AE34A2C89FD0717
            36902E2A84BC025818D3B9EA27F3632B13DF81D18F8511778F1F4078991DE056
            43198BDBE7E77F73ECF6B0AD416529705F9D640476CA2EA7D7203972364D1D93
            123A22467F07026C5FE90D2F39CA10810F9A63891F398EAA051A9A8B403637D7
            15EC425807DAAC5FE857A3EF71CEA27D3A5EAE4A7BC796E843D664923E7C913E
            51A691BD0D8899A25DA237A309B6A4A18B07028E496EEA744723AA9DC212C37E
            A8E70C21E3F6196D2329C6DC51C7973FB5AB19ADB89501E9F94A61E34EC9FEB2
            DA174B9CC3B0A3E4FB7556B6707EA6D71358694EE1CDC401635C21741EA6ECBA
            7B7EFDEA0E505282BF107DBCFA4273174A4FD0E79D4DF0E20A63CFB01CE7AED9
            038D5C1C17C5DFB5F6CAFF589CCE14941D4438F76B2F56047DA0F4DEDD854D18
            25BEAF878EB960A1F9E8828FF385D3A66276386810DCC80A3DE84131195F0297
            6C191D3A3ED414ADB35DF0D3BDF3FDBC2D3FD5752A07A617E86BEBE043F9D3EF
            D19A48CDBCB356FBE303FBCA4BD16D634ED38504C1E2E55D7DC16A3D13A42437
            774675B255DEC3BE4BED17EAA5859D9D451186BAFB7D51CB387FDD7771654F89
            D0545EDCC07CC92B6C940BAAC2B729306DC097D30A078E6ED9840EE0670000CD
            A3754A07C11E7FA713569BF5C7108504A967047919B9A2323FA9FCC43FF4A908
            E6F2E7CD26650855633A6490821AF44F8E2C02716477A900F708B842A3BF3EB2
            99C6E6A4E977A78C07248C8B4D58E9C072AD28F74B04628AA5AA65AFCFF52153
            0131691ADC7F477A678650CB6CDE86056F49F1AEEFEF11F2A812D7E2EA2A21A9
            C0D023614E12A803F79625388FE1E0A2E0A4392A60E0A79797E4C243B8EC3A3D
            EF211F053E0408CB628F4C58BAFBB35D2796DA35D7034854B2E261DF186FB530
            AEDA44A0075BCFF0130362E33FFC9908384DB18B12D16F875C111833B1DB4D0F
            A3EBAAFED49663406DC66FD6BA540AFDA97F8EE850C937E04F843D164BDBF373
            E4BC84E89679135962C09380D9418DB9058A344E1CDF7561D1C0D2492CBDB91D
            97B25E8617C1DE24C8F10FE4B85656ACE94CF97253CFC92874DC398156C5B4ED
            06B68288F14D0118324A9C4EBE2BD4FED390730DD53FAF0A2643582683499F5D
            8187D1695C2E6705ECD9A89D99FF8A49CD463E1692657168DEC904E163DA6CFB
            50BBB224FFE34201F1D0C86773E3F336D653B24534A6BF87526A81EF8D92BBCA
            B4FB5BDA7E3F7144EDB527F17774D6A9D36F64B81C0D3224FAD7AAA23FDA4298
            AC3AE8F9B70C8F637373A81762FC0ABBB36817A10DC33E5D19E1AFCDADCACF6B
            A81E2FD673CED529C7E877EA0E5CD577D59D79EBDB3176FD346E1748524D0B2A
            C5214A42249E97BECFFBF115392CACAF1A58184B9564CACFBD9E17E37D17038B
            09BA77FBB0E3FA6832265CF0CC381E49F87044D5DB562EE659EE5F7920B89CA4
            F5805B4C0F42A92D0EC8C37BCFB7F22B7DF74DD6136D5DBE0FAC35627356952D
            47EB7F39437F75B74E5A3425347C40F6
            """);
        byte[] capturedServerInitialPacket = DecodeHex(
            """
            C30000000108EFC9F7EB01F51BE504A6689B840041CA0844B634D9C8458379E0
            AE7A697BF552DCBEBEF9BFC1890C142CA18112FE82D276868208943B3B3F8FCE
            0D746E620AC76A25D99F39547082795B2F3F2E78F5EF2A9E648069FFB90D889D
            AFDCC9CAB6A1DAF7451E92A14776A6AEA68D385C4ABE68AEE7080F2E56141E58
            8A95321FD7B9B2120E379836143EB4F3D2FFF81EC9BB0D888D1298E896A17E00
            A067CB6BDDD3F6633191DB505ECB26AC2648EA610D9120F7196809F6CB827A9C
            383CA7D5BCA0F2D272F0B9B64063C844C81BC26F045C10D7BD4B2B4548C00835
            B991F81BB380409E0CC85BB1FF7B14A09C92874C805D26F11F378157336BCDBA
            90824957FEBEFFB3FA2758D330B6366591E904A21153827FC8475AB06D417C04
            B9E4F14D4724D454C0CB3D5B9939A639A983376B9BE1E4D68E9A61B329F0C99E
            DD71448400D7B8C85AA771BD71641E4A2445482BA427EF9DF9EE53E67F8C01D7
            2C51FCDB4844F0A47F210FDF1ED2310909091ED95DC770A57F5194C4175C971C
            C3B814394CEBDCC5A0400BDFFA70429949A5EBEF363D826536DB48302A0E07F8
            DF290563056A58805991E0243FDFC88C19B57E7B470D7473E607E96F2D7AA9CB
            6458E8BAD65F1757065DFFD9380807B4E69B3E64146F8A0B558577E7FFD8DF8B
            """);
        byte[] capturedServerHandshakePacket = DecodeHex(
            """
            ED0000000108EFC9F7EB01F51BE504A6689B8442D8374FFF110E087A63A9F867
            77B76B7133DBA4F4A3FE1276C006908E2086E75E714A9A504A1ED02081CA2E06
            652B015C67CC168B4DC5F421D0D5AD9487C93C1B1FB67BBF0ECF6A541FA52CC4
            91BFBE8C55D48E5CBE1AA6132CC27870487D617ECC356B51400D19E933FB3A46
            FF892358EC6953221D4484B7E42B32D91FF35A8C54BB821F652349C85A5DDBF5
            BA776AF4C347D97A49C92A5BEA4DE46D7B9C57AF741687ADAF22FAD306673D64
            F25212A878D80D6B42FC994920129DD08EB71543D5CA6F113D288CDA6D33BFC2
            EECA5EF80B8283053EECB6BC67D34DE72DD6483C8EA272516A5CDC77274D1073
            D6E125A3BDA92BB395FA34DE33FBE01CB3F345D2243C022731BD90C05980EC2C
            AF4C7F0E545FDF6DA2775EC875201DC244148F102FDA1C5F76B7F0CE4F2BB7F1
            A62082A25B624428AB7E2AE93D74B7FB90BA38E34709A807F6565BE0486EF21B
            D207A146181F853C5AE1C147BA561D9597E666B3AD0E32C9FD156DF340A02D85
            5E5EE2D9247BC7990933E33FBC4338DBF1A25DEA21B97F834306946B3BEEDD8A
            8628661FF11E6B2673017DC92DD39D2D38839825C0B9ED30A10D32464ED46100
            2C91925A2CF722669BFD1EFA1E9F0A5995F770DD61FF241BC540E6E486CD2335
            2FBAC6A81F27D6AA553E39D605C86221290F7D5D79B740E0790FB4F68EBE4FE5
            BEA861B7F37B746025DA935391FE77712573C3797940769AAC1AF6893F7049D5
            2DDC3D44B43BF0F4A40F96B22934595806542BCD365ED26F72DA9D00CD7F1675
            494843AAA743C58F8917A9E0F4AA745D8FA40CBAED16F6F9D1C2DD21DA8357A0
            FACD8CC34CE5629C573FC81BA119594AE7FCE8C621CE1677E4023102466B500E
            0A5AEC9B3795981FA73DB5D03024790FDD631125F889A335FA8AE16742BA70E0
            CD5410FEC92B644B9E82FB664ED0904668EEC471C6ED20EE1559CFD25C5EDD6E
            2324F77962BBC9EEDC6613418F2E34A28A43AE7ADE1F0BCDC8F58C54D47A8720
            8D8F2D6C6FE58AA714F883BAAB
            """);

        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.100.100",
            "193.167.0.100",
            443,
            46351);
        QuicRecordingDiagnosticsSink diagnosticsSink = new();

        QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: localHandshakePrivateKey,
            remoteCertificateValidationCallback: static (_, _, _, errors) =>
                errors == SslPolicyErrors.RemoteCertificateChainErrors,
            clientAuthenticationOptions: new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                TargetHost = "server4",
            },
            diagnosticsSink: diagnosticsSink,
            tlsRole: QuicTlsRole.Client);

        Assert.True(clientRuntime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        Assert.True(clientRuntime.TrySetBootstrapOutboundPath(pathIdentity));
        Assert.True(clientRuntime.TrySetHandshakeSourceConnectionId(clientSourceConnectionId));

        QuicConnectionTransitionResult bootstrap = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: CreateCapturedClientTransportParameters(clientSourceConnectionId)),
            nowTicks: 1);

        QuicConnectionSendDatagramEffect sentInitialDatagram = Assert.Single(
            bootstrap.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] bootstrapClientInitialDatagram = sentInitialDatagram.Datagram.ToArray();
        byte[] capturedClientInitialPlaintextPacket =
            OpenProtectedClientInitialAsServer(initialDestinationConnectionId, capturedClientInitialDatagram);
        byte[] bootstrapClientInitialPlaintextPacket =
            OpenProtectedClientInitialAsServer(initialDestinationConnectionId, bootstrapClientInitialDatagram);

        Assert.Equal(capturedClientInitialPlaintextPacket, bootstrapClientInitialPlaintextPacket);

        return new CapturedInteropHandshakeScenario(
            clientRuntime,
            pathIdentity,
            diagnosticsSink,
            capturedClientInitialDatagram,
            bootstrapClientInitialDatagram,
            capturedClientInitialPlaintextPacket,
            bootstrapClientInitialPlaintextPacket,
            capturedServerInitialPacket,
            capturedServerHandshakePacket);
    }

    private static QuicTransportParameters CreateCapturedClientTransportParameters(ReadOnlySpan<byte> clientSourceConnectionId)
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 0,
            InitialMaxData = 16_777_216,
            InitialMaxStreamDataBidiLocal = 65_536,
            InitialMaxStreamDataBidiRemote = 65_536,
            InitialMaxStreamDataUni = 65_536,
            InitialMaxStreamsBidi = 0,
            InitialMaxStreamsUni = 0,
            ActiveConnectionIdLimit = 2,
            InitialSourceConnectionId = clientSourceConnectionId.ToArray(),
        };
    }

    private static byte[] DecodeHex(string hex)
    {
        string normalizedHex = new(hex.Where(static ch => !char.IsWhiteSpace(ch)).ToArray());
        return Convert.FromHexString(normalizedHex);
    }

    private static byte[] OpenProtectedClientInitialAsServer(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> protectedPacket)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection serverInitialProtection));
        byte[] plaintextPacketBuffer = new byte[protectedPacket.Length];
        Assert.True(serverInitialProtection.TryOpen(protectedPacket, plaintextPacketBuffer, out int plaintextPacketLength));
        return plaintextPacketBuffer[..plaintextPacketLength];
    }

    internal sealed class CapturedInteropHandshakeScenario : IDisposable
    {
        public CapturedInteropHandshakeScenario(
            QuicConnectionRuntime clientRuntime,
            QuicConnectionPathIdentity pathIdentity,
            QuicRecordingDiagnosticsSink diagnosticsSink,
            byte[] capturedClientInitialDatagram,
            byte[] bootstrapClientInitialDatagram,
            byte[] capturedClientInitialPlaintextPacket,
            byte[] bootstrapClientInitialPlaintextPacket,
            byte[] capturedServerInitialPacket,
            byte[] capturedServerHandshakePacket)
        {
            ClientRuntime = clientRuntime;
            PathIdentity = pathIdentity;
            DiagnosticsSink = diagnosticsSink;
            CapturedClientInitialDatagram = capturedClientInitialDatagram;
            BootstrapClientInitialDatagram = bootstrapClientInitialDatagram;
            CapturedClientInitialPlaintextPacket = capturedClientInitialPlaintextPacket;
            BootstrapClientInitialPlaintextPacket = bootstrapClientInitialPlaintextPacket;
            CapturedServerInitialPacket = capturedServerInitialPacket;
            CapturedServerHandshakePacket = capturedServerHandshakePacket;
        }

        public QuicConnectionRuntime ClientRuntime { get; }

        public QuicConnectionPathIdentity PathIdentity { get; }

        public QuicRecordingDiagnosticsSink DiagnosticsSink { get; }

        public byte[] CapturedClientInitialDatagram { get; }

        public byte[] BootstrapClientInitialDatagram { get; }

        public byte[] CapturedClientInitialPlaintextPacket { get; }

        public byte[] BootstrapClientInitialPlaintextPacket { get; }

        public byte[] CapturedServerInitialPacket { get; }

        public byte[] CapturedServerHandshakePacket { get; }

        public void Dispose()
        {
            ClientRuntime.Dispose();
        }
    }
}

using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0147")]
public sealed class REQ_QUIC_CRT_0147
{
    private const ushort Tls13Version = 0x0304;
    private const ushort HelloRetryRequestSelectedGroupExtensionLength = sizeof(ushort);

    private static readonly byte[] HelloRetryRequestRandom = Convert.FromHexString(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    private static readonly byte[] CapturedServerMulticonnectHrrReplayClientInitial0 = FromHexLines(
        "C10000000114E699B5051BFC2232F62A176D7ECB0AF4A0A29930000044E241D4233BB6D6DF52B54162FCAADFB2063108",
        "C9658ACF0DA924D6531EE15DC3F4F55E7E30C0DB0FD686147FAFADE6E975A76E6777500FAF77FA95D1EFC0AECAE87713",
        "553F3DE8EC813FA1DA345D8B4CF7A6A9A7A28317C9F7C9E80C8A01969465A12B3038606B3B90F0A853905F709F88F1F2",
        "BB4B69D4D6337A2F8B99286F6C708B2828788624E1CD837A3B178F081C061FBD819B4FB7E963E0F2A63CA21F5D4CD364",
        "E7E3E7B4D7571C1698C7176FF8B2536DBD170ABFCD721FEF1CE64F84F6651B159EA941FF56CB739B8EBF5F4D96A6CBA2",
        "C25707462D6C42D2605BC0855E0BFBECB997DAFCE75CF1281ABFC6F423FB4CECE7327C07D295DA6B3278745A870D7CD5",
        "A3EB6609E9879DE985FA00AB8D0C1EACEDC0BBE9468DE569C983551B3DFDA13C8565B9F7DDF877C2F2A3A03F3E00E4F3",
        "EA81D6CBD7D1EABF48CDF0E8D2D1B2A4FA065E0FB216C5D0CD239314ECE10CFB3FF7745739635B6585B8D1CA6A677D01",
        "694AA953BD0392B68E2DE64976C51AB70E1D1F2FC016593C923BD720E5918D6C06BD5E4568EA878C89DF2EBBC40BE307",
        "C2F73363BAD1EA650BDEF3745E6F4D1617252C7E5926FC78A039F7D192B312D500F61E86448A8A190A261EABD0797F32",
        "BBF6C457BFA11DFAF3784BFD3D4803CF3C507F9BB068EA61B26E3DDB93FFEA661F83B92528D6C583ACC3793F7628D36F",
        "AC08105ADA6E71DAE84A231B488302859DEF40B7C5DA97BE29E45132E21D5739E1EFCD1929B5C6DB5939EB24E3EDE26B",
        "4CF868017123E26652D1E378D6F704448DE1ACE21B2527C0BE855858D1C80220105432E9BB7CA51D8336BAC6D98E701A",
        "61C1B8D5B8C7FA76ADD0FBD5798D5A02DD54040B444436C4D0B320452EB161F83FB9A42E724FB75C52C0748E8BF7774B",
        "7E94F53FE0AF671BF5AE01647D1C0979214DF657293A7AF8FF9034ECAA9CDA44ADDDA59F02E22938AA0608094FD0259F",
        "CF2F7778AE82A6208DFA1F368DFDB0BF6FEDE714DA009E4CDC23FEFD768DB7FDB48EDB83D9AA6B2EFD9DBD2B9B70E46F",
        "A3892469B0AF5A3DF30190268AA18E9492B4B57874786A032DBCC5557E17788468EA5CD2CB6277E4DC1D2BAB617390A7",
        "A480FD2ADBE0650001D9E7CE2A30882C04E8375DB941467A577F3F3246B5E1399614616891546251B6484D23D1C11733",
        "A9C3DA544C1C5ABE4637F7A5FD16634FB68A3BC1BD4F53D130E4D633F0F8790C22ED7DB24551919853FECFE118775AF2",
        "B8804DFCE229F651474F5603A10F60D23869C5E80FB5D4F0CFC06E84348FEE85FBB82E2A5C2660935428188775DB774A",
        "57039FF4FAE276A8E9B71A2AD130463B5814BDE972E4C981E1280581BE8CB670D0EAE33412674476B3A2730FCE7555B4",
        "7CF024D2D867962FFBCF396D45F8484A911E13338868CAB4D1819B735060C2084B2DA2F5171E84F201DF74C56F1B9E1B",
        "AA7D0C166F5239915F06C15D3F3307674B183F17933A8718AC6370AEB51398D27524042A130FB119A477E8360147C6B4",
        "5B1AE280278C99BBC731C3631731E22AA5A9F7ADEE11CC1C9355C78442137C57CF7746F930A8736871AF6D0F3AFEB130",
        "6118B5135904D792945F64DD619C1DB00A27065357710128F71382008254FFDF8AB8AC55FE8EDE54B5665DAD66F2DDB4",
        "340109F4F080027B7BE0FABF3FBBCE9D12632719F2B226164FD75B0150E5B5D2B878BB449055D155ABEF9E7CAB609991",
        "0AC3104632C41E097B1F9CC774A79493822AEDF88DD2E3B9EBCFD24F0C7CCE75");

    private static readonly byte[] CapturedServerMulticonnectHrrReplayClientInitial1 = FromHexLines(
        "C50000000114E699B5051BFC2232F62A176D7ECB0AF4A0A29930000044E2F9893B21C5D8221482D93CEC6F1F8EE00349",
        "5C99E46AC143AC41E44BEEF85765F81C83610C745711864146BA4EAE945DE924F90D23CCE49DB3A4D0320C041FAC5FDE",
        "D688B32F8C2978470C3266E33EAEEFF5D4F3EDB849B3341F17E5F629EEB611962DD89B2151960B9DD9E79F2A3DB04998",
        "4AC40A08BA3AECD346920D97BDA03AE1C68E81B161111DFBAECD4831E1D3902BD84903242416BFEB07061AF6846B87EB",
        "95994EBB43CB7E37C9A58A922FF4D313542D28C2AE6922522BEB1CD5AF4255C5DD764F3FF094E13C185D76EB78A14C06",
        "91B06D6DF97951D7E1B5D2C871F7CCFC79A157A006D7B375EA173BA9755329AE51F8F3924C8BDBC453E352F286710204",
        "DF2CFF27A99E1B8756A828C114CA02B2BCA64057CCC6C7E88F89628EE740B1B656B514ADE325CD3C112F40898B70BC80",
        "0136FF7D4B1187F13A7D17A5090630A19CD5393D523C395F6E272087E5E99022903866738C05741907904678E1407B5A",
        "0626FA2FFB66F3DA7AE27DBAC325B110F90E9CAAC629C1888A0D469D9B5DAE76E19B28D213E8D6A9C28DB378EEDCCC17",
        "0E058FCD93DF9981E474FDD08DE08C399205B645C5B7A59FE2C15099B0E8303279D00E9D9B80148F27DB4C47E4203649",
        "0DD87EC0DDA16EF2E8B688E8A05318FE437D6C3FF6B4809EC499E7139B12B92DD3D49F73608A7FA6A6F410F5B848C42B",
        "1FBAC42F7891CAEC32F46C4EFD29C377786F56C2E7948407596C625BEC4E6EF1816C7CF349CCA59AD994A1AAD02540B2",
        "519FA998843D60D91097675E78AE14A2B6BC06523CD3D17F1C0850C58F37024BF6ECA273A52C884C36417C1AF103532B",
        "0574F2DC9367C8D59391D2504B8D371163AE351E705A343FA2A79763F1BACD1BA8A9C199608ABA3060F79107D70B531F",
        "A7BE80C3DDA39CB4CC2B1CD84220CE7043B9B1472CB6D45CC92D0CAF2ADEACB1E1B30EB272C41F6A70046D8617AB65C1",
        "A72788EBA634A1A8F57F96F5F11B067618AA18066253F94472A0574E6F1785BD79566965E6C133356CC1B6A164C95A0E",
        "0B061D3DA358AB63743EC962E96B9459BCD7611711DBC736DAAAF909C9942776EA7E4B0F9EDF5A09C76DE5C641B1A28D",
        "C7AD5C3165241E6CB60DAE8AE1BFE5E49D8F58DC2625A04D4413E69B06FFF5DBA446BBE85D9A13FE477D019819791EFF",
        "C712A49F3B3F7B4C7B9177DAE549F2AF49A62946B6A17F0176E7253CAF3FA64B59D141F40E0B8681F7B20515E56C5EC4",
        "53782BA44872D273C6C7F37A1223718DB9760607CE606DE500CD7BE364A694EFDFEA9AE77BA2EE35925E4C3589404910",
        "6810D9EECCDD8CE28B25E1D14EB5390269B0BC04A4727CC095DD150D8399BD95679FED0DEADE9DE43E86BEF1F6347556",
        "12DD74A42EDB6D49BBFC47373B050B8E003BE8AF4123234C84EC0C1E04E8803AF6A05744FCA10788D7723211BEEDB742",
        "5537590FBD076F767FC715191DA9C717CED8B53BEB87C1CB6C222F8BE7F72D536812CE2C34B74278AEC6C73B39E25265",
        "89079112EB652B2F34C5EE010F69F8AFF1319A049D02CBA191B78F8FAEB9BAD436E5A8E23727DAD55BC7770BDCEA1ED0",
        "09CD20C1ABC8EE8145951FA9A9B697868AAE4072CD60B96A72235393FFB60E0CEBD0E00FB8D5F3E07DA3A52F6ED58E70",
        "CB99AA2889E6875E9C6BE1B8C0B56AEBEFD88E1A9B3D9220D23DBF4E99335A2B3D92E48067E3B81FB74C708689778759",
        "EF8EBFA9B6764A39F9666B48382DCFAD82CCC0E2F06FEE3217FFABFF3F5122AD");

    private static readonly byte[] CapturedServerMulticonnectHrrReplayClientInitial2 = FromHexLines(
        "C50000000114E699B5051BFC2232F62A176D7ECB0AF4A0A29930000044E2F607947BA365AC41ED991931443CE667F42B",
        "BD146ACC9A4EA9C5A1C8830B4504E3E82068BBBB5D69166C56EA9CFE47AA0864EC00A4EB9E9D3A4232CED23C2D0CC979",
        "5E864B813DFC4BCAA7F1B27195102CD404759058B8CFA77EEB5E8BDD669EA35F605D57201637CC4AFDB3B62053B6613B",
        "86AF330BBC5E3D50007D5E8CC15AAA885DE4221ADBCCD7E9B3FD552F94744FA80AE63EB024C32EB6458ED6E9DAEA3F4A",
        "0E4EAF8CFE15074A71B261D416D9E9A3BC10265B4B886DC65E2B0EDAB359F60FB296C10C1CE6F49B307FD0765C7A71F4",
        "4EF35A452ECB1FD3641F98FA03258BAFE8AF28F5C9D04F90E6FF5D9E8BCB8D12E3CD27C74B2C5F33D753B1D826B6CC57",
        "38BB145195248036B8F64A93E35FE4861404C5A58F21EEFA8B3D8F7F361F9B8A801F175F2A18E88670621DA3A0AE947A",
        "B698BC241655AD56250FC8CD86739FC97AA312AD9AA80DFA9945A7EFB6E9B3AF2B44BFAD3CB7779973A7710C5C04968D",
        "B9D4FB36C215B314C2BD899DBF1F23FB2DC22F208FFFC74862F312C63363E3EEB23E9D9D2487D5022A96BDA1D196EFC5",
        "56E200359E0348FE0E0B5FEBF5EF835E6618CA08BC5F41A269262D352EF0D51D2E409A58483CCB888DF4AB1530113163",
        "2B4201BAB8ADD5C582D87731DE6219FE08B72208275F7CD07673B11CDE9D1BFDB78CA9E99F1F11B3EE814EC1496FC292",
        "D199DE609EC7379A2A85306A73B9084253979FDA7838AB291F91182B37A8B7DC95BFA2F74B48CAFC7603F6BCBBC1897C",
        "3B839C2CDAA9B765C8A0AE34FA67F1F26506B7432BD55BEE4BCD011BF9F2D32D97D41761DAF7F434B4D8DC19A2CF9FA6",
        "352E27A9C31733DE2D1A8FC19642FFCE7C42ABA8174F39CCEFD3743B25EB00CA83654D17D8E4F01D7C71D931D6306B37",
        "09F20D40B4DF5CBEAE46389A62DC099562A2CC21E855CABF3BE1AB9E714619A8A907AEB2E5CB2715ABDFE41EA47260EF",
        "1DFB78B136266CB6A97E05F705D444510B7CF2CCBA7653DDAEC3E8E0353910BCDA6871943FAD5F7ADDF862942F32CCCC",
        "3DE94557EBBCF8605AD492BC16E9F90D8BD09D917372E69AF1DD427FD8A6452CCE677A5CBA087E269A8C6104366BE88A",
        "2D92E50A950EABD7E57A26460237C810357FE5D55DB99ADB17456D10708089DEA9A5AB21BB7525062E6044DD95E1F383",
        "9EA90459D1D0313F688D3AEF73BFBC04AC8DDCD40E628B76D473EE288C4B6911CDFF7B6054762B97B012549CBA402F30",
        "52FDB673DF6DB683DD50AC8C97CB3BE3EA9F96A921329D3993E81B7534B4EF97C94AC6990E7EE91995299D8403E442B4",
        "F4634BE1B5C9997A451F9F279F7CDF920AF535E4247D3A1E65DDEAD7BCE7288D85C6D6F693AB902E3BAF5DDB6529C333",
        "7284FF78CD206E5C7D19B542A1496211D1BFE0F52D3A4741C73AF20F6D482165EC35CA4F35BBAFE171004527562EE34B",
        "7A3CC9AD7B0B30BA1AB719A5C596B043824DF01723E6C81A902550017B52EA0A6808083ECF257E7468421452A4754C3F",
        "A48CC7D8B982318239DFA200977941F0CF9069D3D55E35C5F5D995ED3C40207C322529E7548EBAC692FA891F99512FD0",
        "AD3E00F34DEC4446DAE250745E231CA8A1E7A5E4678067F3BDA9A125FDFC58F626D43891F9FDED53C445798FA38AD397",
        "10D977D1F1F77000E85374B85E223BE1BFC343FE06D6818475EA333ED5A8BDE41F490EA2867B9C2BD95DA3EB55542CE3",
        "B6443D62D6A75C42ECD8B728AB47786D6BCCBEDF3F94F78518261D9F354F68B1");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedQuicGoFirstClientHelloEmitsExactlyOneDeterministicHelloRetryRequestBeforeServerHelloOrHandshakeKeys()
    {
        // Provenance: preserved quic-go server-role handshake evidence under
        // artifacts/interop-runner/20260422-110409619-server-nginx/
        // runner-logs/nginx_quic-go/handshake/output.txt and
        // runner-logs/nginx_quic-go/handshake/server/qlog/server-handshake-929cd4466b6d4e8dba49b1be5f1b6d0e.qlog.
        byte[] capturedClientHello = REQ_QUIC_CRT_0112.CreateCapturedQuicGoServerHandshakeClientHelloTranscript();
        Assert.Contains(
            "0x0033(keyshare=0x11EC:1216/0x001D:32)",
            REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello));

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            capturedClientHello);

        Assert.True(
            updates.Count == 2,
            $"{REQ_QUIC_CRT_0112.DescribeClientHello(capturedClientHello)} || {DescribeUpdates(updates, driver)}");
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, updates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, updates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, updates[0].TranscriptPhase);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, updates[0].SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, updates[0].TranscriptHashAlgorithm);
        Assert.Null(updates[0].TransportParameters);

        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, updates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, updates[1].EncryptionLevel);
        Assert.Equal(0UL, updates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage, driver.State.HandshakeTranscriptPhase);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, driver.State.HandshakeMessageType);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, driver.State.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, driver.State.TranscriptHashAlgorithm);
        Assert.Null(driver.State.StagedPeerTransportParameters);
        Assert.False(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.False(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            stackalloc byte[1],
            out _,
            out _));

        byte[] surfacedHelloRetryRequest = new byte[updates[1].CryptoData.Length];
        Assert.True(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            surfacedHelloRetryRequest,
            out ulong initialOffset,
            out int bytesWritten));
        Assert.Equal(0UL, initialOffset);
        Assert.Equal(surfacedHelloRetryRequest.Length, bytesWritten);
        Assert.True(
            updates[1].CryptoData.Span.SequenceEqual(surfacedHelloRetryRequest),
            "The surfaced Initial CRYPTO payload should match the published HelloRetryRequest bytes.");

        HelloRetryRequestDescription helloRetryRequest = ParseHelloRetryRequest(surfacedHelloRetryRequest);
        Assert.True(helloRetryRequest.Random.AsSpan().SequenceEqual(HelloRetryRequestRandom));
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, helloRetryRequest.CipherSuite);
        Assert.Equal(Tls13Version, helloRetryRequest.SupportedVersion);
        Assert.Equal(QuicTlsNamedGroup.Secp256r1, helloRetryRequest.SelectedGroup);
        Assert.True(
            helloRetryRequest.SessionId.AsSpan().SequenceEqual(GetClientHelloSessionId(capturedClientHello)),
            "The HelloRetryRequest must echo the original ClientHello session ID.");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetriedSecp256r1ClientHelloRejoinsTheExistingServerHelloPublicationFloorAfterHelloRetryRequest()
    {
        QuicTransportParameters peerTransportParameters = REQ_QUIC_CRT_0112.CreateClientTransportParameters();
        byte[] retryEligibleClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            peerTransportParameters,
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, 0x001D],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    0x001D,
                    REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32)),
            ]);
        byte[] retriedClientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(peerTransportParameters);

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);

        Assert.Equal(2, firstUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, firstUpdates[1].Kind);

        byte[] helloRetryRequest = new byte[firstUpdates[1].CryptoData.Length];
        Assert.True(driver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            helloRetryRequest,
            out ulong helloRetryRequestOffset,
            out int helloRetryRequestBytesWritten));
        Assert.Equal(0UL, helloRetryRequestOffset);
        Assert.Equal(helloRetryRequest.Length, helloRetryRequestBytesWritten);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            stackalloc byte[1],
            out _,
            out _));

        IReadOnlyList<QuicTlsStateUpdate> secondUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retriedClientHello);

        Assert.True(secondUpdates.Count >= 6);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, secondUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ClientHello, secondUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, secondUpdates[0].TranscriptPhase);
        Assert.NotNull(secondUpdates[0].TransportParameters);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, secondUpdates[1].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Initial, secondUpdates[1].EncryptionLevel);
        Assert.Equal((ulong)helloRetryRequest.Length, secondUpdates[1].CryptoDataOffset);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, secondUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, secondUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, secondUpdates[4].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, secondUpdates[4].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, secondUpdates[5].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.Handshake, secondUpdates[5].EncryptionLevel);
        Assert.Equal(0UL, secondUpdates[5].CryptoDataOffset);

        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.True(driver.State.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(driver.State.TryGetHandshakeProtectPacketProtectionMaterial(out _));
        Assert.NotNull(driver.State.StagedPeerTransportParameters);
        Assert.Equal(peerTransportParameters.InitialSourceConnectionId, driver.State.StagedPeerTransportParameters!.InitialSourceConnectionId);
        Assert.Equal(peerTransportParameters.MaxIdleTimeout, driver.State.StagedPeerTransportParameters.MaxIdleTimeout);
        Assert.Equal(peerTransportParameters.DisableActiveMigration, driver.State.StagedPeerTransportParameters.DisableActiveMigration);

        QuicTlsTranscriptProgress serverHelloProgress = new(QuicTlsRole.Client);
        serverHelloProgress.AppendCryptoBytes(0, secondUpdates[1].CryptoData.Span);
        QuicTlsTranscriptStep serverHelloStep = serverHelloProgress.Advance(QuicTlsRole.Client);

        Assert.Equal(QuicTlsTranscriptStepKind.Progressed, serverHelloStep.Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloStep.HandshakeMessageType);
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, serverHelloStep.SelectedCipherSuite);
        Assert.Equal(QuicTlsTranscriptHashAlgorithm.Sha256, serverHelloStep.TranscriptHashAlgorithm);
        Assert.Equal(QuicTlsNamedGroup.Secp256r1, serverHelloStep.NamedGroup);
        Assert.False(serverHelloStep.KeyShare.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedQuicGoZeroSourceConnectionIdClientHelloStillFlushesTheHelloRetryRequestInitialDatagram()
    {
        // Provenance: preserved rerun after the transcript-level HelloRetryRequest change under
        // artifacts/interop-runner/20260422-122418367-server-nginx/
        // runner-logs/nginx_quic-go/handshake/client/log.txt and
        // runner-logs/nginx_quic-go/handshake/server/qlog/server-handshake-3639ba87f96646ca94a7b2218dcaf39a.qlog.
        // The live quic-go client advertises destination CID 19f036a30c94ca850c88 and an empty source CID,
        // then times out because the managed server never flushes the HelloRetryRequest Initial response.
        byte[] originalDestinationConnectionId = Convert.FromHexString("19F036A30C94CA850C88");
        byte[] serverSourceConnectionId = [0x65, 0x66, 0x67, 0x68];
        byte[] capturedClientHello = REQ_QUIC_CRT_0112.CreateCapturedQuicGoServerHandshakeClientHelloTranscript();
        byte[][] clientInitialPackets = CreateCapturedQuicGoClientInitialPacketsWithZeroSourceConnectionId(
            originalDestinationConnectionId,
            capturedClientHello);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("server4");
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            parameterName: "serverOptions",
            listenerApplicationProtocols: [SslApplicationProtocol.Http3]);

        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22),
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        localTransportParameters.OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();

        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(originalDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId([]));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));
        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 0).StateChanged);

        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.0.100",
            "193.167.100.100",
            41201,
            443);

        QuicConnectionTransitionResult firstInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                pathIdentity,
                clientInitialPackets[0]),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged, DescribeRuntimeResult(serverRuntime, firstInitialResult));
        Assert.Empty(firstInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicConnectionTransitionResult secondInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                pathIdentity,
                clientInitialPackets[1]),
            nowTicks: 2);

        QuicConnectionSendDatagramEffect helloRetryRequestEffect = Assert.Single(
            secondInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            static effect =>
                QuicPacketParser.TryGetPacketNumberSpace(effect.Datagram.Span, out QuicPacketNumberSpace packetNumberSpace)
                && packetNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.DoesNotContain(
            secondInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            static effect =>
                QuicPacketParser.TryGetPacketNumberSpace(effect.Datagram.Span, out QuicPacketNumberSpace packetNumberSpace)
                && packetNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.False(
            serverRuntime.TlsState.InitialEgressCryptoBuffer.DiscardingFutureFrames,
            DescribeRuntimeResult(serverRuntime, secondInitialResult));
        Assert.False(serverRuntime.TlsState.HandshakeKeysAvailable, DescribeRuntimeResult(serverRuntime, secondInitialResult));
        Assert.Null(serverRuntime.TlsState.StagedPeerTransportParameters);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        QuicHandshakeFlowCoordinator clientCoordinator = new(originalDestinationConnectionId, sourceConnectionId: ReadOnlyMemory<byte>.Empty);
        Assert.True(clientCoordinator.TryOpenInitialPacket(
            helloRetryRequestEffect.Datagram.Span,
            clientProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out _));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));
        Assert.Empty(destinationConnectionId.ToArray());
        Assert.True(sourceConnectionId.SequenceEqual(serverSourceConnectionId));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        Assert.Equal(0UL, cryptoFrame.Offset);

        HelloRetryRequestDescription helloRetryRequest = ParseHelloRetryRequest(cryptoFrame.CryptoData.ToArray());
        Assert.True(helloRetryRequest.Random.AsSpan().SequenceEqual(HelloRetryRequestRandom));
        Assert.Equal(QuicTlsCipherSuite.TlsAes128GcmSha256, helloRetryRequest.CipherSuite);
        Assert.Equal(Tls13Version, helloRetryRequest.SupportedVersion);
        Assert.Equal(QuicTlsNamedGroup.Secp256r1, helloRetryRequest.SelectedGroup);
        Assert.True(
            helloRetryRequest.SessionId.AsSpan().SequenceEqual(GetClientHelloSessionId(capturedClientHello)),
            DescribeRuntimeResult(serverRuntime, secondInitialResult));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetriedZeroSourceConnectionIdClientHelloFlushesServerHelloInitialBeforeTheHandshakeFlight()
    {
        // Provenance: preserved rerun after the zero-length peer-CID fix under
        // artifacts/interop-runner/20260422-124113071-server-nginx/
        // runner-logs/nginx_quic-go/handshake/client/log.txt and
        // runner-logs/nginx_quic-go/handshake/server/qlog/server-handshake-ba27cde4e8594a5da512bd8ae4e5327b.qlog.
        // The live quic-go client receives the HelloRetryRequest Initial, sends a retried ClientHello with an
        // empty source CID, and then only queues an undecryptable Handshake packet because the managed server
        // fails to flush the follow-on ServerHello Initial.
        byte[] originalDestinationConnectionId = Convert.FromHexString("19F036A30C94CA850C88");
        byte[] serverSourceConnectionId = [0x65, 0x66, 0x67, 0x68];
        QuicTransportParameters peerTransportParameters = REQ_QUIC_CRT_0112.CreateClientTransportParameters();
        byte[] retryEligibleClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            peerTransportParameters,
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, 0x001D],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    0x001D,
                    REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32)),
            ],
            applicationProtocols: [SslApplicationProtocol.Http3.Protocol.ToArray()]);
        byte[] retriedClientHello = REQ_QUIC_CRT_0112.CreateClientHelloTranscript(
            peerTransportParameters,
            applicationProtocols: [SslApplicationProtocol.Http3.Protocol.ToArray()]);
        byte[][] clientInitialPackets = CreateClientInitialPacketsWithZeroSourceConnectionId(
            originalDestinationConnectionId,
            retryEligibleClientHello);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("server4");
        QuicServerConnectionSettings serverSettings = QuicServerConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate),
            parameterName: "serverOptions",
            listenerApplicationProtocols: [SslApplicationProtocol.Http3]);

        using QuicConnectionRuntime serverRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22),
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        localTransportParameters.OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();

        Assert.True(serverRuntime.TryConfigureInitialPacketProtection(originalDestinationConnectionId));
        Assert.True(serverRuntime.TrySetHandshakeDestinationConnectionId([]));
        Assert.True(serverRuntime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(serverRuntime.TryConfigureLocalApplicationProtocols([SslApplicationProtocol.Http3]));
        Assert.True(serverRuntime.TryConfigureServerAuthenticationMaterial(
            serverSettings.ServerLeafCertificateDer,
            serverSettings.ServerLeafSigningPrivateKey));
        Assert.True(serverRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 0).StateChanged);

        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.0.100",
            "193.167.100.100",
            41201,
            443);

        QuicConnectionTransitionResult secondInitialResult = default;
        for (int packetIndex = 0; packetIndex < clientInitialPackets.Length; packetIndex++)
        {
            QuicConnectionTransitionResult currentInitialResult = serverRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: packetIndex + 1,
                    pathIdentity,
                    clientInitialPackets[packetIndex]),
                nowTicks: packetIndex + 1);
            Assert.True(currentInitialResult.StateChanged, DescribeRuntimeResult(serverRuntime, currentInitialResult));

            if (packetIndex < clientInitialPackets.Length - 1)
            {
                Assert.Empty(currentInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
            }

            secondInitialResult = currentInitialResult;
        }

        QuicConnectionSendDatagramEffect helloRetryRequestEffect = Assert.Single(
            secondInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            static effect => IsPacketNumberSpace(effect, QuicPacketNumberSpace.Initial));
        Assert.False(
            serverRuntime.TlsState.InitialEgressCryptoBuffer.DiscardingFutureFrames,
            DescribeRuntimeResult(serverRuntime, secondInitialResult));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        QuicHandshakeFlowCoordinator clientCoordinator = new(originalDestinationConnectionId, sourceConnectionId: ReadOnlyMemory<byte>.Empty);
        Assert.True(clientCoordinator.TryOpenInitialPacket(
            helloRetryRequestEffect.Datagram.Span,
            clientProtection,
            out byte[] openedHelloRetryRequestPacket,
            out int helloRetryRequestPayloadOffset,
            out int helloRetryRequestPayloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedHelloRetryRequestPacket.AsSpan(helloRetryRequestPayloadOffset, helloRetryRequestPayloadLength),
            out QuicCryptoFrame helloRetryRequestFrame,
            out _));

        byte[] retriedInitialPacket = BuildProtectedClientInitialPacket(
            initialProtectionConnectionId: originalDestinationConnectionId,
            packetDestinationConnectionId: serverSourceConnectionId,
            cryptoPayload: retriedClientHello,
            cryptoPayloadOffset: (ulong)retryEligibleClientHello.Length,
            packetNumber: 2);

        QuicConnectionTransitionResult retriedInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                retriedInitialPacket),
            nowTicks: 3);

        QuicConnectionSendDatagramEffect[] sendEffects = retriedInitialResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(sendEffects);
        Assert.True(
            IsPacketNumberSpace(sendEffects[0], QuicPacketNumberSpace.Initial),
            DescribeRuntimeResult(serverRuntime, retriedInitialResult));
        QuicConnectionSendDatagramEffect serverHelloEffect = Assert.Single(
            sendEffects,
            static effect => IsPacketNumberSpace(effect, QuicPacketNumberSpace.Initial));
        Assert.Contains(sendEffects, effect => IsPacketNumberSpace(effect, QuicPacketNumberSpace.Handshake));
        Assert.True(serverRuntime.TlsState.HandshakeKeysAvailable, DescribeRuntimeResult(serverRuntime, retriedInitialResult));

        Assert.True(clientCoordinator.TryOpenInitialPacket(
            serverHelloEffect.Datagram.Span,
            clientProtection,
            out byte[] openedServerHelloPacket,
            out int serverHelloPayloadOffset,
            out int serverHelloPayloadLength));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedServerHelloPacket,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out _));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));
        Assert.Empty(destinationConnectionId.ToArray());
        Assert.True(sourceConnectionId.SequenceEqual(serverSourceConnectionId));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedServerHelloPacket.AsSpan(serverHelloPayloadOffset, serverHelloPayloadLength),
            out QuicCryptoFrame serverHelloFrame,
            out _));
        Assert.Equal((ulong)helloRetryRequestFrame.CryptoData.Length, serverHelloFrame.Offset);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ServerHello, serverHelloFrame.CryptoData[0]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedServerMulticonnectDuplicateInitialAfterHelloRetryRequestReplaysThePendingHrrPacket()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-210022638-server-nginx\
        //   runner-logs\nginx_quic-go\handshakeloss\client\log.txt
        //   runner-logs\nginx_quic-go\handshakeloss\server\qlog\server-multiconnect-e9838e9861bf4dc3a997a1536cf523eb.qlog
        // Connection 11 received the first two quic-go Initial packets, emitted an HRR Initial, then received
        // duplicate first-ClientHello Initial packets while the client never logged a received HRR. The server
        // must retransmit the already-published HRR packet promptly without producing a second TLS HRR.
        byte[] originalDestinationConnectionId = Convert.FromHexString("E699B5051BFC2232F62A176D7ECB0AF4A0A29930");
        byte[] serverSourceConnectionId = Convert.FromHexString("C19E25085E926C93");
        using QuicConnectionRuntime serverRuntime = CreateServerRuntimeForCapturedHrrReplay(
            originalDestinationConnectionId,
            serverSourceConnectionId);
        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.0.100",
            "193.167.100.100",
            59504,
            443);

        QuicConnectionTransitionResult firstInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 1, pathIdentity, CapturedServerMulticonnectHrrReplayClientInitial0),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged, DescribeRuntimeResult(serverRuntime, firstInitialResult));
        Assert.Empty(firstInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicConnectionTransitionResult secondInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 2, pathIdentity, CapturedServerMulticonnectHrrReplayClientInitial1),
            nowTicks: 2);
        QuicConnectionSendDatagramEffect firstHrrEffect = Assert.Single(
            secondInitialResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            static effect => IsPacketNumberSpace(effect, QuicPacketNumberSpace.Initial));
        Assert.False(serverRuntime.TlsState.HandshakeKeysAvailable, DescribeRuntimeResult(serverRuntime, secondInitialResult));
        QuicCryptoFrame firstHrrFrame = OpenInitialCryptoFrame(
            originalDestinationConnectionId,
            firstHrrEffect.Datagram.Span);

        QuicConnectionTransitionResult duplicateInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 3, pathIdentity, CapturedServerMulticonnectHrrReplayClientInitial2),
            nowTicks: 3);
        QuicConnectionSendDatagramEffect[] replayEffects = duplicateInitialResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Where(static effect => IsPacketNumberSpace(effect, QuicPacketNumberSpace.Initial))
            .ToArray();
        Assert.True(
            replayEffects.Length == 1,
            $"postHrr={DescribeRuntimeResult(serverRuntime, secondInitialResult)} | firstHrr={firstHrrFrame.Offset}+{firstHrrFrame.CryptoData.Length} | duplicateResult={DescribeRuntimeResult(serverRuntime, duplicateInitialResult)} | duplicate={DescribeClientInitialCryptoFrames(originalDestinationConnectionId, CapturedServerMulticonnectHrrReplayClientInitial2)}");
        QuicConnectionSendDatagramEffect replayedHrrEffect = replayEffects[0];
        Assert.False(serverRuntime.TlsState.HandshakeKeysAvailable, DescribeRuntimeResult(serverRuntime, duplicateInitialResult));
        Assert.Null(serverRuntime.TlsState.StagedPeerTransportParameters);

        QuicCryptoFrame replayedHrrFrame = OpenInitialCryptoFrame(
            originalDestinationConnectionId,
            replayedHrrEffect.Datagram.Span);

        Assert.Equal(0UL, firstHrrFrame.Offset);
        Assert.Equal(firstHrrFrame.Offset, replayedHrrFrame.Offset);
        Assert.True(firstHrrFrame.CryptoData.SequenceEqual(replayedHrrFrame.CryptoData));
        HelloRetryRequestDescription replayedHelloRetryRequest = ParseHelloRetryRequest(replayedHrrFrame.CryptoData.ToArray());
        Assert.True(replayedHelloRetryRequest.Random.AsSpan().SequenceEqual(HelloRetryRequestRandom));
        Assert.Equal(QuicTlsNamedGroup.Secp256r1, replayedHelloRetryRequest.SelectedGroup);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapturedServerMulticonnectDuplicateInitialBeforeCompleteClientHelloDoesNotReplayHrr()
    {
        byte[] originalDestinationConnectionId = Convert.FromHexString("E699B5051BFC2232F62A176D7ECB0AF4A0A29930");
        byte[] serverSourceConnectionId = Convert.FromHexString("C19E25085E926C93");
        using QuicConnectionRuntime serverRuntime = CreateServerRuntimeForCapturedHrrReplay(
            originalDestinationConnectionId,
            serverSourceConnectionId);
        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.0.100",
            "193.167.100.100",
            59504,
            443);

        QuicConnectionTransitionResult firstInitialResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 1, pathIdentity, CapturedServerMulticonnectHrrReplayClientInitial0),
            nowTicks: 1);
        Assert.True(firstInitialResult.StateChanged, DescribeRuntimeResult(serverRuntime, firstInitialResult));

        QuicConnectionTransitionResult duplicateFragmentResult = serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 2, pathIdentity, CapturedServerMulticonnectHrrReplayClientInitial2),
            nowTicks: 2);

        Assert.Empty(duplicateFragmentResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.False(serverRuntime.TlsState.HandshakeKeysAvailable, DescribeRuntimeResult(serverRuntime, duplicateFragmentResult));
        Assert.Equal(0, serverRuntime.TlsState.InitialEgressCryptoBuffer.BufferedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingSecp256r1SupportedGroupsStillFailsInsteadOfEmittingHelloRetryRequest()
    {
        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        byte[] unsupportedClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
            supportedGroups: [0x001D],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    0x001D,
                    REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32)),
            ]);

        IReadOnlyList<QuicTlsStateUpdate> updates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            unsupportedClientHello);

        AssertFatalAlert32(updates, driver);
        Assert.False(driver.TryPeekOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            stackalloc byte[1],
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedRetryEligibleClientHelloIsRejectedAfterTheSingleHelloRetryRequestBoundary()
    {
        byte[] retryEligibleClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, 0x001D],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    0x001D,
                    REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32)),
            ]);

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);
        Assert.Equal(2, firstUpdates.Count);

        IReadOnlyList<QuicTlsStateUpdate> repeatedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);

        AssertFatalAlert32(repeatedUpdates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MalformedRetriedClientHelloFailsDeterministicallyAfterHelloRetryRequest()
    {
        QuicTransportParameters peerTransportParameters = REQ_QUIC_CRT_0112.CreateClientTransportParameters();
        byte[] retryEligibleClientHello = CreateClientHelloTranscriptWithKeyShareEntries(
            peerTransportParameters,
            supportedGroups: [(ushort)QuicTlsNamedGroup.Secp256r1, 0x001D],
            keyShareEntries:
            [
                new ClientHelloKeyShareEntry(
                    0x001D,
                    REQ_QUIC_CRT_0112.CreateSequentialBytes(0x90, 32)),
            ]);

        QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            retryEligibleClientHello);
        Assert.Equal(2, firstUpdates.Count);

        byte[] helloRetryRequest = new byte[firstUpdates[1].CryptoData.Length];
        Assert.True(driver.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            helloRetryRequest,
            out _,
            out int helloRetryRequestBytesWritten));
        Assert.Equal(helloRetryRequest.Length, helloRetryRequestBytesWritten);

        IReadOnlyList<QuicTlsStateUpdate> malformedRetriedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Initial,
            REQ_QUIC_CRT_0112.CreateMalformedClientHelloTranscript(peerTransportParameters));

        AssertFatalAlert32(malformedRetriedUpdates, driver);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzRetryBoundary_PermutedSupportedGroupsAndKeySharesStayWithinTheSingleHelloRetryRequestSlice()
    {
        Random random = new(0x0147);

        for (int iteration = 0; iteration < 48; iteration++)
        {
            QuicTlsTransportBridgeDriver driver = CreateStartedServerDriver();
            byte[] validSecpKeyShare = CreateValidSecp256r1KeyShare(unchecked((byte)(0x40 + iteration)));
            byte[] alternateSecpKeyShare = CreateValidSecp256r1KeyShare(unchecked((byte)(0x80 + iteration)));
            byte[] x25519KeyShare = REQ_QUIC_CRT_0112.CreateSequentialBytes(unchecked((byte)(0x10 + iteration)), 32);
            byte[] hybridKeyShare = REQ_QUIC_CRT_0112.CreateSequentialBytes(unchecked((byte)(0x20 + iteration)), 48);
            byte[] malformedSecpKeyShare = validSecpKeyShare.ToArray();
            malformedSecpKeyShare[0] = 0x05;

            int scenario = iteration % 6;
            IReadOnlyList<QuicTlsStateUpdate> firstUpdates;

            switch (scenario)
            {
                case 0:
                {
                    ushort[] supportedGroups = Shuffle(
                        random,
                        [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D, (ushort)0x11EC]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                            new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, validSecpKeyShare),
                            new ClientHelloKeyShareEntry(0x11EC, hybridKeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    Assert.True(firstUpdates.Count >= 6);
                    Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, firstUpdates[0].Kind);
                    Assert.Equal(QuicTlsTranscriptPhase.PeerTransportParametersStaged, firstUpdates[0].TranscriptPhase);
                    Assert.True(driver.State.HandshakeKeysAvailable);
                    break;
                }

                case 1:
                {
                    ushort[] supportedGroups = Shuffle(
                        random,
                        [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D, (ushort)0x11EC]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                            new ClientHelloKeyShareEntry(0x11EC, hybridKeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    Assert.Equal(2, firstUpdates.Count);
                    Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, firstUpdates[1].Kind);
                    Assert.False(driver.State.HandshakeKeysAvailable);

                    byte[] helloRetryRequest = new byte[firstUpdates[1].CryptoData.Length];
                    Assert.True(driver.TryDequeueOutgoingCryptoData(
                        QuicTlsEncryptionLevel.Initial,
                        helloRetryRequest,
                        out ulong helloRetryRequestOffset,
                        out int helloRetryRequestBytesWritten));
                    Assert.Equal(0UL, helloRetryRequestOffset);
                    Assert.Equal(helloRetryRequest.Length, helloRetryRequestBytesWritten);

                    IReadOnlyList<QuicTlsStateUpdate> retriedUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            Shuffle(
                                random,
                                [
                                    new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                                    new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, validSecpKeyShare),
                                ])));

                    Assert.True(retriedUpdates.Count >= 6);
                    Assert.Equal((ulong)helloRetryRequest.Length, retriedUpdates[1].CryptoDataOffset);
                    Assert.True(driver.State.HandshakeKeysAvailable);
                    break;
                }

                case 2:
                {
                    ushort[] supportedGroups = Shuffle(
                        random,
                        [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, validSecpKeyShare),
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                            new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, alternateSecpKeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    AssertFatalAlert32(firstUpdates, driver);
                    break;
                }

                case 3:
                {
                    ushort[] supportedGroups = Shuffle(
                        random,
                        [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, malformedSecpKeyShare),
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    AssertFatalAlert32(firstUpdates, driver);
                    break;
                }

                case 4:
                {
                    ushort[] supportedGroups = Shuffle(random, [(ushort)0x001D, (ushort)0x11EC]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry((ushort)QuicTlsNamedGroup.Secp256r1, validSecpKeyShare),
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    AssertFatalAlert32(firstUpdates, driver);
                    break;
                }

                default:
                {
                    ushort[] supportedGroups = Shuffle(
                        random,
                        [(ushort)QuicTlsNamedGroup.Secp256r1, (ushort)0x001D]);
                    ClientHelloKeyShareEntry[] keyShareEntries = Shuffle(
                        random,
                        [
                            new ClientHelloKeyShareEntry(0x001D, x25519KeyShare),
                            new ClientHelloKeyShareEntry(0x11EC, hybridKeyShare),
                        ]);

                    firstUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    Assert.Equal(2, firstUpdates.Count);
                    Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, firstUpdates[1].Kind);

                    IReadOnlyList<QuicTlsStateUpdate> repeatedRetryUpdates = driver.ProcessCryptoFrame(
                        QuicTlsEncryptionLevel.Initial,
                        CreateClientHelloTranscriptWithKeyShareEntries(
                            REQ_QUIC_CRT_0112.CreateClientTransportParameters(),
                            supportedGroups,
                            keyShareEntries));

                    AssertFatalAlert32(repeatedRetryUpdates, driver);
                    break;
                }
            }
        }
    }

    private static QuicTlsTransportBridgeDriver CreateStartedServerDriver()
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Server,
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22));
        _ = driver.StartHandshake(REQ_QUIC_CRT_0112.CreateBootstrapLocalTransportParameters());
        return driver;
    }

    private static QuicConnectionRuntime CreateServerRuntimeForCapturedHrrReplay(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            localHandshakePrivateKey: REQ_QUIC_CRT_0112.CreateScalar(0x22),
            tlsRole: QuicTlsRole.Server);
        QuicTransportParameters localTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(serverSourceConnectionId);
        localTransportParameters.OriginalDestinationConnectionId = originalDestinationConnectionId.ToArray();

        Assert.True(runtime.TryConfigureInitialPacketProtection(originalDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId([]));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(serverSourceConnectionId));
        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 0).StateChanged);
        return runtime;
    }

    private static QuicCryptoFrame OpenInitialCryptoFrame(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> datagram)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator clientCoordinator = new(
            originalDestinationConnectionId.ToArray(),
            sourceConnectionId: ReadOnlyMemory<byte>.Empty);
        Assert.True(clientCoordinator.TryOpenInitialPacket(
            datagram,
            clientProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicCryptoFrame cryptoFrame,
            out _));
        return cryptoFrame;
    }

    private static string DescribeClientInitialCryptoFrames(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> datagram)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            originalDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));
        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            datagram,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        List<string> frames = [];
        int offset = payloadOffset;
        int payloadEnd = payloadOffset + payloadLength;
        while (offset < payloadEnd)
        {
            ReadOnlySpan<byte> remaining = openedPacket.AsSpan(offset, payloadEnd - offset);
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                break;
            }

            frames.Add($"{cryptoFrame.Offset}+{cryptoFrame.CryptoData.Length}");
            offset += bytesConsumed;
        }

        return string.Join(",", frames);
    }

    private static byte[] FromHexLines(params string[] lines)
    {
        return Convert.FromHexString(string.Concat(lines));
    }

    private static void AssertFatalAlert32(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsTransportBridgeDriver driver)
    {
        Assert.Single(updates);
        Assert.Equal(QuicTlsUpdateKind.FatalAlert, updates[0].Kind);
        Assert.Equal((ushort)0x0032, updates[0].AlertDescription);
        Assert.True(driver.State.IsTerminal);
    }

    private static byte[][] CreateCapturedQuicGoClientInitialPacketsWithZeroSourceConnectionId(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> clientHello)
    {
        return CreateClientInitialPacketsWithZeroSourceConnectionId(originalDestinationConnectionId, clientHello);
    }

    private static byte[][] CreateClientInitialPacketsWithZeroSourceConnectionId(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> clientHello)
    {
        const int FirstPacketClientHelloBytes = 1024;

        Assert.False(clientHello.IsEmpty);
        List<byte[]> packets = [];
        int offset = 0;
        uint packetNumber = 0;

        while (offset < clientHello.Length)
        {
            int cryptoBytes = Math.Min(FirstPacketClientHelloBytes, clientHello.Length - offset);
            packets.Add(BuildProtectedClientInitialPacket(
                initialProtectionConnectionId: originalDestinationConnectionId,
                packetDestinationConnectionId: originalDestinationConnectionId,
                cryptoPayload: clientHello.Slice(offset, cryptoBytes),
                cryptoPayloadOffset: (ulong)offset,
                packetNumber: packetNumber));
            offset += cryptoBytes;
            packetNumber++;
        }

        return packets.ToArray();
    }

    private static byte[] BuildProtectedClientInitialPacket(
        ReadOnlySpan<byte> initialProtectionConnectionId,
        ReadOnlySpan<byte> packetDestinationConnectionId,
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        uint packetNumber)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialProtectionConnectionId,
            out QuicInitialPacketProtection clientProtection));

        byte[] cryptoFramePayload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(cryptoPayloadOffset, cryptoPayload));
        byte[] packetNumberBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(packetNumberBytes, packetNumber);
        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            packetDestinationConnectionId,
            sourceConnectionId: [],
            token: [],
            packetNumber: packetNumberBytes,
            plaintextPayload: cryptoFramePayload);

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(clientProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        return protectedPacket[..protectedBytesWritten].ToArray();
    }

    private static bool IsPacketNumberSpace(
        QuicConnectionSendDatagramEffect effect,
        QuicPacketNumberSpace packetNumberSpace)
    {
        return QuicPacketParser.TryGetPacketNumberSpace(effect.Datagram.Span, out QuicPacketNumberSpace observedPacketNumberSpace)
            && observedPacketNumberSpace == packetNumberSpace;
    }

    private static string DescribeRuntimeResult(
        QuicConnectionRuntime runtime,
        QuicConnectionTransitionResult result)
    {
        return string.Join(
            " | ",
            [
                $"phase={runtime.Phase}",
                $"peerHandshakeComplete={runtime.PeerHandshakeTranscriptCompleted}",
                $"initialKeys={runtime.TlsState.InitialKeysAvailable}",
                $"handshakeKeys={runtime.TlsState.HandshakeKeysAvailable}",
                $"initialIngressNext={runtime.TlsState.InitialIngressCryptoBuffer.NextReadOffset}",
                $"initialIngress={runtime.TlsState.InitialIngressCryptoBuffer.BufferedBytes}",
                $"initialEgress={runtime.TlsState.InitialEgressCryptoBuffer.BufferedBytes}",
                $"initialDiscarding={runtime.TlsState.InitialEgressCryptoBuffer.DiscardingFutureFrames}",
                $"stagedPeerTp={(runtime.TlsState.StagedPeerTransportParameters is null ? "<null>" : "set")}",
                $"effects={string.Join(",", result.Effects.Select(static effect => effect.GetType().Name))}",
            ]);
    }

    private static string DescribeUpdates(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        QuicTlsTransportBridgeDriver driver)
    {
        return string.Join(
            " | ",
            [
                $"count={updates.Count}",
                $"kinds={string.Join(",", updates.Select(update => update.Kind))}",
                $"alerts={string.Join(",", updates.Where(update => update.AlertDescription.HasValue).Select(update => $"0x{update.AlertDescription!.Value:X4}"))}",
                $"terminal={driver.State.IsTerminal}",
                $"phase={driver.State.HandshakeTranscriptPhase}",
                $"message={driver.State.HandshakeMessageType?.ToString() ?? "<null>"}",
                $"selectedCipher={driver.State.SelectedCipherSuite?.ToString() ?? "<null>"}",
                $"hash={driver.State.TranscriptHashAlgorithm?.ToString() ?? "<null>"}",
            ]);
    }

    private static byte[] CreateClientHelloTranscriptWithKeyShareEntries(
        QuicTransportParameters transportParameters,
        IReadOnlyList<ushort> supportedGroups,
        IReadOnlyList<ClientHelloKeyShareEntry> keyShareEntries,
        IReadOnlyList<byte[]>? applicationProtocols = null)
    {
        byte[] supportedVersionsExtension = CreateClientSupportedVersionsExtension();
        byte[]? applicationProtocolsExtension = applicationProtocols is { Count: > 0 }
            ? CreateClientApplicationProtocolNegotiationExtension(applicationProtocols)
            : null;
        byte[] supportedGroupsExtension = CreateClientSupportedGroupsExtension(supportedGroups);
        byte[] keyShareExtension = CreateClientKeyShareExtension(keyShareEntries);
        byte[] transportParametersExtension = CreateTransportParametersExtension(
            transportParameters,
            QuicTransportParameterRole.Client);

        int extensionsLength = supportedVersionsExtension.Length
            + (applicationProtocolsExtension?.Length ?? 0)
            + supportedGroupsExtension.Length
            + keyShareExtension.Length
            + transportParametersExtension.Length;
        byte[] body = new byte[43 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), 0x0303);
        index += 2;
        REQ_QUIC_CRT_0112.CreateSequentialBytes(0x10, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;
        body[index++] = 0;

        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256);
        index += 2;

        body[index++] = 1;
        body[index++] = 0x00;
        WriteUInt16(body.AsSpan(index, 2), checked((ushort)extensionsLength));
        index += 2;

        supportedVersionsExtension.CopyTo(body.AsSpan(index));
        index += supportedVersionsExtension.Length;
        applicationProtocolsExtension?.CopyTo(body.AsSpan(index));
        index += applicationProtocolsExtension?.Length ?? 0;
        supportedGroupsExtension.CopyTo(body.AsSpan(index));
        index += supportedGroupsExtension.Length;
        keyShareExtension.CopyTo(body.AsSpan(index));
        index += keyShareExtension.Length;
        transportParametersExtension.CopyTo(body.AsSpan(index));

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ClientHello, body);
    }

    private static byte[] CreateClientSupportedVersionsExtension()
    {
        byte[] extension = new byte[2 + 2 + 1 + 2];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x002B);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), 3);
        index += 2;
        extension[index++] = 2;
        WriteUInt16(extension.AsSpan(index, 2), Tls13Version);
        return extension;
    }

    private static byte[] CreateClientApplicationProtocolNegotiationExtension(IReadOnlyList<byte[]> applicationProtocols)
    {
        int protocolListLength = 0;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            protocolListLength += 1 + applicationProtocol.Length;
        }

        byte[] extension = new byte[2 + 2 + 2 + protocolListLength];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0010);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + protocolListLength)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)protocolListLength));
        index += 2;
        foreach (byte[] applicationProtocol in applicationProtocols)
        {
            extension[index++] = checked((byte)applicationProtocol.Length);
            applicationProtocol.CopyTo(extension.AsSpan(index));
            index += applicationProtocol.Length;
        }

        return extension;
    }

    private static byte[] CreateClientSupportedGroupsExtension(IReadOnlyList<ushort> supportedGroups)
    {
        byte[] extension = new byte[2 + 2 + 2 + (supportedGroups.Count * 2)];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x000A);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + (supportedGroups.Count * 2))));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(supportedGroups.Count * 2)));
        index += 2;
        foreach (ushort supportedGroup in supportedGroups)
        {
            WriteUInt16(extension.AsSpan(index, 2), supportedGroup);
            index += 2;
        }

        return extension;
    }

    private static byte[] CreateClientKeyShareExtension(IReadOnlyList<ClientHelloKeyShareEntry> keyShareEntries)
    {
        int keyShareVectorLength = 0;
        foreach (ClientHelloKeyShareEntry keyShareEntry in keyShareEntries)
        {
            keyShareVectorLength += 2 + 2 + keyShareEntry.KeyExchange.Length;
        }

        byte[] extension = new byte[2 + 2 + 2 + keyShareVectorLength];
        int index = 0;
        WriteUInt16(extension.AsSpan(index, 2), 0x0033);
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)(2 + keyShareVectorLength)));
        index += 2;
        WriteUInt16(extension.AsSpan(index, 2), checked((ushort)keyShareVectorLength));
        index += 2;

        foreach (ClientHelloKeyShareEntry keyShareEntry in keyShareEntries)
        {
            WriteUInt16(extension.AsSpan(index, 2), keyShareEntry.NamedGroup);
            index += 2;
            WriteUInt16(extension.AsSpan(index, 2), checked((ushort)keyShareEntry.KeyExchange.Length));
            index += 2;
            keyShareEntry.KeyExchange.CopyTo(extension.AsSpan(index));
            index += keyShareEntry.KeyExchange.Length;
        }

        return extension;
    }

    private static byte[] CreateTransportParametersExtension(
        QuicTransportParameters transportParameters,
        QuicTransportParameterRole role)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            role,
            encodedTransportParameters,
            out int bytesWritten));

        byte[] extension = new byte[4 + bytesWritten];
        WriteUInt16(extension.AsSpan(0, 2), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        WriteUInt16(extension.AsSpan(2, 2), (ushort)bytesWritten);
        encodedTransportParameters.AsSpan(0, bytesWritten).CopyTo(extension.AsSpan(4));
        return extension;
    }

    private static byte[] CreateValidSecp256r1KeyShare(byte scalarTail)
    {
        using ECDiffieHellman clientKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        clientKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = REQ_QUIC_CRT_0112.CreateScalar(scalarTail),
        });

        ECParameters parameters = clientKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[65];
        keyShare[0] = 0x04;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    private static byte[] GetClientHelloSessionId(ReadOnlySpan<byte> clientHelloBytes)
    {
        int index = 4;
        index += 2 + 32;
        int sessionIdLength = clientHelloBytes[index++];
        byte[] sessionId = clientHelloBytes.Slice(index, sessionIdLength).ToArray();
        return sessionId;
    }

    private static HelloRetryRequestDescription ParseHelloRetryRequest(ReadOnlySpan<byte> helloRetryRequestBytes)
    {
        Assert.True(helloRetryRequestBytes.Length >= 4);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.ServerHello, helloRetryRequestBytes[0]);

        int index = 4;
        Assert.Equal(0x0303, ReadUInt16(helloRetryRequestBytes, ref index));

        byte[] random = helloRetryRequestBytes.Slice(index, 32).ToArray();
        index += 32;

        int sessionIdLength = helloRetryRequestBytes[index++];
        byte[] sessionId = helloRetryRequestBytes.Slice(index, sessionIdLength).ToArray();
        index += sessionIdLength;

        QuicTlsCipherSuite cipherSuite = (QuicTlsCipherSuite)ReadUInt16(helloRetryRequestBytes, ref index);
        Assert.Equal(0x00, helloRetryRequestBytes[index++]);

        int extensionsLength = ReadUInt16(helloRetryRequestBytes, ref index);
        int extensionsEnd = index + extensionsLength;
        ushort supportedVersion = 0;
        QuicTlsNamedGroup selectedGroup = 0;
        bool foundSupportedVersion = false;
        bool foundSelectedGroup = false;

        while (index < extensionsEnd)
        {
            ushort extensionType = ReadUInt16(helloRetryRequestBytes, ref index);
            int extensionLength = ReadUInt16(helloRetryRequestBytes, ref index);
            ReadOnlySpan<byte> extensionValue = helloRetryRequestBytes.Slice(index, extensionLength);
            index += extensionLength;

            switch (extensionType)
            {
                case 0x002B:
                    Assert.False(foundSupportedVersion);
                    Assert.Equal(sizeof(ushort), extensionLength);
                    int supportedVersionIndex = 0;
                    supportedVersion = ReadUInt16(extensionValue, ref supportedVersionIndex);
                    Assert.Equal(extensionLength, supportedVersionIndex);
                    foundSupportedVersion = true;
                    break;

                case 0x0033:
                {
                    Assert.False(foundSelectedGroup);
                    Assert.Equal(HelloRetryRequestSelectedGroupExtensionLength, extensionLength);
                    int selectedGroupIndex = 0;
                    selectedGroup = (QuicTlsNamedGroup)ReadUInt16(extensionValue, ref selectedGroupIndex);
                    Assert.Equal(extensionLength, selectedGroupIndex);
                    foundSelectedGroup = true;
                    break;
                }

                default:
                    Assert.Fail($"Unexpected HelloRetryRequest extension 0x{extensionType:X4}.");
                    break;
            }
        }

        Assert.Equal(extensionsEnd, index);
        Assert.True(foundSupportedVersion);
        Assert.True(foundSelectedGroup);
        return new HelloRetryRequestDescription(random, sessionId, cipherSuite, supportedVersion, selectedGroup);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> source, ref int index)
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(index, 2));
        index += 2;
        return value;
    }

    private static void WriteUInt16(Span<byte> destination, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, value);
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[4 + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, 3), body.Length);
        body.CopyTo(transcript.AsSpan(4));
        return transcript;
    }

    private static T[] Shuffle<T>(Random random, IReadOnlyList<T> source)
    {
        T[] result = new T[source.Count];
        for (int index = 0; index < source.Count; index++)
        {
            result[index] = source[index];
        }

        for (int index = result.Length - 1; index > 0; index--)
        {
            int swapIndex = random.Next(index + 1);
            (result[index], result[swapIndex]) = (result[swapIndex], result[index]);
        }

        return result;
    }

    private readonly record struct ClientHelloKeyShareEntry(
        ushort NamedGroup,
        byte[] KeyExchange);

    private readonly record struct HelloRetryRequestDescription(
        byte[] Random,
        byte[] SessionId,
        QuicTlsCipherSuite CipherSuite,
        ushort SupportedVersion,
        QuicTlsNamedGroup SelectedGroup);
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

public sealed class QuicCapturedInteropReplayTests
{
    private const int HashLength = 32;
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly string[] CapturedQuicGoServerHandshakeTrafficSecrets =
    [
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\debug-deterministic-refresh\20260420-133311751-client-chrome\
        //   runner-logs\quic-go_chrome\handshake\server\keys.log
        //
        // The preserved server log contains two deterministic handshake attempts for the same client_random.
        // The replayed server Initial flight must line up with one of these emitted secrets.
        "A99BF54108AEB69E8EEFD54BB0152EBCDEFF9DC01764B8A4D4DCBCD58D348525",
        "6ED1E010470329261635D5456FCE94B2F70F4596831A668AC61AF02BFBA9B854",
    ];
    private static readonly byte[] CapturedManagedClientCurrentTrafficSecret = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-handshake-repro-short-header-fix-classified\20260420-161914132-client-chrome\
        //   runner-logs\quic-go_chrome\handshake\server\keys.log
        "55042CC4BD45F07C476A7D792B66E3C318126DFBC28DD337DB2EDD053AFED8DA");
    private static readonly byte[] CapturedQuicGoIssuedConnectionId = Convert.FromHexString("325C86A6");
    private static readonly byte[] CapturedManagedClientSourceConnectionId = Convert.FromHexString("BD0B27A812A5E5F6");
    private static readonly byte[] CapturedQuicGoServerChosenConnectionId = Convert.FromHexString("E6F0A827");
    private static readonly byte[] CapturedQuicGoServerTrafficSecret = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-handshake-repro-after-fix\20260420-154518670-client-chrome\
        //   runner-logs\quic-go_chrome\handshake\server\keys.log
        "7AA5C0CFB97250D61E71581AD3BE14C0C94C4A6F3B8F5F82BE7ED63A4EB5D0C5");
    private static readonly byte[] CapturedManagedClientSmallPacketBeforeRequest = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-handshake-repro-short-header-fix-classified\20260420-161914132-client-chrome\
        //   runner-logs\quic-go_chrome\handshake\sim\trace_node_left.pcap
        // Packet 46: client -> server short 1-RTT packet, 57-byte UDP payload.
        "6E325C86A61C7F535104FD763E0AAF5225A3B5723126EE6B8A6F4FFDB7E9DFFF39024416320F6401A8D818B9BC3059AFFC454EC0A7B75392BB");
    private static readonly byte[] CapturedManagedClientRequestPacket = Convert.FromHexString(
        // Captured from the same repro pcap.
        // Packet 47: client -> server short 1-RTT packet carrying the HTTP/0.9 request bytes.
        "6D325C86A6F8B8727E565DA2E505C5851960882C7AB0712D4BD127ABDC779AA0D12B23D1361966AE368765D9A8134F9A252BE22C800DBB4255F9E173D41D44887CC2BDC62102C6CE3D65E176CD3AAA0B890272F5A7B3");
    private static readonly byte[] CapturedManagedClientSmallPacketAfterRequest = Convert.FromHexString(
        // Captured from the same repro pcap.
        // Packet 48: client -> server short 1-RTT packet, 57-byte UDP payload.
        "61325C86A6977479FA3F8A70EBDB972ACE132260AD37F56E474BEECEB88D2E43E93076ED62986AB24659341759FC7BBB98F2F9CA86B408C336");
    private static readonly byte[] CapturedQuicGoServerResponsePacket = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-handshake-repro-after-fix\20260420-154518670-client-chrome\
        //   runner-logs\quic-go_chrome\handshake\sim\trace_node_left.pcap
        // Packet 67: server -> client short 1-RTT packet carrying the first 1024 response bytes on stream 0.
        "5DBD0B27A812A5E5F6175918A7E2D8ABFEB125AAC439A493BF7DA2559F9D3192DE3D9C286B837BF490B6F707631AD101112A686A27F176E8DBCCC036DEAD83717CD5F2EDF53F948C02E6CB0D8723163B2EDA83412CA58AB16E274318BC87D72DC497499E92E0FE3B4CCAEE3AB25B43D20CB4752BD11F13F5EDC2C2806148768405A80AB9F8EE712AB7F14924264E1458F6FB90A0E931DB83B80300BB8A61E4B502FA79533F838F2BCD8EEBEDE2D84AF7EAD440870580A65024BF2AEC3F5232EC5B9EF5071EED8AA1F5625160BC2AB40EF8111ADF9C75895881A07550CC619FCD3CB0B97619ADDB5A0BDA6A56D01CA8DE2D59CA75A05847160252F437A4EC65B4AAC85A2D0E5AF176859C84EB0889B996A650522D4F59A42866A2C46FD5558F54EA5DA76EBFEABF981AFEEF464B69337EEA19CB64CE58FC89F84B063DED974CFF3672B72904CF91F912695949E2B328F6007A490D170FA50D55835905766894F2D31C8FA16836B29128B8301A5D447F72CF05EF1FE70A161412C16D922C177398A8B8211309227018AD137E63932C059E498ABB19D32F40B8E8A3D27C7683B4425B769A72AC49F8D9A24788921E20BC0E585FC93096D60E1A423004628A84FFBEB6D43D80A067D74F7E8DE67F29C03A88ECD96E0233FAE2F26C68FED0817D2313CB910209815CE2EB898713B5D291050FB4BDD1B8BF7DCB069B94BFEB268632F121F13CE9CBA7D1E081A730BD77F386C85BAFD01DFBBC540D102D4864E757482D8503A70AA8005B2B8117D4AA0C72FDFFD9BA7D0959E9FCC2A114470BE6359963AE63F4BF8CBBF9B5DDDA69566C2BFC9666368086930979DE1B57A9E97BA54B5D080C243327D64E49C834CFEC35A3F9340B4A1632E21C25F57502E270AF79F40BD966C0BFE181842E5DFD3609652C10B67CE1449DE33B0DB1F7319688A2583079A404AFBA4E242AFC2B3886B3BCF8BFBA7B0D6CBF8AFBF69B00A4FC6FA484EE11C2ECE157715CD59CB2FE170037D5D041B61B4A259C4FE21401DE7137998897DC53AC1BF60E5538D923117E6E844011F74D1A13C7734AE07813980E3F3694A4CBCE1C7F5BDC116908E8A544197249FB1DEF480F586DBEEC012E2325EDE7B01886972B82A3B5481A103A6F0709D8AF1E1057538F213809D4B157AD7AD887B191CD619A6F829D3D8FF19B5BE8506C13947CBB9A1D4513D5D8B27F9B28BB1A078F2E35DCCF94B425B2B37E1C0B881603B9A35DDF8A8CDC54B41BD1667967F9F94E84C0DB8C9503D18DCA87A8607DA15D9CCBAC78FA56454C500065827556782A36AB37516DB016842F478CD1D269A25F122075CD60E8CD6AFE31AE54D1DC539911CB7387289FC227178DABF2354DEE54F900B89B7137B0C4335FD76B5C010C6492FF71199BB3E5785497915682BF436C5CF860871265B7EF7E49863864A13152842668D4248FDB831E225BADBD56F4D146F9AE0A6130F839EC42389529A16E");
    private static readonly byte[] CapturedQuicGoServerResponseFinPacket = Convert.FromHexString(
        // Captured from the same repro pcap.
        // Packet 68: server -> client short 1-RTT FIN-only STREAM packet for stream 0.
        "48BD0B27A812A5E5F6C224A783A2B1295ECCC1ACBBEB429A6B00C5578336AA");
    private static readonly byte[] CapturedManagedClientOriginalInitialDestinationConnectionIdForRetry = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-retry-repro\20260420-184749312-client-chrome\
        //   runner-logs\quic-go_chrome\retry\sim\trace_node_left.pcap
        // Packet 46: client -> server Initial packet before Retry.
        "AACF05E43CC63FF5");
    private static readonly byte[] CapturedQuicGoRetrySourceConnectionId = Convert.FromHexString("4274E8CE");
    private static readonly byte[] CapturedQuicGoRetryPacket = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-retry-repro\20260420-184749312-client-chrome\
        //   runner-logs\quic-go_chrome\retry\sim\trace_node_left.pcap
        // Packet 47: server -> client Retry packet.
        "F0000000010888B72C24D21FF97C044274E8CEEA5944A5B83A19629A69A7242056B907AD648E374D790C57AADB84B45E034C38A894A0E32C4CDF469C922B5CB456A05A94358EDF537D730AFF561A24E74BF3ADE2DF2710F8CBE5B67915A092F5EE34254EDC00FD518792833BB8A88DC20EE01EC1905140ABDFBA1B3C6EDAC12DFF2CF7783341FB81");
    private static readonly byte[] CapturedManagedClientRetriedInitialPacket = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\artifacts\client-retry-repro\20260420-184749312-client-chrome\
        //   runner-logs\quic-go_chrome\retry\sim\trace_node_left.pcap
        // Packet 48: client -> server replayed Initial packet that follows the Retry.
        "C700000001044274E8CE0888B72C24D21FF97C4065EA5944A5B83A19629A69A7242056B907AD648E374D790C57AADB84B45E034C38A894A0E32C4CDF469C922B5CB456A05A94358EDF537D730AFF561A24E74BF3ADE2DF2710F8CBE5B67915A092F5EE34254EDC00FD518792833BB8A88DC20EE01EC1905140AB449A93981243EA133BA9AE4294E5A4F062239554F12CD22A2257A6C47EBA6375C2CD4CA0A9330BCF3AA1D154DE83E8923286B8AB177C539F16D819FAE6F5CD5AA99D616F0A2142A40F5CF05314F8DFEADB7C528CAF38B51BC0A35067F53DAA95AFE4B1B86403DE9311BA9E7F4AF4CE0C9B0D456497C498BD4E88BE4B748D2EB4221542A284240846CD2C1E7D98DB126693D9080572027A9D15BACE4B1D34492B75E459C0287F63FDBCD4393431D267917EE9CAEC550535ABE9617FF4E6EDACFFCC693520EB86047FD83BE284755C8B4D5EFE5F4C37BE62D82121C5EF648E9ACBDDCB5C519544006475FA4DA3EC6476FD1444E1AF94B42F722ACE36BECC0B9FB1F8E7BCFCC8DC80F89BBC62475BD4B443520AC7FB3449A378750EF736DC8680F20632F4E51F7C68D5A39E3A29A066C726F8E1231D8515ED4AB3878D5C928FC450360EE8294433F3383FA4DB0B5FAFF26882D86912E3AEB5963A5674DAEF16EE240D755A5B3AC3E41AD9B53B48DA4B29CFA403DB14DDC2DBDE9862A0E1FE0DD1A224BB01FF0A2A8B712610ABAF8907E05704FCD211291429A79D86C61BF22F79CE0EB4ECF0B7088FFB3DA38FFD834C12A3C0BAFB4E5D95D384A4841F2FFAD1FCA1AB0A53D346191718357A603B03C16F970FCB2211B5BFE300CE754848635BE06CC82187A3FC5CD3C3A0BF89F7793355D3DB71AE216744F4FD0F0D264208FE227E39BEA01DCA4A565713F3B5A7CBB2E157246EB1C41B648043E8C1957DCC4F63A5DE7EBBF46D600AF05DE437D0DCE9B0C38DEE51F0CABFA09FE072445963FE494AA7AA8D095E135246C7EE70A9822F586B317ABF773A36EA03AE4DF5180FB71FF68489632DAA509EEA642E236B9840801C8A2F48286E8BC66405AF2B37D35315A381BC3FC0752FBDD6B2C66FF9E0EEC2D92D1998B8110811FFB4B56FC8BCE186AE4CB7AE49EEEF82D56496FEA7DB2C54E21D10B753393819BC14EEFB37620309EC988C8C551039DFC60BA18974E68FEA8E5969C0E80DF3D4911EC12B8D98886ACE8583524B994FB20B0AF0B38DCA825F2408BAD8EC5E328C786BA5CA98071228373D03C88F232D7FA2AC899C04FBB700B279885757A51185DC3A403DE86528D7842EDE87C5BED5D990F7529F66DB353F772CE15005859C0DCA94E36A1BDF05ACE6790D84EA20450B08359DAEAE2477CA7CAB77C7E1665800D3181DCAEF190D60027616A2FCFFDDFD9E133291B1784D62DA3A2D7108008C6FEB0D55CB88F021A3F112F06C9435B4493A6FA8CCE1BF56F40551AB139E4BE7ABA33FF6364F6AFBBCDA9F0D7E5D3B436BCE7C111002132631F6B4A44A7D98A7FE26C54D6BF1E514C8E7DCA3D62ADB18EE6D0C3750518A34194A9AD871993C8FD19F30C846C1BE22B422EF69AC9B7E9DF3C4E529C26E531EF511A259272AC61F78B9F87957F570557A7EDA96D05066E38C6A2E8AE7D0BB1E0D0E2D63FF8C7A08C2F5EE87E4CF9E96608DC9FBEF8D946BB5D91630453219565BC093F9851FA9664FD9C9FBC2495E47B1CC476A0E5FA536A3CAB0CDE6951475E40BF3E65D226C97456693A6BEA773398619B5585C2B9C1AAAF75E8AF4C934D7E0D4A8ED1F06382A8DBE29D2138A941F399744F62ED60387F4315E9CDB34BE76ABB96B8CB5EC184E5C8E64983C55");

    [Fact]
    public void DeterministicBootstrapMatchesCapturedInteropClientInitialPlaintextPacket()
    {
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        Assert.Equal(1200, scenario.CapturedClientInitialDatagram.Length);
        Assert.Equal(scenario.CapturedClientInitialDatagram.Length, scenario.BootstrapClientInitialDatagram.Length);
        Assert.Equal(scenario.CapturedClientInitialPlaintextPacket, scenario.BootstrapClientInitialPlaintextPacket);
    }

    [Fact]
    public void CapturedQuicGoServerInitialPacketInstallsHandshakeOpenMaterial()
    {
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: 10);

        string detail = DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, initialResult);

        Assert.True(initialResult.StateChanged, detail);
        Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable, detail);
        Assert.True(scenario.ClientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _), detail);
    }

    [Fact]
    public void CapturedQuicGoServerInitialPacketDerivesHandshakeOpenMaterialThatMatchesServerKeyLog()
    {
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: 10);

        Assert.True(initialResult.StateChanged, DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, initialResult));
        Assert.True(scenario.ClientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial openMaterial));

        List<string> candidateMaterialDescriptions = [];
        bool matchedLoggedSecret = false;
        foreach (string serverHandshakeTrafficSecretHex in CapturedQuicGoServerHandshakeTrafficSecrets)
        {
            byte[] serverHandshakeTrafficSecret = Convert.FromHexString(serverHandshakeTrafficSecretHex);
            Assert.True(TryCreateHandshakePacketProtectionMaterial(serverHandshakeTrafficSecret, out QuicTlsPacketProtectionMaterial expectedOpenMaterial));
            candidateMaterialDescriptions.Add(
                $"secret={serverHandshakeTrafficSecretHex} " +
                $"key={Convert.ToHexString(expectedOpenMaterial.AeadKey.ToArray())} " +
                $"iv={Convert.ToHexString(expectedOpenMaterial.AeadIv.ToArray())} " +
                $"hp={Convert.ToHexString(expectedOpenMaterial.HeaderProtectionKey.ToArray())}");

            if (MaterialsMatch(expectedOpenMaterial, openMaterial))
            {
                matchedLoggedSecret = true;
                break;
            }
        }

        Assert.True(
            matchedLoggedSecret,
            $"actualKey={Convert.ToHexString(openMaterial.AeadKey.ToArray())} " +
            $"actualIv={Convert.ToHexString(openMaterial.AeadIv.ToArray())} " +
            $"actualHp={Convert.ToHexString(openMaterial.HeaderProtectionKey.ToArray())} " +
            $"candidates={string.Join(" || ", candidateMaterialDescriptions)}");
    }

    [Fact]
    public void CapturedQuicGoServerHandshakePacketCommitsPeerTransportParameters()
    {
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: 10);
        Assert.True(initialResult.StateChanged, DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, initialResult));

        QuicConnectionTransitionResult handshakeResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerHandshakePacket),
            nowTicks: 11);

        string detail = DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, handshakeResult);

        Assert.True(handshakeResult.StateChanged, detail);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted, detail);
    }

    [Fact]
    public void CapturedQuicGoRetryPacketRetainsValidRetryBootstrapMetadata()
    {
        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(
            CapturedManagedClientOriginalInitialDestinationConnectionIdForRetry,
            CapturedQuicGoRetryPacket));
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            CapturedManagedClientOriginalInitialDestinationConnectionIdForRetry,
            CapturedQuicGoRetryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));

        Assert.Equal(CapturedQuicGoRetrySourceConnectionId, retryMetadata.RetrySourceConnectionId);
        Assert.NotEmpty(retryMetadata.RetryToken);
    }

    [Fact]
    public void CapturedManagedClientRetriedInitialNeedsTheRetrySelectedInitialKeysToOpen()
    {
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            CapturedManagedClientOriginalInitialDestinationConnectionIdForRetry,
            CapturedQuicGoRetryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            CapturedManagedClientOriginalInitialDestinationConnectionIdForRetry,
            out QuicInitialPacketProtection originalServerProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            retryMetadata.RetrySourceConnectionId,
            out QuicInitialPacketProtection retryServerProtection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.False(coordinator.TryOpenInitialPacket(
            CapturedManagedClientRetriedInitialPacket,
            originalServerProtection,
            out _,
            out _,
            out _));
        Assert.True(coordinator.TryOpenInitialPacket(
            CapturedManagedClientRetriedInitialPacket,
            retryServerProtection,
            out byte[] openedPacket,
            out _,
            out _));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out _,
            out uint replayVersion,
            out ReadOnlySpan<byte> replayDestinationConnectionId,
            out _,
            out ReadOnlySpan<byte> replayVersionSpecificData));
        Assert.Equal(1u, replayVersion);
        Assert.Equal(retryMetadata.RetrySourceConnectionId, replayDestinationConnectionId.ToArray());
        Assert.True(QuicVariableLengthInteger.TryParse(
            replayVersionSpecificData,
            out ulong retryTokenLength,
            out int retryTokenLengthBytes));
        Assert.Equal((ulong)retryMetadata.RetryToken.Length, retryTokenLength);
        Assert.True(retryMetadata.RetryToken.AsSpan().SequenceEqual(
            replayVersionSpecificData.Slice(retryTokenLengthBytes, retryMetadata.RetryToken.Length)));
    }

    [Fact]
    public void CapturedQuicGoServerResponsePacketNeedsTheInboundLocalConnectionIdLengthToOpen()
    {
        Assert.True(TryCreateOneRttPacketProtectionMaterial(
            CapturedQuicGoServerTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        QuicHandshakeFlowCoordinator incompleteCoordinator = new(CapturedQuicGoServerChosenConnectionId);
        Assert.False(incompleteCoordinator.TryOpenProtectedApplicationDataPacket(
            CapturedQuicGoServerResponsePacket,
            openMaterial,
            out _,
            out _,
            out _,
            out _));

        QuicHandshakeFlowCoordinator coordinator = new(
            CapturedQuicGoServerChosenConnectionId,
            CapturedManagedClientSourceConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            CapturedQuicGoServerResponsePacket,
            openMaterial,
            out _,
            out _,
            out _,
            out bool observedKeyPhase));
        Assert.False(observedKeyPhase);
    }

    [Fact]
    public void CapturedManagedClientRequestPacketCanBeOpenedWithRecordedClientTrafficSecret()
    {
        OpenCapturedClientApplicationPacket(
            CapturedManagedClientRequestPacket,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out _);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame streamFrame));
        Assert.Equal(0UL, streamFrame.StreamId.Value);
        Assert.Equal(0UL, streamFrame.Offset);
        Assert.False(streamFrame.IsFin);
        Assert.Equal("GET /excessive-quiet-mewtwo\r\n", Encoding.ASCII.GetString(streamFrame.StreamData));
    }

    [Fact]
    public void CapturedManagedClientPacketsUseConsecutivePacketNumbersAcrossOpenWriteAndFinish()
    {
        Assert.Equal(0U, GetCapturedClientApplicationPacketNumber(CapturedManagedClientSmallPacketBeforeRequest));
        Assert.Equal(1U, GetCapturedClientApplicationPacketNumber(CapturedManagedClientRequestPacket));
        Assert.Equal(2U, GetCapturedClientApplicationPacketNumber(CapturedManagedClientSmallPacketAfterRequest));
    }

    [Fact]
    public void CapturedManagedClientSmallPacketBeforeRequestReplaysAsAnEmptyStreamOpenFollowedByPadding()
    {
        Assert.Equal(
            "stream(id=0,off=0,len=0,fin=False,data=),padding(29)",
            DescribeCapturedClientApplicationFrames(CapturedManagedClientSmallPacketBeforeRequest));
    }

    [Fact]
    public void CapturedManagedClientRequestPacketReplaysAsTheHttp09RequestStreamFrameFollowedByPadding()
    {
        Assert.Equal(
            "stream(id=0,off=0,len=29,fin=False,data=474554202F657863),padding(29)",
            DescribeCapturedClientApplicationFrames(CapturedManagedClientRequestPacket));
    }

    [Fact]
    public void CapturedManagedClientSmallPacketAfterRequestReplaysAsAFinOnlyStreamFrameFollowedByPadding()
    {
        Assert.Equal(
            "stream(id=0,off=29,len=0,fin=True,data=),padding(28)",
            DescribeCapturedClientApplicationFrames(CapturedManagedClientSmallPacketAfterRequest));
    }

    [Fact]
    public void CapturedQuicGoServerResponsePacketsReplayAsStreamDataThenFin()
    {
        Assert.Equal(
            "stream(id=0,off=0,len=1024,fin=False,data=16F4F0F2BA740F1D)",
            DescribeCapturedServerApplicationFrames(CapturedQuicGoServerResponsePacket));
        Assert.Equal(
            "stream(id=0,off=1024,len=0,fin=True,data=)",
            DescribeCapturedServerApplicationFrames(CapturedQuicGoServerResponseFinPacket));
    }

    [Fact]
    public void CapturedQuicGoTransferPacket77ReplaysAsStreamDataBlockedThenTheNextResponseChunk()
    {
        Assert.Equal(
            "stream_data_blocked(stream=0,max=83018),stream(id=0,off=82693,len=325,fin=False,data=D3BE139613F3A3DC)",
            DescribeCapturedTransferServerApplicationFrames(
                QuicCapturedInteropTransferEvidence.QuicGoTransferPacket77Protected));
    }

    [Fact]
    public void CapturedQuicGoTransferPacket83ReplaysAsNewTokenCryptoBlockedHandshakeDoneAndTheNextResponseChunk()
    {
        Assert.Equal(
            "new_token(len=89),crypto(off=0,len=170),stream_data_blocked(stream=0,max=83018),handshake_done,stream(id=0,off=82693,len=325,fin=False,data=D3BE139613F3A3DC)",
            DescribeCapturedTransferServerApplicationFrames(
                QuicCapturedInteropTransferEvidence.QuicGoTransferPacket83Protected));
    }

    [Fact]
    public void CapturedQuicGoTransferKeyUpdatePacket101ReplaysAsAckWhenTheCurrentHeaderProtectionKeyIsRetained()
    {
        Assert.Equal(
            "ack(largest=72,first=37,ranges=0)",
            DescribeCapturedTransferPhaseOneServerApplicationFrames(
                QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected));
    }

    [Fact]
    public void CapturedQuicGoTransferKeyUpdatePacket101DoesNotOpenWhenTheHeaderProtectionKeyAlsoRotates()
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateTransferPhaseOneServerOpenMaterialWithDerivedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial openMaterial));
        Assert.False(QuicCapturedInteropTransferEvidence.TryOpenTransferPhaseOneServerPacket(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected,
            openMaterial,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    public void CapturedQuicGoTransferKeyUpdatePacket102OpensWithTheRetainedCurrentHeaderProtectionKey()
    {
        Assert.NotEmpty(QuicCapturedInteropTransferEvidence.OpenTransferPhaseOneServerApplicationPayloadWithRetainedHeaderProtectionKey(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket102Protected));
    }

    private static string DescribeState(
        QuicConnectionRuntime runtime,
        QuicRecordingDiagnosticsSink diagnosticsSink,
        QuicConnectionTransitionResult result)
    {
        return string.Join(
            " | ",
            [
                $"stateChanged={result.StateChanged}",
                $"phase={runtime.Phase}",
                $"handshakeKeys={runtime.TlsState.HandshakeKeysAvailable}",
                $"handshakeOpenMaterial={runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _)}",
                $"handshakePhase={runtime.TlsState.HandshakeTranscriptPhase}",
                $"handshakeMessageType={runtime.TlsState.HandshakeMessageType?.ToString() ?? "<none>"}",
                $"peerFinishedVerified={runtime.TlsState.PeerFinishedVerified}",
                $"peerCertVerifyVerified={runtime.TlsState.PeerCertificateVerifyVerified}",
                $"peerCertPolicyAccepted={runtime.TlsState.PeerCertificatePolicyAccepted}",
                $"stagedPeerTransportParameters={(runtime.TlsState.StagedPeerTransportParameters is null ? "<null>" : "set")}",
                $"peerTransportParametersCommitted={runtime.TlsState.PeerTransportParametersCommitted}",
                $"terminal={runtime.TlsState.IsTerminal}",
                $"fatalAlert={runtime.TlsState.FatalAlertDescription?.ToString() ?? "<none>"}",
                $"effectDiagnostics={string.Join(" || ", result.Effects.OfType<QuicConnectionEmitDiagnosticEffect>().Select(static effect => $"{effect.Diagnostic.Name}: {effect.Diagnostic.Message}"))}",
                $"sinkDiagnostics={string.Join(" || ", diagnosticsSink.Events.Select(static diagnostic => $"{diagnostic.Name}: {diagnostic.Message}"))}",
            ]);
    }

    private static bool TryCreateHandshakePacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], 16);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out material);
    }

    private static bool TryCreateOneRttPacketProtectionMaterial(
        ReadOnlySpan<byte> trafficSecret,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], 16);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], 12);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], 16);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out material);
    }

    private static bool MaterialsMatch(in QuicTlsPacketProtectionMaterial left, in QuicTlsPacketProtectionMaterial right)
    {
        return left.EncryptionLevel == right.EncryptionLevel
            && left.Algorithm == right.Algorithm
            && BitConverter.DoubleToInt64Bits(left.UsageLimits.ConfidentialityLimitPackets) == BitConverter.DoubleToInt64Bits(right.UsageLimits.ConfidentialityLimitPackets)
            && BitConverter.DoubleToInt64Bits(left.UsageLimits.IntegrityLimitPackets) == BitConverter.DoubleToInt64Bits(right.UsageLimits.IntegrityLimitPackets)
            && left.AeadKey.SequenceEqual(right.AeadKey)
            && left.AeadIv.SequenceEqual(right.AeadIv)
            && left.HeaderProtectionKey.SequenceEqual(right.HeaderProtectionKey);
    }

    private static uint GetCapturedClientApplicationPacketNumber(ReadOnlySpan<byte> protectedPacket)
    {
        OpenCapturedClientApplicationPacket(
            protectedPacket,
            out byte[] openedPacket,
            out _,
            out _,
            out _);

        int packetNumberOffset = 1 + CapturedQuicGoIssuedConnectionId.Length;
        return BinaryPrimitives.ReadUInt32BigEndian(openedPacket.AsSpan(packetNumberOffset, sizeof(uint)));
    }

    private static string DescribeCapturedClientApplicationFrames(ReadOnlySpan<byte> protectedPacket)
    {
        OpenCapturedClientApplicationPacket(
            protectedPacket,
            out _,
            out int payloadOffset,
            out int payloadLength,
            out ReadOnlyMemory<byte> payloadMemory);

        return DescribeFrames(payloadMemory.Span.Slice(payloadOffset, payloadLength));
    }

    private static string DescribeCapturedServerApplicationFrames(ReadOnlySpan<byte> protectedPacket)
    {
        OpenCapturedServerApplicationPacket(
            protectedPacket,
            out _,
            out int payloadOffset,
            out int payloadLength,
            out ReadOnlyMemory<byte> payloadMemory);

        return DescribeFrames(payloadMemory.Span.Slice(payloadOffset, payloadLength));
    }

    private static string DescribeCapturedTransferServerApplicationFrames(ReadOnlySpan<byte> protectedPacket)
    {
        return DescribeFrames(GetCapturedTransferServerApplicationPayload(protectedPacket));
    }

    private static string DescribeCapturedTransferPhaseOneServerApplicationFrames(ReadOnlySpan<byte> protectedPacket)
    {
        return DescribeFrames(
            QuicCapturedInteropTransferEvidence.OpenTransferPhaseOneServerApplicationPayloadWithRetainedHeaderProtectionKey(
                protectedPacket));
    }

    private static void OpenCapturedClientApplicationPacket(
        ReadOnlySpan<byte> protectedPacket,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out ReadOnlyMemory<byte> payloadMemory)
    {
        Assert.True(TryCreateOneRttPacketProtectionMaterial(
            CapturedManagedClientCurrentTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(CapturedQuicGoIssuedConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            openMaterial,
            out openedPacket,
            out payloadOffset,
            out payloadLength,
            out bool observedKeyPhase));
        Assert.False(observedKeyPhase);

        payloadMemory = openedPacket;
    }

    private static void OpenCapturedServerApplicationPacket(
        ReadOnlySpan<byte> protectedPacket,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out ReadOnlyMemory<byte> payloadMemory)
    {
        Assert.True(TryCreateOneRttPacketProtectionMaterial(
            CapturedQuicGoServerTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(
            CapturedQuicGoServerChosenConnectionId,
            CapturedManagedClientSourceConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            openMaterial,
            out openedPacket,
            out payloadOffset,
            out payloadLength,
            out bool observedKeyPhase));
        Assert.False(observedKeyPhase);

        payloadMemory = openedPacket;
    }

    private static byte[] GetCapturedTransferServerApplicationPayload(ReadOnlySpan<byte> protectedPacket)
    {
        return QuicCapturedInteropTransferEvidence.OpenServerApplicationPayload(protectedPacket);
    }

    private static string DescribeFrames(ReadOnlySpan<byte> payload)
    {
        StringBuilder description = new();
        int offset = 0;

        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            int paddingLength = 0;
            while (paddingLength < remaining.Length && remaining[paddingLength] == 0x00)
            {
                paddingLength++;
            }

            if (paddingLength > 0)
            {
                AppendFrameDescription(description, $"padding({paddingLength})");
                offset += paddingLength;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out QuicAckFrame ackFrame, out int ackBytesConsumed))
            {
                AppendFrameDescription(
                    description,
                    $"ack(largest={ackFrame.LargestAcknowledged},first={ackFrame.FirstAckRange},ranges={ackFrame.AdditionalRanges.Length})");
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseNewTokenFrame(remaining, out QuicNewTokenFrame newTokenFrame, out int newTokenBytesConsumed))
            {
                AppendFrameDescription(
                    description,
                    $"new_token(len={newTokenFrame.Token.Length})");
                offset += newTokenBytesConsumed;
                continue;
            }

            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                AppendFrameDescription(
                    description,
                    $"stream(id={streamFrame.StreamId.Value},off={streamFrame.Offset},len={streamFrame.StreamDataLength},fin={streamFrame.IsFin},data={Convert.ToHexString(streamFrame.StreamData[..Math.Min(streamFrame.StreamDataLength, 8)])})");
                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                AppendFrameDescription(description, "ping");
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed))
            {
                AppendFrameDescription(
                    description,
                    $"crypto(off={cryptoFrame.Offset},len={cryptoFrame.CryptoData.Length})");
                offset += cryptoBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseStreamDataBlockedFrame(remaining, out QuicStreamDataBlockedFrame streamDataBlockedFrame, out int streamDataBlockedBytesConsumed))
            {
                AppendFrameDescription(
                    description,
                    $"stream_data_blocked(stream={streamDataBlockedFrame.StreamId},max={streamDataBlockedFrame.MaximumStreamData})");
                offset += streamDataBlockedBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseHandshakeDoneFrame(remaining, out _, out int handshakeDoneBytesConsumed))
            {
                AppendFrameDescription(description, "handshake_done");
                offset += handshakeDoneBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseResetStreamFrame(remaining, out QuicResetStreamFrame resetStreamFrame, out int resetBytesConsumed))
            {
                AppendFrameDescription(
                    description,
                    $"reset_stream(id={resetStreamFrame.StreamId},final={resetStreamFrame.FinalSize})");
                offset += resetBytesConsumed;
                continue;
            }

            AppendFrameDescription(description, $"unknown(0x{remaining[0]:X2})");
            break;
        }

        return description.Length == 0 ? "<empty>" : description.ToString();
    }

    private static void AppendFrameDescription(StringBuilder description, string frameDescription)
    {
        if (description.Length > 0)
        {
            description.Append(',');
        }

        description.Append(frameDescription);
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        const int HkdfLengthFieldLength = sizeof(ushort);
        const int HkdfLabelLengthFieldLength = 1;
        const int HkdfContextLengthFieldLength = 1;
        const int HkdfExpandCounterLength = 1;
        const byte HkdfExpandCounterValue = 1;
        byte[] hkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");

        int hkdfLabelLength = HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + hkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength
            + context.Length;

        Span<byte> hkdfLabel = stackalloc byte[hkdfLabelLength];
        int index = 0;

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        index += HkdfLengthFieldLength;

        hkdfLabel[index++] = checked((byte)(hkdfLabelPrefix.Length + label.Length));
        hkdfLabelPrefix.CopyTo(hkdfLabel[index..]);
        index += hkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel[index..]);
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel[index..]);
        }

        byte[] expandInput = new byte[hkdfLabel.Length + HkdfExpandCounterLength];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = HkdfExpandCounterValue;

        using HMACSHA256 hmac = new(secret.ToArray());
        byte[] output = hmac.ComputeHash(expandInput);
        if (output.Length == length)
        {
            return output;
        }

        byte[] truncated = new byte[length];
        output.AsSpan(..length).CopyTo(truncated);
        return truncated;
    }
}

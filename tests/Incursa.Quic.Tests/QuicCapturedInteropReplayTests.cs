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
    private static readonly byte[] CapturedQuicGoMulticonnectOriginalInitialDestinationConnectionId = Convert.FromHexString("97484682953323E0");
    private static readonly byte[] CapturedQuicGoMulticonnectClientHandshakeRetransmission = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-stall\
        //   client-multiconnect-11a0e9f9cf014ab7bb861a240967f43d.qlog
        // Final contained-trace tuple 193.167.100.100:443|193.167.0.100:52643, client packet_sent time=10.
        "E900000001042FC84F0108AFABAAD4B0FE3CE03B368D1348DAFF7CB25CA3E85A3C613F6B3E49659ABAB723D7DD5862997483E9DD0E33F87D52934DF1384AF38252B721C60A3BAB0E27FE8B92E96CA4");
    private static readonly byte[] CapturedQuicGoMulticonnectClientInitialRetransmission = Convert.FromHexString(
        // Captured from the same preserved qlog.
        // Final contained-trace tuple 193.167.100.100:443|193.167.0.100:52643, client packet_sent time=9.
        "C200000001042FC84F0108AFABAAD4B0FE3CE000449A2E7D2F3110C8D91A367A90A45C60A672F32AA257B330E1EAF0C2BD9E84F65B102C033C346363AACC53FB32B054982DCADA2C8D362F242D8E4FFE3CFBDC23F9BF1FFC68B3CB13FFF6A6AAFB0766D41EFBF146452BE601932D494C6E052BE86F912F5CA8CA25F7D86C7045BF9D7FD3DFE62B3434D25766722290A7F68D7FB53EBFBFD83D18AED24BF4281C12A97E11E6150B0D3BD70874D2E2222EEF3E4DBF5730E9BDCB4051FD5563735C642E50EE604AA9B3923F4A4106D262FE428F77116A6088D0FD6571B38C949FBD0043DFB5A04BD32DFCCB3ED3F61317DBDBB6D21487212B46AD4D30D2BF170E431C92439C8FF7788F927981999AF60A480B0D54F2DC3FBF4E957B2481DBB57C0514FA291E447731A7616200D20A213F684AF1003523386074BB6314B8782015FC5121C065E3D0EB289DBD83569041076B786528D887ACA94CE5E11BCF194127D87F492817ADEC7B561CB47E279F04E3D68BDEFF27C05E03DCBA7718707CF312B21F676257081824D84B261F7931B0B707A2B08E652EF74858D19146BE5321127B074AA82E99D29A277C31674AB0864283F5BE757FA5F643F444CBB0C71367A6AEB94A8BF8CDB2DA3C4DE08C43DF0FD8D2FF498C57E07D33BB2351C69BE0A339CE73C0EF2E3244698896C66CA56E4138710BA04F0A864AC2EAB7FA737AB6A0C581CA8E7704FF60AB30F2A03A63451D29916D9035352F3E742047709BED3C296BF95EDC0E882597DCBE88BB3AB57BB3BDA7D3B9703DF46FC97DDDE8833AB16995120220C25FFDA5E63F787F07D98C38F0B9F732286740A10FE6755006DDE9CF15D77743E74EC58F6CF650E15F36F7566CE63D5F70E001DFD947125CE5865A576F7004C33130E3888FF84F1A1F73F328551F8277EB1F7F1EC8880F3DBFDA78BF50C1C1100B9EDF1010867BD90C87AD72E5F963C9153559E58D62353E0A69D51CD4D8E94555262C6BFE3F31674B79DE486038C50355473F274519B0B047C18DB663B8A48CC48645624BD2EED2EA695620627676A0F107AB0268CA5ED048CCAE324F38AD031C63B0174B18C425EBB7F52F27002B79B89B5F8F73ED64F22B5E2ED535D80F8A573103E9E37642DFCFF1FD30864B94A679F6667600A91F151271467FD240427B0CBC3C8BDD0CDB87A6D4733EF72956CAC417D99B9D80D607F3C2CD8F217732463082A9ADF1E1448B6DDF7C400E648FD460CFA8833610ED2393413D864EC560A23B0C1FF1092D4EC728C32888490EE94729C5228F3B7AC958359C19815A956F25FAFE529F09411F50ACD6346CD0CEB41FAB0FF99D10879F27382EC3F9DACBFF32C519E77CB56A5B4A194E5112924A37079E5E0D017D2EB478D6CA5671D1D7E8B7BEF3F7E27C890C73C7DEA1301A9D3940B40B6C3F267D449A7F26FE4D374C2FC231FB67762F127CE1C36776171A147AAB5EF4ABC6E41EA90EBC48A7BAC8DCF8CEFB24A35ED219A356C33ABE396B50255E9E419CD75680845455953C7B5DCCCC81B8FD6145B5ED78AF86E3754FB879F6F8D66892C2FD0C82E509883E1C1169B636EA149F2D0075E219D34ADC843B87C028CC641BB959A6FB0A48CC866D2CEAB7BB489ABF8B54186E0C6F0272A60E03231A58DF48A900CF9E81476590AC2485579D731258AB05D6D4AB49724D38B0C4");
    private static readonly byte[][] CapturedQuicGoMulticonnectClientHandshakeTrafficSecretCandidates =
    [
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-stall\
        //   server-keys.log
        // Tail candidates from the preserved quic-go server key log for the final multiconnect attempts.
        Convert.FromHexString("07A68A9A10577D3AA91E8E80C46F2A45E4FAFF1F7F71FF9B1046C6CB58E66026"),
        Convert.FromHexString("7648808F590BEFB2F545D596021BAACC9E5AF01014F13097ADE79A33B7354BC2"),
        Convert.FromHexString("FD0B0387B345AF3825D51B889E69D34D4D9B8CBAC5A2845864EA4DAB4E235978"),
        Convert.FromHexString("BA227DCC5A82F4B8E5033378E4618B2164BCD77B458E49A07A503E0C7660236D"),
    ];
    private static readonly byte[] CapturedCurrentMulticonnectIssuedConnectionId = Convert.FromHexString("0C2A5AB9");
    private static readonly byte[] CapturedCurrentMulticonnectClientTrafficSecret = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-regression\
        //   server-keys.log
        // CLIENT_TRAFFIC_SECRET_0 for the first stalled multiconnect connection.
        "7DC1AE4378C05772C86DB76BCAEC43041EA0706B0AC0AB61CC160CBDAD8D47F7");
    private static readonly byte[] CapturedCurrentMulticonnectOpenMarkerPacket = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet.local\interop-evidence\20260421-multiconnect-regression\
        //   trace_node_left.pcap
        // Client-facing packet 7: short-header 1-RTT stream-open marker that never reached the server-facing trace.
        "620C2A5AB911246E64D0DD0E9DE4884851848D307B8D9C47340A7CED481E16858DFA6AA0826657D56E9DD12DAF26E75E9BF5B406E970D13AA3");
    private static readonly byte[] CapturedCurrentMulticonnectRequestPacket = Convert.FromHexString(
        // Captured from the same preserved left-side simulator trace.
        // Client-facing packet 8: short-header 1-RTT packet that carries "GET /abundant-endless-ocelot\r\n".
        "650C2A5AB929BAAF3F43C5322B26F5CB56632C37E378231BA96A5F70D2AA2E3C1DCCBC9DC16C99DB7BF42383D7D25217107B506800341D3D453F1126AA790372015B9B9EDF6492D379AD7B59A8CAC3A3646D78C3596CB4");
    private static readonly byte[] CapturedCurrentMulticonnectFinOnlyPacket = Convert.FromHexString(
        // Captured from the same preserved left-side simulator trace.
        // Client-facing packet 9: short-header 1-RTT FIN-only close at final offset 30.
        "6C0C2A5AB9F2F7220D20B76B30800718B7D8DC0B4D82DA4AE42C8DFF1DEA0130B6B4FD43146C05189BA1364593794CBD2E2DEB48BB31834F57");

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
    public void CapturedQuicGoServerInitialPacketEmitsOnlyInitialReceiveDiagnosticsForItsOwnBytes()
    {
        using QuicCapturedInteropReplayTestSupport.CapturedInteropHandshakeScenario scenario =
            QuicCapturedInteropReplayTestSupport.CreateDeterministicQuicGoClientHandshakeScenario();

        int diagnosticCountBeforeInitial = scenario.DiagnosticsSink.Events.Count;
        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerInitialPacket),
            nowTicks: 10);

        string detail = DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, initialResult);
        QuicDiagnosticEvent[] newDiagnostics = scenario.DiagnosticsSink.Events
            .Skip(diagnosticCountBeforeInitial)
            .ToArray();

        Assert.True(initialResult.StateChanged, detail);
        Assert.Contains(newDiagnostics, diagnostic =>
            diagnostic.Kind == QuicDiagnosticKind.InitialPacketReceived
            && diagnostic.PacketBytes.Span.SequenceEqual(scenario.CapturedServerInitialPacket));
        Assert.DoesNotContain(newDiagnostics, diagnostic =>
            diagnostic.Kind == QuicDiagnosticKind.HandshakePacketReceived
            && diagnostic.PacketBytes.Span.SequenceEqual(scenario.CapturedServerInitialPacket));
    }

    [Fact]
    public void CapturedQuicGoServerHandshakePacketEmitsHandshakeDiagnosticsWithoutMislabelingItAsInitial()
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

        int diagnosticCountBeforeHandshake = scenario.DiagnosticsSink.Events.Count;
        QuicConnectionTransitionResult handshakeResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CapturedServerHandshakePacket),
            nowTicks: 11);

        string detail = DescribeState(scenario.ClientRuntime, scenario.DiagnosticsSink, handshakeResult);
        QuicDiagnosticEvent[] newDiagnostics = scenario.DiagnosticsSink.Events
            .Skip(diagnosticCountBeforeHandshake)
            .ToArray();

        Assert.True(handshakeResult.StateChanged, detail);
        Assert.Contains(newDiagnostics, diagnostic =>
            diagnostic.Kind == QuicDiagnosticKind.HandshakePacketReceived
            && diagnostic.PacketBytes.Span.SequenceEqual(scenario.CapturedServerHandshakePacket));
        Assert.DoesNotContain(newDiagnostics, diagnostic =>
            diagnostic.Kind == QuicDiagnosticKind.InitialPacketReceived
            && diagnostic.PacketBytes.Span.SequenceEqual(scenario.CapturedServerHandshakePacket));
        Assert.DoesNotContain(newDiagnostics, diagnostic =>
            diagnostic.Kind == QuicDiagnosticKind.InitialPacketOpenFailed
            && diagnostic.PacketBytes.Span.SequenceEqual(scenario.CapturedServerHandshakePacket));
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
    public void CapturedMulticonnectClientInitialRetransmissionStillOpensWithTheOriginalInitialKeysAfterTheVisibleDcidChanges()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            CapturedQuicGoMulticonnectOriginalInitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            CapturedQuicGoMulticonnectClientInitialRetransmission,
            serverProtection,
            out byte[] openedPacket,
            out _,
            out _));
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out _,
            out uint version,
            out ReadOnlySpan<byte> destinationConnectionId,
            out ReadOnlySpan<byte> sourceConnectionId,
            out _));

        Assert.Equal(1u, version);
        Assert.Equal("2FC84F01", Convert.ToHexString(destinationConnectionId));
        Assert.Equal("AFABAAD4B0FE3CE0", Convert.ToHexString(sourceConnectionId));
        Assert.NotEqual(
            Convert.ToHexString(CapturedQuicGoMulticonnectOriginalInitialDestinationConnectionId),
            Convert.ToHexString(destinationConnectionId));
    }

    [Fact]
    public void CapturedMulticonnectClientHandshakeRetransmissionOpensWithOneOfThePreservedServerKeyLogSecrets()
    {
        QuicHandshakeFlowCoordinator coordinator = new();

        foreach (byte[] trafficSecret in CapturedQuicGoMulticonnectClientHandshakeTrafficSecretCandidates)
        {
            Assert.True(TryCreateHandshakePacketProtectionMaterial(
                trafficSecret,
                out QuicTlsPacketProtectionMaterial openMaterial));

            if (!coordinator.TryOpenHandshakePacket(
                    CapturedQuicGoMulticonnectClientHandshakeRetransmission,
                    openMaterial,
                    out byte[] openedPacket,
                    out _,
                    out _))
            {
                continue;
            }

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out uint version,
                out ReadOnlySpan<byte> destinationConnectionId,
                out ReadOnlySpan<byte> sourceConnectionId,
                out _));
            Assert.Equal(1u, version);
            Assert.Equal("2FC84F01", Convert.ToHexString(destinationConnectionId));
            Assert.Equal("AFABAAD4B0FE3CE0", Convert.ToHexString(sourceConnectionId));
            return;
        }

        Assert.Fail("None of the preserved multiconnect client handshake traffic-secret candidates opened the captured client Handshake retransmission.");
    }

    [Fact]
    public void CapturedCurrentMulticonnectPacketsUseConsecutivePacketNumbersAcrossOpenRequestAndFin()
    {
        Assert.Equal(1U, GetCapturedCurrentMulticonnectPacketNumber(CapturedCurrentMulticonnectOpenMarkerPacket));
        Assert.Equal(2U, GetCapturedCurrentMulticonnectPacketNumber(CapturedCurrentMulticonnectRequestPacket));
        Assert.Equal(3U, GetCapturedCurrentMulticonnectPacketNumber(CapturedCurrentMulticonnectFinOnlyPacket));
    }

    [Fact]
    public void CapturedCurrentMulticonnectRequestPacketReplaysAsTheHttp09RequestFrame()
    {
        Assert.Equal(
            "stream(id=0,off=0,len=30,fin=False,data=474554202F616275),padding(29)",
            DescribeCapturedCurrentMulticonnectFrames(CapturedCurrentMulticonnectRequestPacket));
    }

    [Fact]
    public void CapturedCurrentMulticonnectFinOnlyPacketReplaysAsAFinOnlyCloseAtOffset30()
    {
        Assert.Equal(
            "stream(id=0,off=30,len=0,fin=True,data=),padding(28)",
            DescribeCapturedCurrentMulticonnectFrames(CapturedCurrentMulticonnectFinOnlyPacket));
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

    private static uint GetCapturedCurrentMulticonnectPacketNumber(ReadOnlySpan<byte> protectedPacket)
    {
        OpenCapturedCurrentMulticonnectPacket(
            protectedPacket,
            out byte[] openedPacket,
            out _,
            out _,
            out _);

        int packetNumberOffset = 1 + CapturedCurrentMulticonnectIssuedConnectionId.Length;
        return BinaryPrimitives.ReadUInt32BigEndian(openedPacket.AsSpan(packetNumberOffset, sizeof(uint)));
    }

    private static string DescribeCapturedCurrentMulticonnectFrames(ReadOnlySpan<byte> protectedPacket)
    {
        OpenCapturedCurrentMulticonnectPacket(
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

    private static void OpenCapturedCurrentMulticonnectPacket(
        ReadOnlySpan<byte> protectedPacket,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out ReadOnlyMemory<byte> payloadMemory)
    {
        Assert.True(TryCreateOneRttPacketProtectionMaterial(
            CapturedCurrentMulticonnectClientTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(CapturedCurrentMulticonnectIssuedConnectionId);
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

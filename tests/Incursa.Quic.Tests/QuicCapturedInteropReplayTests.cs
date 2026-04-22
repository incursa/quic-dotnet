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
    private static readonly byte[] CapturedCurrentMulticonnectReplacementOriginalInitialDestinationConnectionId = Convert.FromHexString("B12D1B38C43B37B5");
    private static readonly byte[] CapturedCurrentMulticonnectReplacementServerInitialPacket = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-165836034-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\client\qlog\client-multiconnect-058e8e6027214cef9b9795e196a185e9.qlog
        // Final contained-trace tuple 193.167.100.100:443|193.167.0.100:45438, packet_received time=1.
        "C9000000010865E34261219998A804730719AC0044EA1CD5A9A2ED73C7689D30DFFA342FEC0DA0D108CB02C60EA353D9EA206704181E7B98E27C5FEDAEABDB328B51DF62FDCD97F1B2B69C938221BD4713A365A725D1BAFAB6401FC6184885CD518CBB43D38BEBE7BC7739CB3D35A2AF74898D2DE3D0ABAF2BD3E0912F66BD15DE14A7277E5BB0E02B7D5DE174E82DD1943E7E53278D4E6172BD20A1DB3453FAC3EA9CED52C91BEC95D660E9DC7FA7A3308C4870D9DD8F8369A3AA0C4C3FF344F12FB1791BD2177734A7057B11EB5E6DCEE1BE87C794686AC12E27B7FA67E2219A3CC56C7F91E666DFD429D75AFEEB67F12452312E169D1F722629341ECC7E9A3310DB4C8DDA0408CE40BE5346C233CC76F89840ED345B24CC8EC7C152EBB73BB0F0390C087E7DB1EFE65A134F8E6D1AD6C53E5B1E7BCE4C809905947ED0BA9950C7F1166144BBAC326C97D0D7BFD418A1E986433ED13DF26D8CE55BC1A3A6223F364459BB447F09C0EAA0FFA45B4E148C0875A1FF590F4AC539CFC9A855762D7A684CF4C821E3C0C12FC39F06997B04F385951D5450599E815DFCC360E18462E30D9144DDFD151A7D8C2A41854DBBC2CEC46308AFC493098899A4A152C6BF153A570F4766C7FDF1CC28E9775BF7EABF6AB7AC43D8344365C64F877B3EB3B8DB3F5B6D20766D7F69207F0C63677FB6DE0881A9F22545CC2332DB9D5191C2BA90A297103ACF89C06205035201E116BAD74C3A7BD1621C905A812ABFB1CA68C08981A7B2E93D771BA06857B4180CA1B288111D156CC2893E2E912BB6F470E18E99C7A4E8AF7130A18BF7156773D307735422ED6B82FDCFBC6357E753355B505310D23E4E58519E00FB0CB7948C048A21EE5C5D68B58D1D046B5247E1220345D51A458506A5B19AE638342EF2311F5EA71936DD0A296A068BC515F03F8AC5ACFBC59542A81EEBAE9128EEF198377FBA3F3BF7B72B2B6FDC144D2DD5ADC691F56D35CB64251DA9F928AB1B89EABFB0A3B0E194B81036C39B4CA2D6E6762D2D6C1CBAC5207BDC5FCC5E4CC4F8D3F2B0EED857C8AA53E12E3DD232460F77FDAEB7E18F22C12D2A4990BD34F4941BDBA6409C18FFA2F2C9B90ECBD8695F7B6ABE58C8F9DDE42815600FFB81D1A130F9D7C9E0198BACB05B54D5676F47FEDE1499D9668A16D3D6D5FC2C7BFEFB896360450448F36F8EB43B31EB990D00FE77FFE497C40851AD48EF659E07BB4860AC0599C79BF58690BBF099A2C05DBEE04C1CC2D8E22DD05D385AB2A91995BDD9A831807FBFC2CBD121AC834290F8810673548FA8542B2451C6783858F61C891C53BD2D916E88012C47AE75ECB67ADF272D68500D802F1956A11DED216324D73A62D783B579AC899A4237A0DD37CA7867A334CA44A5A4E951EA8418364882F507FF2396EE99FDB2FB772F506D3365F2FA41E88C41CEBEA1ACF45F33DAE467C4741317528DBE45CF1C324535897EDAA5CF34586FE3CFE81E7B7E01D519A31002A128F4971A296E1964CAAAB79BE9AF7D84E95F33E5D5BDB6A68FC7EF5AA54A09D92C035C4111C14453FBAB93C8503AE235EAB5FBD3994768196392115A73CADF7D53A7A170C29DF0B2B06C65F3EECBA43E7331A02588998FF98E71A100352329E2D4EB662AB8CE0CCB5C2BC2D1883F9479A91FFBA3B8950B41BDF3CB3ED35E6B5FD30A3D35CE2CEF974E95431A791451F7813BCA215235A2FC93B5168690BDC8603C922407634F7DD11AE9134EC05E78433EB4BBE4FFA99BEA8E87A5AB3CDBC477859F8F430BD6CD196F9DD8F752A396BABB004647CFC8");
    private static readonly byte[] CapturedCurrentMulticonnectReplacementServerInitialRetryAttemptPacket = Convert.FromHexString(
        // Captured from the same preserved qlog.
        // Final contained-trace tuple 193.167.100.100:443|193.167.0.100:45438, packet_received time=10.
        "CC000000010865E34261219998A8040B77975E0041C405C6B066F603CF0AEE7EBCD3E9B9D9D95326BA406AAEB30B5A86DB20257E0D053A89968E136565FA9589EA3D24010704DF4A95630CF9C70F49BD8FB473EB38429CC058EEE25A21D73CFE57F28AB74FDC17C401E6A0D4163A5750B9FF9E09C70575AEB8BD16F4649B6E18C226A0F58069D55FDB0CD2C73A7E9D890EF98D2AE522E0DF91479D642D0E9B5828C58C049A5D570EE5B9BF8EADB4A8251E3C3E112DF78FBEFC41FA1D6B631BB4F0DCE9C3020079C241706056D3D66F34F1E93C243A12D3B76BC87B977C082975ED5C39F26192D8C3C8295452A794DDE5EAD2BE4D3F7597D6C9E833278C7CC132CA8F8026DA75EE7C82F5BA604BB11EA58C80735B3D67F6312D4076A39BC6BFDA3B0C1EB846619A79E8F9F7CF7C134CD04ACF6111BF9080030BAD27CD0716DFF7425ABA3091F63EA139525F39857CC11641C3AB33D6F2F44A0A257C9A0D5743934E1135A8D8F9C9D4E647113986B0E0F57F802CD866801FA020FCD0511217A7037B90F596751E3B69380A110F48EA7E7936F0E5D44F14E1CE1E6455CAA330412466BDB1401D5AB2ACB57C6CB1B41F04CF2690C0CB3408DCBC1A5E99EC4E54C981D358FDD9519CB5107ED0B16784EB9CE07BEE4157F7AC1CD922E5");
    private static readonly byte[] CapturedCurrentMulticonnectReplacementServerHandshakePacket = Convert.FromHexString(
        // Captured from the same preserved qlog.
        // Final contained-trace tuple 193.167.100.100:443|193.167.0.100:45438, packet_received time=13.
        "EB000000010865E34261219998A8040B77975E42DE33D090392916CE5FDAB48FEF250C3542D7F23DB6DCA42B8AE7D0EC5985D9C756F007405DAA6A65A1D55C3429E1F3E134BBB1DE294C33221B2920871E655B83061F91763671C8D1C8BCE85107367C33632F1693AF3AA9EC89A88FBCB59E4A199A4386992B4E47ED3687CED162AB7CF1C3EFF012AC53D9E70BD8CB5F5F8B72C2E129C2EC4900C5111197953233194F7AE2FFFFBD7E68007A246F1ABE78AF4C10FD091DB214DB724683B1C22878DB2C3A07180D817F9E4F5977A590212158CDB87DBDD0BEA152DA740A6590BF3FCBF64731184107AD5EEB50A41231C60281D962E054F4C38E589914312F3E80A1A8948F4C5D242830C2AA530DD9026FA7BFDF148DFFB42D1CA0B6D9A2756CD7B542B3CC018C8123E1E8FFA60BD96DA83461FB2383199240E5BDC3762A8B429FE47E05F1CBC8AF7780E518E4471EF3821BBC84243957D7B319C4C1C0EE016F0692BEC784242C35D86240B6A7BC3038629B414988B088A7C4FA75B1DE879711489DA7B736E9B38E36405D7960E8629A8698A01D7A6790636C2237B5AFDA73E906EBF18302746AF89C0D1243028BDED5118D2344548705213F7321914078063C284F58A9DDC0AEB13214A1CA33D12837C413A3E9D5C27326EB479F725B3329ACBB29CAED8A9A69B1553FEC2CD574B5262CE24E59F5ADE74C2EF2CCDEE70C1F48CEFFDFADE93F027488E9F48DF6A67A6E6E9D5AA7A5766F67519145097BC77B41872BA0430E822E48ECF75EC79BBABDDE6EB35BDACF4E1C6AB872661818D8D0ED70B120F27B2D0BADF915FFEE9AC441AAAB995F0BE129AF640E1C9D7B52CE102B4087D81BF77AF2FCEDB8C85CE0CEA8E905914A4540C3FA1823967188FB82D8D11C070C1BDC8FA7F52501ECF0E9546A7F0C133DAF36E0339DA7F587F6167E52026C483BDA6030B255DBAE85F1080487012D044B4522919DE96BC977A3743C55C3E2263801A393E9841D85B8791125B6F3066BF07516F686171AA340CD3E60B491776DF7C560A66EA466DA062BE61B5B771851C4A9");
    private static readonly byte[][] CapturedCurrentMulticonnectReplacementServerHandshakeTrafficSecretCandidates =
    [
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-165836034-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\server\keys.log
        Convert.FromHexString("B9A5C0691BD1452E30B92BE9EBAA198194364216E2C262BA61CDF56A202E8346"),
        Convert.FromHexString("56651DBCBB656A7C4D23CD2E28725F3F5B814ACA6BA4E93CF87630FBF679F134"),
        Convert.FromHexString("AA0787504850F2D3DF007E6F0A60A489135617DE2C4115B7B914CA92F19D743A"),
        Convert.FromHexString("784950BE8F730A191F2B478A96B91147A40D09BF0D14A615E3A353FBB657A4AE"),
    ];

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
    public void CapturedCurrentMulticonnectReplacementServerInitialsCarryDifferentServerHelloCryptoPayloads()
    {
        byte[] firstInitialCrypto = GetCapturedCurrentMulticonnectReplacementInitialCryptoPayload(
            CapturedCurrentMulticonnectReplacementServerInitialPacket);
        byte[] laterInitialCrypto = GetCapturedCurrentMulticonnectReplacementInitialCryptoPayload(
            CapturedCurrentMulticonnectReplacementServerInitialRetryAttemptPacket);

        Assert.NotEqual(Convert.ToHexString(firstInitialCrypto), Convert.ToHexString(laterInitialCrypto));
    }

    [Fact]
    public void CapturedCurrentMulticonnectReplacementServerHandshakePacketOpensWithOneOfThePreservedServerKeyLogSecrets()
    {
        QuicHandshakeFlowCoordinator coordinator = new();

        foreach (byte[] trafficSecret in CapturedCurrentMulticonnectReplacementServerHandshakeTrafficSecretCandidates)
        {
            Assert.True(TryCreateHandshakePacketProtectionMaterial(
                trafficSecret,
                out QuicTlsPacketProtectionMaterial openMaterial));

            if (!coordinator.TryOpenHandshakePacket(
                    CapturedCurrentMulticonnectReplacementServerHandshakePacket,
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
            Assert.Equal("65E34261219998A8", Convert.ToHexString(destinationConnectionId));
            Assert.Equal("0B77975E", Convert.ToHexString(sourceConnectionId));
            return;
        }

        Assert.Fail("None of the preserved multiconnect server handshake traffic-secret candidates opened the captured replacement Handshake packet.");
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

    private static byte[] GetCapturedCurrentMulticonnectReplacementInitialCryptoPayload(ReadOnlySpan<byte> protectedPacket)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            CapturedCurrentMulticonnectReplacementOriginalInitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new();
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            protection,
            requireZeroTokenLength: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        return ExtractFirstCryptoFrameData(openedPacket.AsSpan(payloadOffset, payloadLength));
    }

    private static byte[] ExtractFirstCryptoFrameData(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed))
            {
                _ = cryptoBytesConsumed;
                return cryptoFrame.CryptoData.ToArray();
            }

            break;
        }

        Assert.Fail("The captured Initial payload did not contain a CRYPTO frame.");
        return [];
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

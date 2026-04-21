using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

internal static class QuicCapturedInteropTransferEvidence
{
    private const int TrafficSecretLength = 32;
    private const int AeadKeyLength = 16;
    private const int AeadIvLength = 12;
    private const int HeaderProtectionKeyLength = 16;
    private const int MaximumShortHeaderConnectionIdLength = 20;

    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] QuicKeyUpdateLabel = Encoding.ASCII.GetBytes("quic ku");

    internal static readonly byte[] QuicGoTransferServerTrafficSecret = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260420-232634306-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\server\keys.log
        // SERVER_TRAFFIC_SECRET_0 for the preserved client-role transfer repro.
        "675D6C96A0EBA40B253C1F8E302E2D7780539B8B305BF599B50D29CB24AB2E0C");

    internal static readonly byte[] QuicGoTransferPacket77Protected = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260420-232634306-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\sim\trace_node_right.pcap
        // Packet 77: server -> client short 1-RTT packet that carries STREAM_DATA_BLOCKED plus the next 325 stream bytes.
        "5629165682D4F4BAD2A3BE1CAC12604EA5A9655644362093FE496E4B240307DE9BC76CA3B0C777B3C773C9BF3517D593" +
        "F1A8CF65DC06829312D83907D4C6355EDB45AAB9DAF12C9C63D8A3D0F7F594C47C73CCF829F8BB27B823352AD027045C" +
        "E8511285630B7CC28D5D44F2DF2C3560B49E4629AB40F14AB54EB9EEDDAD754D4C6D6CB43AB2D1B8537B8448249E6122" +
        "AD56BD9C41E0E986397558BB11CCB4910F7CDE6EAB08415A8D114C2864430668410DE02BF97359CC33F1C714A611A100" +
        "F30B74D0B2FFBE4059D8A151AFF5D211E6E9D31911BAC24E12366F822A85CDF6CD0DF560D76BA47C2F93CA98B472C655" +
        "F149F2081C81331CDEA8B912A74FD2CBC3E9DA1ADC188EAC5E6344D401F7A1086745D5B182B4F1523765CD90746784D7" +
        "AAB132BB4C1FA547B624EEAF8DAE2DA5F668A8134F0ADC0A639CC803AED6C87F7699A0D84210697EC1F5A46EB5EA04FF" +
        "70404523DB6CB610534B4377546723FE3350A3DBC07F1EDC15127FE2");

    internal static readonly byte[] QuicGoTransferPacket77Payload = Convert.FromHexString(
        // Opened from the same preserved packet with SERVER_TRAFFIC_SECRET_0 from the same run.
        "15008001444A0C0080014305D3BE139613F3A3DCA8FAD0FDB05F9867A324CA3CC4184D41670BAAB1E9CCBCB033D49341" +
        "AD2C800D6F12CC1B3D07A0E8ACE14548190B83C342DCEF024F3842ED6955151EA0B39072B294BF1331162DA172469DFB" +
        "F24917ADBE4F888617676914EB818087B1ECE8E5DC38222CB9CA80757280CDA4AF5BD02D02585C606AC4965C2B3D05BA" +
        "3380E82B8775FD80DD2B7F0ED48E40A9E341263AC9E9A3ACFE842BEE505010E7FCCD607971351D8319C237255CC52776" +
        "BB285DD41F60F758F4195E77004FFB11FC7DFFFFBE81D0196699A01D77C619E5EC7EFA6ED3915EEFF8ED5796C2ACEEC1" +
        "D52543DE78626F056B0E977C93E38955195697A9E35ADA6BE8CA1B63675E6622EC9B9F1FF179F2ACCEF1BC98FB2F6D1F" +
        "277E9CB3EF1F5B669F333DC2889D996F74607BE16152B98F2D07D925634A4E");

    internal static readonly byte[] QuicGoTransferPacket83Protected = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260420-232634306-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\sim\trace_node_right.pcap
        // Packet 83: server -> client short 1-RTT packet that carries NEW_TOKEN, CRYPTO, STREAM_DATA_BLOCKED,
        // HANDSHAKE_DONE, and the same next 325 stream bytes.
        "4829165682D4F4BAD2F178A5E3BAB9C5DEEB150B9B8BF529E2A5556CC75C32510539B69CE0D60F63CD3E5E4CB527EBB7" +
        "7A090042F8D31036FBE3B0F8629B883CF68DBC78829BFAF2D9D308930472329DCBCBE0662F7855F43B76F5C15F25DB63" +
        "C32174FBB1C1EF603223123A9D9D1A54EA234A1A226F3D8C8F9FC63BABA32C56F3B7E4DD49DEB62D05122EC76C5D5D65" +
        "809757CFAEC312F33913CD9BE0283E95BD478683A7C3AC1DE075F2FB4AB68AC955B7B1559D6026CA87A632FBDB676088" +
        "5A37D4C72653885B7D9B131B0210FA5CE939B36B4482288786023A8BA17211C708CEBB18D4775E4A107AF31780592319" +
        "5BCB8A09AE4F8D831856167A475FEB91E2D26F57D4EA7537B5D653760A6743591A5131B290C6E73EE131F7ACFDECA2A8" +
        "8D70EC3D510F54EC536A5DEDA7CE98809AECCA57A9A4680E7CBC1DD642E7CA9E4A094BCE1302932DEB169F1677FD2485" +
        "8998AE52F76E5BC6CFDE0FD085FCA7BB6CC2B4607327A4B1A62E642D6CA797C0611024A25F2CF6DF5B7A9FCE3E82C82C" +
        "5593CFE1823D32917DD1CEF41997ADADFF96762E494AABAE3DECC1F89BE7470F4AF25D6FC69F13A5BDC38DA264D8DFB8" +
        "2E5597049319C79A1FE9185B1941E94B4E2B6915A04641AE9EA7FD9729038191448953A4DDECD97B21ED8700A5BA06D2" +
        "388797711FF5C20573516531AA4B63C91D337DF6EBE1B280EA5768644C2C38CEA82763ED0DEF4B7086E158BE44B343A0" +
        "D2FD17D5266B3572F0272FB5BD784AE49B8EC0372671B6CB1F9131B44A4C301E6A5B92EBE76BCC1EE4E3F6F2E7ECBE30" +
        "2CB3E1EA8C993A86FC9E286B59AD632FA3035ECA30EF1BD8D115F3CAE1A4B8869A7B52112950BD12F63940995C89818A" +
        "FE7501DE49A46C");

    internal static readonly byte[] QuicGoTransferPacket83Payload = Convert.FromHexString(
        // Opened from the same preserved packet with SERVER_TRAFFIC_SECRET_0 from the same run.
        "0740592EAC2995D25B3784724B9FD2E31B6EE0084F818CB1D334B47834803FAFE508EC78A904FBA6B5E075347FB9ED20" +
        "044931E1D98F1166F2E427CDC249CB2BF1BFC6CF22E2F8715A14D9FF7F54ECF42BF67F412268F48845033D88060040AA" +
        "040000A600093A802153F012000099B5BCC39997ADBA6B34D8FEDE485FFFF5F02D275473280CCD7850620DF6AF1AD5C2" +
        "D8A43B3583776ECC9E0ED3FF8A5A7555FA101B66A5111417C754C75A3BF769432EFEBC405276AA29DA6F1391784817A1" +
        "FD79123EEAA5E4317A8B776DD83E40F9276DFFE53395738DF5A1A27FB18C6F36E6224D38A17A2ACF5895B34FE541813E3" +
        "A46E259F8962EDFEACAB1401DA995D0E17FD2F344AAAA38000015008001444A1E0C0080014305D3BE139613F3A3DCA8F" +
        "AD0FDB05F9867A324CA3CC4184D41670BAAB1E9CCBCB033D49341AD2C800D6F12CC1B3D07A0E8ACE14548190B83C342DC" +
        "EF024F3842ED6955151EA0B39072B294BF1331162DA172469DFBF24917ADBE4F888617676914EB818087B1ECE8E5DC38" +
        "222CB9CA80757280CDA4AF5BD02D02585C606AC4965C2B3D05BA3380E82B8775FD80DD2B7F0ED48E40A9E341263AC9E9A" +
        "3ACFE842BEE505010E7FCCD607971351D8319C237255CC52776BB285DD41F60F758F4195E77004FFB11FC7DFFFFBE81D" +
        "0196699A01D77C619E5EC7EFA6ED3915EEFF8ED5796C2ACEEC1D52543DE78626F056B0E977C93E38955195697A9E35ADA" +
        "6BE8CA1B63675E6622EC9B9F1FF179F2ACCEF1BC98FB2F6D1F277E9CB3EF1F5B669F333DC2889D996F74607BE16152B98" +
        "F2D07D925634A4E");

    internal static readonly byte[] QuicGoTransferKeyUpdateServerTrafficSecret = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-002742364-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\server\keys.log
        // SERVER_TRAFFIC_SECRET_0 for the preserved client-role transfer key-update repro.
        "1472A05727B830B7643BC2BE4A511C46D327935441A9E2B27FD655C03257AD62");

    internal static readonly byte[] QuicGoTransferKeyUpdatePacket101Protected = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-002742364-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\sim\trace_node_right.pcap
        // Packet 101: server -> client short 1-RTT phase-one packet that only opens when the successor AEAD key/IV
        // are paired with the retained current header-protection key from the same run.
        "58BAABE6B0BFDE84ACF0B785A5ED8624EEDF88AEF64E553DE4685068B16CD2DC9D");

    internal static readonly byte[] QuicGoTransferKeyUpdatePacket101Payload = Convert.FromHexString(
        // Opened from the same preserved packet with successor AEAD key/IV derived via "quic ku" from
        // SERVER_TRAFFIC_SECRET_0 above while retaining the current header-protection key from that same run.
        "024048090025");

    internal static readonly byte[] QuicGoTransferKeyUpdatePacket102Protected = Convert.FromHexString(
        // Captured from:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-002742364-client-chrome\
        //   runner-logs\quic-go_chrome\transfer\sim\trace_node_right.pcap
        // Packet 102: the next server -> client short 1-RTT phase-one packet from the same preserved key-update repro.
        "41BAABE6B0BFDE84AC267B2A77111AFF135EFD89FDE23D4417E9FE4A299E33CAD55816BDD4002C06E0D38CEB6E5C1735" +
        "4ED436D20B6B77DCAAFDAE3FCC61DD327A1CFD297F78BB5035166B0B334AE2B539506A2440A95D880CDD349C30FD41B8" +
        "0BCB6BB6D43B1B2991484B8E6E01543DABC0D0CE59C09CF5EA134A138C0F43244F199021D77F9A92C7961A2781D25F78" +
        "A98CB6A288C355A7C2C7137468F5997DA5B748E695790B6C092A52AF9CCF09DB6499E014EF10CBACC15A1E5F7EBD90A77" +
        "4C66DD905DCEFF6CA664F1C749A6BAB499975DE5DCC09E3A3AD5714FF05145E1DF602D759DDB1849767C7FE031735F230" +
        "0B37028526272D3572F4CAA94B185F7A02C276F6E870949B80E5C6581D38CE1532E5D022BD8DAA252435E95232120656B" +
        "1F3233A61CC75427E9ACD209234548223EE81E315DF77C23F796A789C4FBF1A7E7F3033F14E379D838638BE2D452F7042" +
        "38A1179F1BF9718C93D6C6BCF3532C0F48AFD365DD6D407A49681E64D288464E26F2607D45ED74FF5D1A95C46289B1E64" +
        "BFCBE44DB78EDAC51F20493D43E772DC05A4D369358F8528B1D322CF96D410BF145929F228A8F7F1C8CF82CF02699E37F" +
        "61E7FA3ABEBF2F3BE244AD43B88ED8DEBAB312B09D214EEDBF34441C8CC16BF4741F5C02B55ACC9F8E369B7979040D8BF" +
        "70B0FE677BC6103728BBED841EBDA033E5785EF5D9713B899692C09B41C0E83FC1827776F205AE9013DB1554975698DC5" +
        "E3AA8D6504D1A9D1E4A8E416A626E2B770EFA31CE6DCE1DDBCE1ABFF9C87CBD705D778D79DB5F42781D69E55F5D227C08" +
        "0366AF4E13434C77D10374550828CFB66185D1858E85BD1F197478C09B933E64FE5CBD4ACEE928D8029E6D9C8648F8A91" +
        "69467FC004218FD5BFFE1C7414EBF8E757C2431EAF76F5E384410C9AE5AC1C9E03A45729BD40F133F72B8B7984B818361" +
        "BD54282EB19D7BF6C07F0F25F22A62D613B6E16970978F7C4FC9B761579202F97E355156E2C20A6C342FFDCAFC045EB59" +
        "F85F0893AD3D704CC853CE1BE6CD9C4F3FFEF86D62BD85A84C7137FE117C1882B5E3DB61485C5853C302BD96703048E9D" +
        "10DE8946C70FDAB681D563854607163AEE2BC9066BEBB8CAE7D4412BC5D909C36DC5BE693DE8F38B2B7CC0582B6D69363" +
        "B0EAD0E403FE868DED6798D8111EE4E2E482F5A01B501BB2F3F1F27E232C60DE5700712362B9B74E497209F79BCCB7FBE" +
        "8DFA232FEF4BAFC1CCC1011979463A61A2D40909C2233178A01CBB010F154C9E42D247E79A6F562F44B3264BDB9E841FE" +
        "6C000D8EEA8F8D6A1D2B4991155185C588C159FEE8ED159D4704D62F9FEF12F1C857145370EA6A506476BE359AE109FA8" +
        "FCDC8054136F1ACE1DD590875BE1D1A2861D4EB59FD7C254CFFD8C0D0B4AE7B9B0ED26D52BB6A0950FB6CA30957E8C3B" +
        "AF45207040F4F4545F2676567916DE36F65BFF708C35F0DCC5426BD7FFCEA59F102E0CDAC88B618EA709209F448E98D2A" +
        "F21A1EE60007CBE95E8CB7413CDB31597EA83E012D8D8E9AB83D6DCACC3EEE22C57883A949F47642B13BCE76AE0F206A9" +
        "A91EC92C8993EE94B151919175D016572D4EDE53CD9DA55DD9C53FED4A5D49749F8A6ADEC2A35A133774E061E19727248" +
        "30B000E5D45E27FDBA7CE6B72AF156CB67622ED757FD7CA8ECD83650ECBDB18B094FE61F3D2E9821FF8FA227BBC7F035" +
        "16CF187223E19B0803848C5E09BA7C1E7F5A90790A3B5F30B225AED190812192BDEEBE68B52DE561CA24ADFB3728F65CD" +
        "D9E820B0355B483F0DEDF888CFA50176F200A60C503");

    internal static byte[] OpenServerApplicationPayload(ReadOnlySpan<byte> protectedPacket)
    {
        Assert.True(TryCreateOneRttPacketProtectionMaterial(
            QuicGoTransferServerTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        for (int connectionIdLength = 0; connectionIdLength <= 20; connectionIdLength++)
        {
            QuicHandshakeFlowCoordinator coordinator = new(new byte[connectionIdLength], new byte[connectionIdLength]);
            if (coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                openMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool observedKeyPhase))
            {
                Assert.False(observedKeyPhase);
                return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
            }
        }

        throw new Xunit.Sdk.XunitException("The preserved transfer packet could not be opened with any short-header connection-id length.");
    }

    internal static bool TryCreateTransferPhaseOneServerOpenMaterialWithRetainedHeaderProtectionKey(
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        if (!TryCreateOneRttPacketProtectionMaterial(
                QuicGoTransferKeyUpdateServerTrafficSecret,
                out QuicTlsPacketProtectionMaterial currentMaterial))
        {
            return false;
        }

        return TryCreateTransferPhaseOneServerOpenMaterial(
            currentMaterial.HeaderProtectionKey,
            out material);
    }

    internal static bool TryCreateTransferPhaseOneServerOpenMaterialWithDerivedHeaderProtectionKey(
        out QuicTlsPacketProtectionMaterial material)
    {
        return TryCreateTransferPhaseOneServerOpenMaterial(
            headerProtectionKeyOverride: [],
            out material);
    }

    internal static bool TryOpenTransferPhaseOneServerPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial openMaterial,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out bool observedKeyPhase)
    {
        openedPacket = [];
        payloadOffset = 0;
        payloadLength = 0;
        observedKeyPhase = false;

        for (int connectionIdLength = 0; connectionIdLength <= MaximumShortHeaderConnectionIdLength; connectionIdLength++)
        {
            QuicHandshakeFlowCoordinator coordinator = new(new byte[connectionIdLength], new byte[connectionIdLength]);
            if (coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                openMaterial,
                out openedPacket,
                out payloadOffset,
                out payloadLength,
                out observedKeyPhase))
            {
                return true;
            }
        }

        return false;
    }

    internal static byte[] OpenTransferPhaseOneServerApplicationPayloadWithRetainedHeaderProtectionKey(ReadOnlySpan<byte> protectedPacket)
    {
        Assert.True(TryCreateTransferPhaseOneServerOpenMaterialWithRetainedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial openMaterial));
        Assert.True(TryOpenTransferPhaseOneServerPacket(
            protectedPacket,
            openMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));
        Assert.True(observedKeyPhase);
        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static bool TryCreateTransferPhaseOneServerOpenMaterial(
        ReadOnlySpan<byte> headerProtectionKeyOverride,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        byte[] nextTrafficSecret = HkdfExpandLabel(
            QuicGoTransferKeyUpdateServerTrafficSecret,
            QuicKeyUpdateLabel,
            [],
            TrafficSecretLength);

        byte[] aeadKey = HkdfExpandLabel(nextTrafficSecret, QuicKeyLabel, [], AeadKeyLength);
        byte[] aeadIv = HkdfExpandLabel(nextTrafficSecret, QuicIvLabel, [], AeadIvLength);
        ReadOnlySpan<byte> headerProtectionKey = headerProtectionKeyOverride.IsEmpty
            ? HkdfExpandLabel(nextTrafficSecret, QuicHpLabel, [], HeaderProtectionKeyLength)
            : headerProtectionKeyOverride;

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
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

        byte[] aeadKey = HkdfExpandLabel(trafficSecret, QuicKeyLabel, [], AeadKeyLength);
        byte[] aeadIv = HkdfExpandLabel(trafficSecret, QuicIvLabel, [], AeadIvLength);
        byte[] headerProtectionKey = HkdfExpandLabel(trafficSecret, QuicHpLabel, [], HeaderProtectionKeyLength);

        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(64, 128),
            out material);
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

        byte[] hkdfLabel = new byte[hkdfLabelLength];
        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel.AsSpan(0, HkdfLengthFieldLength), checked((ushort)length));
        hkdfLabel[HkdfLengthFieldLength] = checked((byte)(hkdfLabelPrefix.Length + label.Length));

        int index = HkdfLengthFieldLength + HkdfLabelLengthFieldLength;
        hkdfLabelPrefix.CopyTo(hkdfLabel.AsSpan(index));
        index += hkdfLabelPrefix.Length;

        label.CopyTo(hkdfLabel.AsSpan(index));
        index += label.Length;

        hkdfLabel[index++] = checked((byte)context.Length);
        if (!context.IsEmpty)
        {
            context.CopyTo(hkdfLabel.AsSpan(index));
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

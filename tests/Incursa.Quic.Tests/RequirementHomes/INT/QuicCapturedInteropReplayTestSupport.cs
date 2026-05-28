// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

internal static class QuicCapturedInteropReplayTestSupport
{
    // Captured from:
    // C:\src\incursa\quic-dotnet\.artifacts\interop-runner\deterministic-fixture-refresh\20260519-103533285-client-chrome\
    //   runner-logs\quic-go_chrome\handshake\client\qlog\client-handshake-aacc3f161f4d480d80c76d698d11c53d.qlog
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
        byte[] initialDestinationConnectionId = DecodeHex("48B28881B1D1C7B3");
        byte[] clientSourceConnectionId = DecodeHex("AA2763691C344066");
        byte[] localHandshakePrivateKey = DecodeHex("0000000000000000000000000000000000000000000000000000000000000011");
        byte[] capturedClientInitialDatagram = DecodeHex(
            """
            C8000000010848B28881B1D1C7B308AA2763691C3440660044964AE2370924F905F8
            B93A1213BDC84C14C03179D0BA16BF342FFEA54942CB734D37161E89E44F872D6537
            D75A361A520744AE7A6F4F7E831646F1D444C65CA4CDF4226BD94EF13D29AACA5DB1
            9C9F4439CB1659907B3106D44544E7D6E2E1B3D829A7CCDD5B2F44D000E05EE3F406
            2A6F1862516AD3EB1B24314F24E9BDC99C03F8A38A65F86807C176D838A225F2A7D7
            16A8026A4444B7E55C04146E94CB3E5BF472856E6411ACAB133655C7974FA89930FD
            44A2892956878948C62437B99BF104EA6BD70D678F1874B52C85C358058F5A46A0E4
            118AAEB4E19FD2EC29E982365B02D807E816121F7EBCBF2594F72C918CC7C117FA03
            0C15AC7A23E43AB20BE71A8CC111B0640F727F7CAEECE27823193071D40263187A8B
            AA38D9658A120FB1859D768AA2386248267A7F00DAF17380F3C7CC3E4FCD11CC4C6E
            08C521803E6327CC12B002A3F1EE86B092D5E967075425C9497A61B034ACDAD85418
            23E5EBA478BF10EE82322D36CB27A967F71A6D3CCF296327F25B0338355EA07FC48C
            33EC33741C072E9E906F122CE03A6D4EA9346844BFBFFF9B480A44E4070F00665E0F
            BAD7FD847DEBB23D9D52A382325C07F810335B28F87553A64B2808D7E3827D064DFB
            ED0D0C1567DCF99A2A236A9BBB33E633601BDB9614595DFFCD4CC94B13B0D4E15847
            56F7B34A78B8B7019312E959D4DDBAF9E42C306D97015E29ED26A91B4B8910304A2E
            3448A96303FFD6EC95E0B84D36FF9AAA55255024601A091910293B78C1A6E67B3A2D
            B9DA958A76746B0C9558ACB7B686DF4B972338F306BB6A736A165064D0104D177758
            E85FE70235EE5F68F6BE40C622BDEA1824612245927E728092FD82F2BA638C683A95
            80DBDC244EF732CCCDAA9FBFB1E291290A541D0D3B5B3E2E9BB3402DD88BE9B6E694
            0D8E267257E12650C17A100F288DBAE6EA5FACA2B88E33388F9291DE48C723201155
            A9EC0F854357C05E3EC13DE9306E00576F2CAFDCF865072C9ACFA1E03CE8A8E85FF1
            A3FD423482832B638FDB20F9A3DF36C13C36B5B677F18586E3C6D7ED1DAFEA4E0689
            FF2C3920EADFE6DE5C4FAC298DE210ABDE5F2EB8293F9ADCF63DFCBE2657407AD7B0
            66AAAD794C67CA728C81B17A2619FF6C6305AD413E12DA8975848B85B2CFF612184B
            D125D225696814EBE68B9D7FA8E96E4809187953FE163CD5B5868F38D082431B404B
            874CEF7DD8F384860F3608B1425447CB104E89BC09217ABF86773516F490FFCD1568
            88587C053D8DD6D154E22318ACAC34B8537250BD22226EBB3E252E71AD0D6195BF51
            25067D65C1A9818E7C45DAD4CEE9741DD2E6F083D56C4311C3F8FB1203C27BF2C3D4
            8342B74CFCC79EE8D2AEA70AB2AE8447D27ADCC2C42807905248BC67EA130D793DF4
            ADEC643F04448B10C5A6BBE6F12756F9667637F0CFC2CD03D50B05A859C3794E934B
            E60470507E858382B5B1C9508B28BAF1F63B5914D7C83486CA09AEA9BD518359C289
            7F92DD548B18967AEF1798F24AA44F4910A62216A532FF5895CE4C2FFE48E96B9BD9
            67758779E731913961C78502DE68CB47C2A5CBA1587D9EBB52919C6C4016BD002F4A
            FFF85A952B64442244312142111FAC38C41076A61E274AAFB8A1F1E863F3E0FBE3A7
            C58819A12A8F786D090B
            """);
        byte[] capturedServerInitialPacket = DecodeHex(
            """
            C40000000108AA2763691C344066043A16015C0041C1FB51161F773F7796D10E3F35
            BA6CE9B5D2A0EF009212730ED615D69B130A7EF99ACC4627450464E09EAC3EE4E1BC
            C60325514F5F1EE77553812EE5B2EEAC18F28C428A77F9EEFF6B521E733970766557
            4703BFEC6597B00261F3525CCE9F9D26389339CEA4EE1819DC307BC84D70703690D7
            E83316D055E1751F851BBE60B7EEF763E6FA2FE6CC4EADC11705AC78C0744542A688
            097D95AB6347225ED76DF33374472248C4D1EF722B7C052AA4F45A2BD62EF738D7AB
            0FBA45F1483A8FC69D47DA389F0FC96A2C34B16488AB43214DBBB4B44A222AB2BECF
            B0D070C3658BD9DFF3757AE335B0E8494F7349A9BD490553C87B2CE8AFBC7D68E890
            B47FC5AA78DA8BE26B04A4211163A3D259D635ECD83038181020E8B65D727186C94F
            8002CFCABC33C8C7F9E7BE9C423CAA05A7E1F24C6F051FB5BD1764C601FD213AD438
            9AEEF6FB5FD39A0639B78B693CAF62C54DC72AC4493D34121C668D15260F6CD88F5A
            C3568033FFCB6C08F12285F3E3BE0168C8E6FCB6DCCBCD0BB81A6B6AA769F3C5F5BB
            25EB0002B8DAA6FD74C18E11EECD45988EE7FC15A4560CFF7B70F5C391D17B099A62
            42331194BFB8BC51F1716218F5ECC1AA5DB69852549DA566F1C754A2BD
            """);
        byte[] capturedServerHandshakePacket = DecodeHex(
            """
            E50000000108AA2763691C344066043A16015C42E14DC39E5BF572E3ECB26FA995F7
            3F56911011C271934413433BFFF822D4A9049D5089959795B32C8D9D6F47FA4CE5A3
            A4A6DF43762AE4170B5519F9EB1DFC18129DB5332F34BB1A1AF90442375E7B827765
            1A47B83E2F2B27628553624D2B568604A5BBE6F994392E2BD6B3BC9A10767D88B08A
            59BDFDB2D5FD49F99D000A73BFD6B5D6016062EF5C4EADD368BD4718C6F160D689BA
            CCED907ECEFC86A835AD036104F2BC2788CAAD79DA8D4E43FEB4F57D494882AA18C7
            CAF84A38394D33F71EC046DE3E3F9705DF10A3C16F1437D3B40B7B7FDA42069231A8
            CB762DDE768E8EBAA578365B2092FB208589042BCEA962BE15894BDDA8904A360BB7
            73E76BF79642B983852C7A87DFFB4D409E6DAC3CE879F1DFF5250675234C13392828
            0918F57148996D5E5558EE1C1055FC887195A58EE074DE195170D4BEAE946412A42A
            9646A339462E012E2E1B4B248FC9215626EBF35A31EA8E7D7ED60D8D5FC5DB779255
            6570F263AF915F604DF68840F0E915ABD601EE982B08E978B168667AD77C2E95D8A6
            E6E9638E4ADC2B80667CD787A61EADE5CAEAE7032DB0927DDDE3E7E51FABA7C2D275
            F7EB808E4EF65642E2BDBFFFDB8610DB4AB698E0FF5810579E96642E672B4AE77F02
            4D3ED8C65819F310585640A25302C0976605476003EFBE1389E5B16BFC8CD9EF0084
            B886187211FC60D0A2EABFE6A748D5C0EE7DF40E51C3A6693D7E19F75251B6331841
            CD3B7FD9BF13F64DEEDC3DFBFD460EA5E773627E31F27F63C8663DD8733E99707CAE
            F6562B382427645FB50DD01C14DD7F41D0926BCD6A95EFB3644395F25401BD8EF413
            6A8AA6A57FD8E8BC218A4978C5DB5CF21BB61AF627BC1F066B641FCA156253AF5380
            BE687A7137C5C7418760CA683F0210703BCE50036AC4C4EAE0B2382C2E84B14D4698
            CC57EEFCFC5F52E943D6EC72537C37F3C897CF9B23785BFE592FAC8B221C8DB5F959
            9083F95177D2C53FF298B87DBC611F6D3A6F3FD43155F42147500A2554E524AC2C4F
            827A5C7E0EA17CE7B2AC
            """);

        QuicConnectionPathIdentity pathIdentity = new(
            "193.167.100.100",
            "193.167.0.100",
            443,
            34360);
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

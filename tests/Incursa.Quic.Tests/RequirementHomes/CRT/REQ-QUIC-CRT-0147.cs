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

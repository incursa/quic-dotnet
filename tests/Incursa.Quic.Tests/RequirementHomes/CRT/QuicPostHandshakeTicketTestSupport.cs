using System.Diagnostics;
using System.Reflection;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

internal static class QuicPostHandshakeTicketTestSupport
{
    private const int HandshakeHeaderLength = 4;
    private const int UInt16Length = 2;
    private const int UInt24Length = 3;
    private const ushort TlsLegacyVersion = 0x0303;
    private const ushort Tls13Version = 0x0304;
    private const byte NullCompressionMethod = 0x00;
    private const int MaximumSessionIdLength = 32;
    private const ushort SupportedVersionsExtensionType = 0x002b;
    private const ushort KeyShareExtensionType = 0x0033;
    private const ushort EarlyDataExtensionType = 0x002a;
    private const ushort Secp256r1NamedGroup = (ushort)QuicTlsNamedGroup.Secp256r1;
    private const ushort TlsAes128GcmSha256Value = (ushort)QuicTlsCipherSuite.TlsAes128GcmSha256;
    private const byte UncompressedPointFormat = 0x04;
    private const int Secp256r1CoordinateLength = 32;
    private const int Secp256r1KeyShareLength = 1 + (Secp256r1CoordinateLength * 2);
    private const ulong DefaultConnectionFlowControlLimit = 64;
    private const ulong DefaultStreamFlowControlLimit = 8;
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];
    private static readonly byte[] PacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];
    private static readonly QuicConnectionPathIdentity PacketPathIdentity =
        new("203.0.113.10", RemotePort: 443);

    internal static QuicTlsTransportBridgeDriver CreateStartedClientDriver()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        Assert.Equal(2, driver.StartHandshake(localTransportParameters).Count);
        return driver;
    }

    internal static QuicTlsTransportBridgeDriver CreateFinishedClientDriver()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(localTransportParameters);
        Assert.Equal(2, bootstrapUpdates.Count);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        Assert.Equal(4, driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript).Count);
        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript));
        Assert.Single(driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript));
        Assert.Equal(3, driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript).Count);
        Assert.Equal(8, driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript).Count);
        Assert.True(driver.State.HasResumptionMasterSecret);

        return driver;
    }

    internal static QuicConnectionRuntime CreateFinishedClientRuntime()
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        Assert.True(runtime.TryConfigureInitialPacketProtection(PacketConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(PacketPathIdentity));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(PacketSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(PacketConnectionId));

        QuicTlsPacketProtectionMaterial handshakePacketMaterial = CreateHandshakeMaterial();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: handshakePacketMaterial)),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 1,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 1).StateChanged);

        byte[] clientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(runtime);
        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript) = CreateClientHandshakeTranscriptParts(
            clientHelloBytes,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        ulong transcriptOffset = 0;
        Assert.True(TransitionHandshakePacket(
            runtime,
            serverHelloTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 2));
        AssertRuntimeNotClosing(runtime, "serverHello");

        Assert.True(runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out handshakePacketMaterial));
        transcriptOffset += (ulong)serverHelloTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            encryptedExtensionsTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 3));
        AssertRuntimeNotClosing(runtime, "encryptedExtensions");
        transcriptOffset += (ulong)encryptedExtensionsTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            certificateTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 4));
        AssertRuntimeNotClosing(runtime, "certificate");
        transcriptOffset += (ulong)certificateTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            certificateVerifyTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 5));
        AssertRuntimeNotClosing(runtime, "certificateVerify");
        transcriptOffset += (ulong)certificateVerifyTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            finishedTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 6));
        AssertRuntimeNotClosing(runtime, "finished");

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.HasResumptionMasterSecret);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(ReceiveProtectedHandshakeDonePacket(runtime, observedAtTicks: 7).StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        AcknowledgeTrackedPackets(runtime);

        return runtime;
    }

    internal static QuicConnectionRuntime CreateFinishedServerRuntime(
        ulong connectionReceiveLimit = DefaultConnectionFlowControlLimit,
        ulong connectionSendLimit = DefaultConnectionFlowControlLimit,
        ulong incomingBidirectionalStreamReceiveLimit = DefaultStreamFlowControlLimit,
        ulong outgoingBidirectionalStreamReceiveLimit = DefaultStreamFlowControlLimit,
        ulong peerConnectionFlowControlLimit = DefaultConnectionFlowControlLimit,
        ulong peerStreamFlowControlLimit = DefaultStreamFlowControlLimit)
    {
        byte[] clientHandshakePrivateKey = CreateScalar(0x11);
        byte[] localHandshakePrivateKey = CreateScalar(0x22);
        byte[] localSigningPrivateKey = CreateScalar(0x44);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();

        QuicTlsTransportBridgeDriver clientDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: clientHandshakePrivateKey);
        IReadOnlyList<QuicTlsStateUpdate> clientBootstrapUpdates = clientDriver.StartHandshake(
            CreateClientTransportParameters(peerConnectionFlowControlLimit, peerStreamFlowControlLimit));
        Assert.Equal(2, clientBootstrapUpdates.Count);
        byte[] clientHelloBytes = clientBootstrapUpdates[1].CryptoData.ToArray();

        using ECDsa localLeafCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        localLeafCertificateKey.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = localSigningPrivateKey,
        });

        byte[] localLeafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(localLeafCertificateKey);

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: connectionReceiveLimit,
                connectionSendLimit: connectionSendLimit,
                localBidirectionalReceiveLimit: outgoingBidirectionalStreamReceiveLimit,
                peerBidirectionalReceiveLimit: incomingBidirectionalStreamReceiveLimit,
                localBidirectionalSendLimit: outgoingBidirectionalStreamReceiveLimit,
                peerBidirectionalSendLimit: incomingBidirectionalStreamReceiveLimit),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey,
            localServerLeafCertificateDer: localLeafCertificateDer,
            localServerLeafSigningPrivateKey: localSigningPrivateKey);

        Assert.True(runtime.TryConfigureInitialPacketProtection(PacketConnectionId));
        Assert.True(runtime.TrySetBootstrapOutboundPath(PacketPathIdentity));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(PacketSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(PacketConnectionId));

        Assert.True(runtime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: 0,
                LocalTransportParameters: localTransportParameters),
            nowTicks: 0).StateChanged);

        QuicTlsPacketProtectionMaterial handshakePacketMaterial = CreateHandshakeMaterial();
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                PacketProtectionMaterial: handshakePacketMaterial)),
            nowTicks: 0).StateChanged);

        FieldInfo runtimeDriverField = typeof(QuicConnectionRuntime).GetField(
            "tlsBridgeDriver",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsTransportBridgeDriver runtimeDriver = (QuicTlsTransportBridgeDriver)runtimeDriverField.GetValue(runtime)!;
        FieldInfo runtimeKeyScheduleField = typeof(QuicTlsTransportBridgeDriver).GetField(
            "keySchedule",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        QuicTlsKeySchedule runtimeKeySchedule = (QuicTlsKeySchedule)runtimeKeyScheduleField.GetValue(runtimeDriver)!;
        IReadOnlyList<QuicTlsStateUpdate> clientHelloUpdates = runtimeDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            clientHelloBytes);
        Assert.Equal(9, clientHelloUpdates.Count);
        long observedAtTicks = 1;
        observedAtTicks = ApplyRuntimeUpdates(runtime, clientHelloUpdates, observedAtTicks);
        Assert.True(runtimeKeySchedule.TryGetExpectedPeerFinishedVerifyData(out byte[] expectedFinishedVerifyData));

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = runtimeDriver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            CreateFinishedTranscript(expectedFinishedVerifyData));
        Assert.Equal(6, finishedUpdates.Count);
        observedAtTicks = ApplyRuntimeUpdates(runtime, finishedUpdates, observedAtTicks);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.False(runtime.HasResumptionMasterSecret);

        return runtime;
    }

    private static void AssertRuntimeNotClosing(QuicConnectionRuntime runtime, string stage)
    {
        Assert.True(
            runtime.Phase != QuicConnectionPhase.Closing,
            $"after {stage}: phase={runtime.Phase} terminal={runtime.TlsState.IsTerminal} " +
            $"alert={runtime.TlsState.FatalAlertCode} desc={runtime.TlsState.FatalAlertDescription} " +
            $"handshakePhase={runtime.TlsState.HandshakeTranscriptPhase} peerFinished={runtime.TlsState.PeerFinishedVerified} " +
            $"peerHandshakeCompleted={runtime.TlsState.PeerHandshakeTranscriptCompleted} handshakeKeys={runtime.TlsState.HandshakeKeysAvailable} " +
            $"oneRttKeys={runtime.TlsState.OneRttKeysAvailable} certVerified={runtime.TlsState.PeerCertificateVerifyVerified} " +
            $"certAccepted={runtime.TlsState.PeerCertificatePolicyAccepted} transportCommitted={runtime.TlsState.PeerTransportParametersCommitted}");
    }

    internal static (
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] CertificateTranscript,
        byte[] CertificateVerifyTranscript,
        byte[] FinishedTranscript) CreateClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> clientHelloTranscript,
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters,
        ECDsa leafKey,
        byte[] leafCertificateDer)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        schedule.AppendLocalHandshakeMessage(clientHelloTranscript.Span);

        byte[] serverHello = CreateServerHelloTranscript();
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(peerTransportParameters);
        byte[] certificate = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        byte[] certificateVerifyTranscriptHash = SHA256.HashData([
            .. clientHelloTranscript.Span,
            .. serverHello,
            .. encryptedExtensions,
            .. certificate,
        ]);
        byte[] certificateVerify = QuicTlsCertificateVerifyTestSupport.CreateCertificateVerifyTranscript(
            leafKey,
            certificateVerifyTranscriptHash);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(CreateServerHelloStep(serverHello));
        Assert.Equal(3, serverHelloUpdates.Count);
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters)));
        Assert.Empty(schedule.ProcessTranscriptStep(CreateCertificateStep(leafCertificateDer)));
        Assert.Single(schedule.ProcessTranscriptStep(CreateCertificateVerifyStep(certificateVerify)));
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData));
        Assert.False(serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData));

        return (
            serverHello,
            encryptedExtensions,
            certificate,
            certificateVerify,
            CreateFinishedTranscript(finishedVerifyData));
    }

    internal static (
        byte[] ServerHelloTranscript,
        byte[] EncryptedExtensionsTranscript,
        byte[] FinishedTranscript) CreateAcceptedClientHandshakeTranscriptParts(
        ReadOnlyMemory<byte> clientHelloTranscript,
        QuicTransportParameters localTransportParameters,
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot,
        long nowTicks,
        ReadOnlyMemory<byte> localHandshakePrivateKey,
        QuicTransportParameters peerTransportParameters,
        bool includeEarlyData = false)
    {
        QuicTlsKeySchedule schedule = new(localHandshakePrivateKey);
        Assert.True(schedule.TryCreateClientHello(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks,
            out _));
        schedule.AppendLocalHandshakeMessage(clientHelloTranscript.Span);

        byte[] serverHello = CreateServerHelloTranscript(selectedPreSharedKey: true);
        byte[] encryptedExtensions = CreateEncryptedExtensionsTranscript(peerTransportParameters, includeEarlyData);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = schedule.ProcessTranscriptStep(
            CreateServerHelloStep(serverHello, selectedPreSharedKey: true));
        Assert.Equal(4, serverHelloUpdates.Count);
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] serverHelloOnlyVerifyData));

        Assert.Empty(schedule.ProcessTranscriptStep(CreateEncryptedExtensionsStep(peerTransportParameters, includeEarlyData)));
        Assert.True(schedule.TryGetExpectedPeerFinishedVerifyData(out byte[] finishedVerifyData));
        Assert.False(serverHelloOnlyVerifyData.SequenceEqual(finishedVerifyData));

        return (
            serverHello,
            encryptedExtensions,
            CreateFinishedTranscript(finishedVerifyData));
    }

    internal static QuicConnectionRuntime CreateAcceptedFinishedClientRuntime(
        uint? ticketMaxEarlyDataSize = null,
        bool includeEarlyData = false)
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = CreatePeerTransportParameters();

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        long observedAtTicks = nowTicks;
        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);
        observedAtTicks = ApplyRuntimeUpdates(runtime, bootstrapUpdates, observedAtTicks);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] finishedTranscript) = CreateAcceptedClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks,
            localHandshakePrivateKey,
            peerTransportParameters,
            includeEarlyData);

        observedAtTicks = ApplyRuntimeUpdates(
            runtime,
            driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, serverHelloTranscript),
            observedAtTicks);
        observedAtTicks = ApplyRuntimeUpdates(
            runtime,
            driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, encryptedExtensionsTranscript),
            observedAtTicks);
        observedAtTicks = ApplyRuntimeUpdates(
            runtime,
            driver.ProcessCryptoFrame(QuicTlsEncryptionLevel.Handshake, finishedTranscript),
            observedAtTicks);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.HasResumptionMasterSecret);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(ReceiveProtectedHandshakeDonePacket(runtime, observedAtTicks).StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        AcknowledgeTrackedPackets(runtime);

        return runtime;
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }

        Assert.Empty(runtime.SendRuntime.SentPackets);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    internal static QuicConnectionTransitionResult ReceiveProtectedHandshakeDonePacket(
        QuicConnectionRuntime runtime,
        long observedAtTicks)
    {
        byte[] protectedPacket = CreateProtectedHandshakeDonePacket(runtime);
        QuicConnectionPathIdentity pathIdentity = runtime.ActivePath?.Identity ?? PacketPathIdentity;
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }

    internal static byte[] CreateProtectedHandshakeDonePacket(QuicConnectionRuntime runtime)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        byte[] destinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(destinationConnectionId));
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            QuicFrameTestData.BuildHandshakeDoneFrame(),
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    internal static byte[] CreatePostHandshakeTicketMessage(
        ReadOnlySpan<byte> ticket,
        ReadOnlySpan<byte> ticketNonce,
        uint ticketLifetimeSeconds = 0,
        uint ticketAgeAdd = 0,
        uint? ticketMaxEarlyDataSize = null)
    {
        if (ticket.IsEmpty)
        {
            throw new ArgumentException("The ticket must not be empty.", nameof(ticket));
        }

        if (ticketNonce.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ticketNonce));
        }

        int extensionsLength = ticketMaxEarlyDataSize.HasValue ? 8 : 0;
        int bodyLength = checked(4 + 4 + 1 + ticketNonce.Length + 2 + ticket.Length + 2 + extensionsLength);
        byte[] transcript = new byte[HandshakeHeaderLength + bodyLength];
        int index = 0;

        transcript[index++] = (byte)QuicTlsHandshakeMessageType.NewSessionTicket;
        WriteUInt24(transcript.AsSpan(index, UInt24Length), bodyLength);
        index += UInt24Length;

        BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(index, 4), ticketLifetimeSeconds);
        index += 4;
        BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(index, 4), ticketAgeAdd);
        index += 4;

        transcript[index++] = (byte)ticketNonce.Length;
        ticketNonce.CopyTo(transcript.AsSpan(index, ticketNonce.Length));
        index += ticketNonce.Length;

        WriteUInt16(transcript.AsSpan(index, UInt16Length), (ushort)ticket.Length);
        index += UInt16Length;
        ticket.CopyTo(transcript.AsSpan(index, ticket.Length));
        index += ticket.Length;

        WriteUInt16(transcript.AsSpan(index, UInt16Length), (ushort)extensionsLength);
        index += UInt16Length;

        if (ticketMaxEarlyDataSize.HasValue)
        {
            WriteUInt16(transcript.AsSpan(index, UInt16Length), EarlyDataExtensionType);
            index += UInt16Length;
            WriteUInt16(transcript.AsSpan(index, UInt16Length), sizeof(uint));
            index += UInt16Length;
            BinaryPrimitives.WriteUInt32BigEndian(transcript.AsSpan(index, sizeof(uint)), ticketMaxEarlyDataSize.Value);
            index += sizeof(uint);
        }

        return transcript;
    }

    internal static byte[] CreateUnknownPostHandshakeMessage()
    {
        return WrapHandshakeMessage((QuicTlsHandshakeMessageType)0x19, [0x00]);
    }

    internal static byte[] CreateProhibitedKeyUpdatePostHandshakeMessage()
    {
        return WrapHandshakeMessage((QuicTlsHandshakeMessageType)0x18, [0x00]);
    }

    internal static byte[] CreateMalformedKeyUpdatePostHandshakeMessage()
    {
        return WrapHandshakeMessage((QuicTlsHandshakeMessageType)0x18, [0x00, 0x01]);
    }

    internal static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 15,
            InitialSourceConnectionId = [0x01, 0x02, 0x03],
        };
    }

    internal static QuicTransportParameters CreatePeerTransportParameters()
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            OriginalDestinationConnectionId = [0x0A, 0x0B, 0x0C],
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
            InitialMaxData = DefaultConnectionFlowControlLimit,
            InitialMaxStreamDataBidiLocal = DefaultStreamFlowControlLimit,
            InitialMaxStreamDataBidiRemote = DefaultStreamFlowControlLimit,
            InitialMaxStreamDataUni = DefaultStreamFlowControlLimit,
        };
    }

    private static QuicTransportParameters CreateClientTransportParameters(
        ulong connectionFlowControlLimit = DefaultConnectionFlowControlLimit,
        ulong streamFlowControlLimit = DefaultStreamFlowControlLimit)
    {
        return new QuicTransportParameters
        {
            MaxIdleTimeout = 21,
            DisableActiveMigration = true,
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
            InitialMaxData = connectionFlowControlLimit,
            InitialMaxStreamDataBidiLocal = streamFlowControlLimit,
            InitialMaxStreamDataBidiRemote = streamFlowControlLimit,
            InitialMaxStreamDataUni = streamFlowControlLimit,
        };
    }

    private static bool TransitionHandshakePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> cryptoPayload,
        QuicTlsPacketProtectionMaterial material,
        ulong cryptoOffset,
        long observedAtTicks)
    {
        byte[] protectedPacket = BuildProtectedHandshakePacket(material, cryptoPayload, cryptoOffset);
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                PacketPathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);

        return result.StateChanged;
    }

    private static byte[] BuildProtectedHandshakePacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoOffset)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId, PacketSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoOffset,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    private static QuicTlsPacketProtectionMaterial CreateHandshakeMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x41, 16),
            CreateSequentialBytes(0x51, 12),
            CreateSequentialBytes(0x61, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));

        return material;
    }

    private static QuicTlsTranscriptStep CreateServerHelloStep(byte[] transcriptBytes, bool selectedPreSharedKey = false)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.AwaitingPeerHandshakeMessage,
            HandshakeMessageType: QuicTlsHandshakeMessageType.ServerHello,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            SelectedCipherSuite: QuicTlsCipherSuite.TlsAes128GcmSha256,
            TranscriptHashAlgorithm: QuicTlsTranscriptHashAlgorithm.Sha256,
            NamedGroup: QuicTlsNamedGroup.Secp256r1,
            KeyShare: CreateServerKeyShare(),
            PreSharedKeySelected: selectedPreSharedKey,
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateEncryptedExtensionsStep(
        QuicTransportParameters transportParameters,
        bool includeEarlyData = false)
    {
        byte[] transcriptBytes = CreateEncryptedExtensionsTranscript(transportParameters, includeEarlyData);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.PeerTransportParametersStaged,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            TransportParameters: transportParameters,
            HandshakeMessageType: QuicTlsHandshakeMessageType.EncryptedExtensions,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateStep(byte[] leafCertificateDer)
    {
        byte[] transcriptBytes = QuicTlsCertificateVerifyTestSupport.CreateCertificateTranscript(leafCertificateDer);
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.Certificate,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    private static QuicTlsTranscriptStep CreateCertificateVerifyStep(byte[] transcriptBytes)
    {
        return new QuicTlsTranscriptStep(
            QuicTlsTranscriptStepKind.Progressed,
            TranscriptPhase: QuicTlsTranscriptPhase.PeerTransportParametersStaged,
            HandshakeMessageType: QuicTlsHandshakeMessageType.CertificateVerify,
            HandshakeMessageLength: (uint)(transcriptBytes.Length - 4),
            HandshakeMessageBytes: transcriptBytes);
    }

    internal static byte[] CreateServerHelloTranscript(bool selectedPreSharedKey = false)
    {
        byte[] keyShare = CreateServerKeyShare();
        int extensionsLength = 6 + 4 + 2 + 2 + keyShare.Length + (selectedPreSharedKey ? 6 : 0);
        byte[] body = new byte[40 + extensionsLength];
        int index = 0;

        WriteUInt16(body.AsSpan(index, 2), TlsLegacyVersion);
        index += 2;

        CreateSequentialBytes(0x40, 32).CopyTo(body.AsSpan(index, 32));
        index += 32;

        body[index++] = 0;
        WriteUInt16(body.AsSpan(index, 2), TlsAes128GcmSha256Value);
        index += 2;
        body[index++] = NullCompressionMethod;

        WriteUInt16(body.AsSpan(index, 2), (ushort)extensionsLength);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), SupportedVersionsExtensionType);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), 2);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), Tls13Version);
        index += 2;

        WriteUInt16(body.AsSpan(index, 2), KeyShareExtensionType);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)(2 + 2 + keyShare.Length));
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), Secp256r1NamedGroup);
        index += 2;
        WriteUInt16(body.AsSpan(index, 2), (ushort)keyShare.Length);
        index += 2;
        keyShare.CopyTo(body.AsSpan(index, keyShare.Length));

        if (selectedPreSharedKey)
        {
            index += keyShare.Length;

            WriteUInt16(body.AsSpan(index, 2), 0x0029);
            index += 2;
            WriteUInt16(body.AsSpan(index, 2), 2);
            index += 2;
            WriteUInt16(body.AsSpan(index, 2), 0);
        }

        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.ServerHello, body);
    }

    private static byte[] CreateServerKeyShare()
    {
        using ECDiffieHellman serverKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        serverKeyPair.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = CreateScalar(0x02),
        });

        ECParameters parameters = serverKeyPair.ExportParameters(true);
        byte[] keyShare = new byte[1 + (2 * Secp256r1CoordinateLength)];
        keyShare[0] = UncompressedPointFormat;
        parameters.Q.X!.CopyTo(keyShare, 1);
        parameters.Q.Y!.CopyTo(keyShare, 33);
        return keyShare;
    }

    internal static byte[] CreateEncryptedExtensionsTranscript(
        QuicTransportParameters transportParameters,
        bool includeEarlyData = false)
    {
        byte[] encodedTransportParameters = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            encodedTransportParameters,
            out int bytesWritten));

        byte[] transcript = new byte[512];
        int extensionsLength = 4 + bytesWritten + (includeEarlyData ? 4 : 0);
        int messageLength = 2 + extensionsLength;
        int index = 0;

        transcript[index++] = (byte)QuicTlsHandshakeMessageType.EncryptedExtensions;
        WriteUInt24(transcript.AsSpan(index, UInt24Length), messageLength);
        index += UInt24Length;

        WriteUInt16(transcript.AsSpan(index, UInt16Length), (ushort)extensionsLength);
        index += UInt16Length;

        WriteUInt16(transcript.AsSpan(index, UInt16Length), QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        index += UInt16Length;
        WriteUInt16(transcript.AsSpan(index, UInt16Length), (ushort)bytesWritten);
        index += UInt16Length;
        encodedTransportParameters.AsSpan(..bytesWritten).CopyTo(transcript.AsSpan(index, bytesWritten));
        index += bytesWritten;

        if (includeEarlyData)
        {
            WriteUInt16(transcript.AsSpan(index, UInt16Length), EarlyDataExtensionType);
            index += UInt16Length;
            WriteUInt16(transcript.AsSpan(index, UInt16Length), 0);
            index += UInt16Length;
        }

        Array.Resize(ref transcript, HandshakeHeaderLength + messageLength);
        return transcript;
    }

    private static byte[] CreateFinishedTranscript(ReadOnlySpan<byte> verifyData)
    {
        return WrapHandshakeMessage(QuicTlsHandshakeMessageType.Finished, verifyData);
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private static byte[] WrapHandshakeMessage(QuicTlsHandshakeMessageType messageType, ReadOnlySpan<byte> body)
    {
        byte[] transcript = new byte[HandshakeHeaderLength + body.Length];
        transcript[0] = (byte)messageType;
        WriteUInt24(transcript.AsSpan(1, UInt24Length), body.Length);
        body.CopyTo(transcript.AsSpan(HandshakeHeaderLength));
        return transcript;
    }

    private static long ApplyRuntimeUpdates(
        QuicConnectionRuntime runtime,
        IReadOnlyList<QuicTlsStateUpdate> updates,
        long observedAtTicks)
    {
        Assert.NotEmpty(updates);

        foreach (QuicTlsStateUpdate update in updates)
        {
            _ = runtime.Transition(
                new QuicConnectionTlsStateUpdatedEvent(observedAtTicks, update),
                nowTicks: observedAtTicks);
            observedAtTicks++;
        }

        return observedAtTicks;
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
}

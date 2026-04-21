using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

internal static class QuicS13ApplicationSendDelayTestSupport
{
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

    internal static QuicConnectionRuntime CreateFinishedClientRuntimeWithValidatedActivePath(
        ulong localBidirectionalSendLimit = 32,
        int maximumCandidatePaths = 8,
        int maximumRecentlyValidatedPaths = 8)
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = new()
        {
            MaxIdleTimeout = 21,
            OriginalDestinationConnectionId = [0x0A, 0x0B, 0x0C],
            InitialSourceConnectionId = [0x0A, 0x0B, 0x0C],
            InitialMaxData = Math.Max(localBidirectionalSendLimit, 64UL),
            InitialMaxStreamDataBidiLocal = Math.Max(localBidirectionalSendLimit, 64UL),
            InitialMaxStreamDataBidiRemote = Math.Max(localBidirectionalSendLimit, 64UL),
            InitialMaxStreamDataUni = Math.Max(localBidirectionalSendLimit, 64UL),
        };

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(localBidirectionalSendLimit: localBidirectionalSendLimit),
            new FakeMonotonicClock(0),
            maximumCandidatePaths: maximumCandidatePaths,
            maximumRecentlyValidatedPaths: maximumRecentlyValidatedPaths,
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
            byte[] finishedTranscript) = QuicPostHandshakeTicketTestSupport.CreateClientHandshakeTranscriptParts(
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

        Assert.True(runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out handshakePacketMaterial));
        transcriptOffset += (ulong)serverHelloTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            encryptedExtensionsTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 3));
        transcriptOffset += (ulong)encryptedExtensionsTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            certificateTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 4));
        transcriptOffset += (ulong)certificateTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            certificateVerifyTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 5));
        transcriptOffset += (ulong)certificateVerifyTranscript.Length;

        Assert.True(TransitionHandshakePacket(
            runtime,
            finishedTranscript,
            handshakePacketMaterial,
            transcriptOffset,
            observedAtTicks: 6));

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.HasResumptionMasterSecret);

        QuicConnectionPathIdentity validatedPath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 7,
                validatedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 7);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(validatedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            validatedPath,
            observedAtTicks: 8);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(validatedPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.IsValidated);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        return runtime;
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

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}

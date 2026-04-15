using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0137")]
public sealed class REQ_QUIC_CRT_0137
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcceptedPSKAttemptCompletesTheAbbreviatedResumptionFlightAndReachesActive()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateAcceptedFinishedClientRuntime();

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.HasResumptionMasterSecret);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AcceptedPSKAttemptUsesTheAbbreviatedTranscriptWithoutCertificateMessages()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);

        Assert.Equal(2, bootstrapUpdates.Count);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Unknown, driver.State.ResumptionAttemptDisposition);

        (
            byte[] serverHelloTranscript,
            byte[] encryptedExtensionsTranscript,
            byte[] finishedTranscript) = QuicPostHandshakeTicketTestSupport.CreateAcceptedClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks,
            localHandshakePrivateKey,
            peerTransportParameters);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            serverHelloTranscript);

        Assert.Equal(5, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.ServerHello, serverHelloUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable, serverHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, serverHelloUpdates[1].ResumptionAttemptDisposition);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, serverHelloUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, serverHelloUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[4].Kind);

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, driver.State.ResumptionAttemptDisposition);
        Assert.False(driver.State.IsTerminal);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.OneRttKeysAvailable);

        IReadOnlyList<QuicTlsStateUpdate> encryptedExtensionsUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript);

        Assert.Equal(2, encryptedExtensionsUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, encryptedExtensionsUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensionsUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable, encryptedExtensionsUpdates[1].Kind);
        Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, encryptedExtensionsUpdates[1].PeerEarlyDataDisposition);
        Assert.Equal(QuicTlsEarlyDataDisposition.Rejected, driver.State.PeerEarlyDataDisposition);

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(8, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, finishedUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, finishedUpdates[3].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, finishedUpdates[3].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable, finishedUpdates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable, finishedUpdates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.ResumptionMasterSecretAvailable, finishedUpdates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[7].Kind);

        Assert.True(driver.State.PeerFinishedVerified);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.HasResumptionMasterSecret);
        Assert.False(driver.State.PeerCertificateVerifyVerified);
        Assert.False(driver.State.PeerCertificatePolicyAccepted);
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));

        IReadOnlyList<QuicTlsStateUpdate> commitUpdates = driver.CommitPeerTransportParameters(peerTransportParameters);
        Assert.Single(commitUpdates);
        Assert.Equal(QuicTlsUpdateKind.PeerTransportParametersCommitted, commitUpdates[0].Kind);
        Assert.True(driver.State.PeerTransportParametersCommitted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RejectedPSKAttemptStillFallsBackToTheExistingFullHandshakePath()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();

        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] leafCertificateDer = QuicTlsCertificateVerifyTestSupport.CreateLeafCertificateDer(leafKey);
        byte[] pinnedPeerLeafCertificateSha256 = SHA256.HashData(leafCertificateDer);

        using QuicConnectionRuntime earlyDataRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.False(earlyDataRuntime.IsEarlyDataAdmissionOpen);

        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256: pinnedPeerLeafCertificateSha256);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        IReadOnlyList<QuicTlsStateUpdate> bootstrapUpdates = driver.StartHandshake(
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks);

        Assert.Equal(2, bootstrapUpdates.Count);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Unknown, driver.State.ResumptionAttemptDisposition);

        IReadOnlyList<QuicTlsStateUpdate> serverHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            QuicPostHandshakeTicketTestSupport.CreateServerHelloTranscript());

        Assert.Equal(5, serverHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, serverHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable, serverHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, serverHelloUpdates[1].ResumptionAttemptDisposition);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, serverHelloUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, serverHelloUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, serverHelloUpdates[4].Kind);

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, driver.State.ResumptionAttemptDisposition);
        Assert.False(driver.State.IsTerminal);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.OneRttKeysAvailable);

        (
            _,
            byte[] encryptedExtensionsTranscript,
            byte[] certificateTranscript,
            byte[] certificateVerifyTranscript,
            byte[] finishedTranscript) = QuicPostHandshakeTicketTestSupport.CreateClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localHandshakePrivateKey,
            peerTransportParameters,
            leafKey,
            leafCertificateDer);

        IReadOnlyList<QuicTlsStateUpdate> encryptedExtensionsUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            encryptedExtensionsTranscript);
        Assert.Single(encryptedExtensionsUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, encryptedExtensionsUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensionsUpdates[0].HandshakeMessageType);
        IReadOnlyList<QuicTlsStateUpdate> certificateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateTranscript);
        Assert.Single(certificateUpdates);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, certificateUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Certificate, certificateUpdates[0].HandshakeMessageType);
        Assert.Equal(3, driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            certificateVerifyTranscript).Count);

        IReadOnlyList<QuicTlsStateUpdate> finishedUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            finishedTranscript);

        Assert.Equal(8, finishedUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, finishedUpdates[0].Kind);
        Assert.Equal(QuicTlsHandshakeMessageType.Finished, finishedUpdates[0].HandshakeMessageType);
        Assert.Equal(QuicTlsUpdateKind.PeerFinishedVerified, finishedUpdates[1].Kind);
        Assert.Equal(QuicTlsUpdateKind.CryptoDataAvailable, finishedUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, finishedUpdates[3].Kind);
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, finishedUpdates[3].EncryptionLevel);
        Assert.Equal(QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable, finishedUpdates[4].Kind);
        Assert.Equal(QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable, finishedUpdates[5].Kind);
        Assert.Equal(QuicTlsUpdateKind.ResumptionMasterSecretAvailable, finishedUpdates[6].Kind);
        Assert.Equal(QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted, finishedUpdates[7].Kind);

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, driver.State.ResumptionAttemptDisposition);
        Assert.False(driver.State.IsTerminal);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.HasResumptionMasterSecret);
        Assert.True(driver.State.CanCommitPeerTransportParameters(peerTransportParameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BootstrapWithoutDormantMaterialStaysOnTheNonResumptionPath()
    {
        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client);

        long nowTicks = Stopwatch.Frequency;
        Assert.True(clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()),
            nowTicks).StateChanged);

        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(
                QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime));

        Assert.False(parsedClientHello.HasPskKeyExchangeModes);
        Assert.False(parsedClientHello.HasPreSharedKey);
        Assert.False(parsedClientHello.HasEarlyData);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Unknown, clientRuntime.TlsState.ResumptionAttemptDisposition);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
        Assert.False(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Resum", "EarlyData", "Psk", "Binder"];

        string[] publicMembers = typeof(QuicConnection).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Select(member => $"{type.FullName}.{member.Name}"))
            .Concat(
                typeof(QuicConnection).Assembly.GetExportedTypes()
                    .Select(type => type.FullName ?? type.Name))
            .ToArray();

        Assert.DoesNotContain(publicMembers, member =>
            forbiddenFragments.Any(fragment => member.Contains(fragment, StringComparison.OrdinalIgnoreCase)));
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}

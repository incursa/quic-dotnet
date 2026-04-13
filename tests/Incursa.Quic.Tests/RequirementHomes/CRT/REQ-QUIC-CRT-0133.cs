using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0133")]
public sealed class REQ_QUIC_CRT_0133
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResumptionAttemptRejectedServerHelloFallsBackToTheExistingFullHandshakePath()
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

        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(bootstrapUpdates[1].CryptoData.ToArray());
        Assert.True(parsedClientHello.HasPskKeyExchangeModes);
        Assert.True(parsedClientHello.HasPreSharedKey);
        Assert.True(parsedClientHello.PreSharedKeyIsLastExtension);
        Assert.True(QuicResumptionClientHelloTestSupport.VerifyBinder(
            bootstrapUpdates[1].CryptoData.ToArray(),
            detachedResumptionTicketSnapshot));

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

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Rejected, driver.State.ResumptionAttemptDisposition);
        Assert.False(driver.State.IsTerminal);
        Assert.True(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.True(driver.State.OneRttKeysAvailable);
        Assert.True(driver.State.HasResumptionMasterSecret);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ResumptionAttemptAcceptedServerHelloIsRecognizedAtTheBranchPoint()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters();

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

        IReadOnlyList<QuicTlsStateUpdate> acceptedServerHelloUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.Handshake,
            QuicPostHandshakeTicketTestSupport.CreateServerHelloTranscript(selectedPreSharedKey: true));

        Assert.Equal(5, acceptedServerHelloUpdates.Count);
        Assert.Equal(QuicTlsUpdateKind.TranscriptProgressed, acceptedServerHelloUpdates[0].Kind);
        Assert.Equal(QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable, acceptedServerHelloUpdates[1].Kind);
        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, acceptedServerHelloUpdates[1].ResumptionAttemptDisposition);
        Assert.Equal(QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable, acceptedServerHelloUpdates[2].Kind);
        Assert.Equal(QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable, acceptedServerHelloUpdates[3].Kind);
        Assert.Equal(QuicTlsUpdateKind.KeysAvailable, acceptedServerHelloUpdates[4].Kind);

        Assert.Equal(QuicTlsResumptionAttemptDisposition.Accepted, driver.State.ResumptionAttemptDisposition);
        Assert.False(driver.State.IsTerminal);
        Assert.True(driver.State.HandshakeKeysAvailable);
        Assert.False(driver.State.OneRttKeysAvailable);
        Assert.False(driver.State.PeerHandshakeTranscriptCompleted);
        Assert.False(driver.State.HasResumptionMasterSecret);
        Assert.True(driver.State.HasAnyAvailableKeys);
        Assert.True(driver.State.HasAnyPacketProtectionMaterial);
        Assert.False(earlyDataRuntime.IsEarlyDataAdmissionOpen);
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
    public void EarlyDataGateStaysExplicitlyClosedAcrossBothBranchOutcomes()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot();

        using QuicConnectionRuntime rejectedRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        using QuicConnectionRuntime acceptedRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.False(rejectedRuntime.IsEarlyDataAdmissionOpen);
        Assert.False(acceptedRuntime.IsEarlyDataAdmissionOpen);
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

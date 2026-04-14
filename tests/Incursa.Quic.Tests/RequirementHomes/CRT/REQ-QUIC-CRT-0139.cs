using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0139")]
public sealed class REQ_QUIC_CRT_0139
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DetachedCarrierCapturesTheMinimumEarlyDataPrerequisiteMaterialAfterTheCorrectPrecursorPath()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();

        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0xDE, 0xAD, 0xBE, 0xEF],
            [0x01, 0x02, 0x03],
            ticketLifetimeSeconds: 7200,
            ticketAgeAdd: 0x01020304,
            ticketMaxEarlyDataSize: 4096);

        Assert.False(runtime.IsEarlyDataAdmissionOpen);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(1234, ticketUpdates[0]),
            nowTicks: 1234).StateChanged);

        Assert.True(runtime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        Assert.True(detachedResumptionTicketSnapshot!.HasResumptionCredentialMaterial);
        Assert.Equal(4096u, detachedResumptionTicketSnapshot.TicketMaxEarlyDataSize);
        Assert.True(detachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial);
        Assert.NotNull(detachedResumptionTicketSnapshot.PeerTransportParameters);
        Assert.Equal(21UL, detachedResumptionTicketSnapshot.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(detachedResumptionTicketSnapshot.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal([0x0A, 0x0B, 0x0C], detachedResumptionTicketSnapshot.PeerTransportParameters.InitialSourceConnectionId);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LaterManagedClientSetupStoresTheRicherDetachedCarrierAsDormantInternalState()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.NotNull(clientRuntime.DormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot!.HasResumptionCredentialMaterial);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial);
        Assert.Equal(4096u, clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketMaxEarlyDataSize);
        Assert.NotNull(clientRuntime.DormantDetachedResumptionTicketSnapshot.PeerTransportParameters);
        Assert.Equal(21UL, clientRuntime.DormantDetachedResumptionTicketSnapshot.PeerTransportParameters!.MaxIdleTimeout);
        Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot.PeerTransportParameters.DisableActiveMigration);
        Assert.Equal([0x0A, 0x0B, 0x0C], clientRuntime.DormantDetachedResumptionTicketSnapshot.PeerTransportParameters.InitialSourceConnectionId);
        Assert.Equal(QuicConnectionPhase.Establishing, clientRuntime.Phase);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WithoutTheEarlyDataTicketSignalTheNewPrerequisiteMaterialIsAbsent()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x10, 0x20, 0x30, 0x40],
            [0x09, 0x08],
            ticketLifetimeSeconds: 3600,
            ticketAgeAdd: 0x0A0B0C0D);

        Assert.False(runtime.IsEarlyDataAdmissionOpen);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(4321, ticketUpdates[0]),
            nowTicks: 4321).StateChanged);

        Assert.True(runtime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        Assert.True(detachedResumptionTicketSnapshot!.HasResumptionCredentialMaterial);
        Assert.Null(detachedResumptionTicketSnapshot.TicketMaxEarlyDataSize);
        Assert.False(detachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial);
        Assert.NotNull(detachedResumptionTicketSnapshot.PeerTransportParameters);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDataAdmissionRemainsExplicitlyClosedBeforeAndAfterCapture()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);

        using QuicConnectionRuntime bootstrapRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client);

        Assert.False(bootstrapRuntime.IsEarlyDataAdmissionOpen);

        using QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);

        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;
        Assert.True(clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters()),
            nowTicks).StateChanged);

        QuicResumptionClientHelloTestSupport.ParsedClientHello parsedClientHello =
            QuicResumptionClientHelloTestSupport.ParseClientHello(
                QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime));

        Assert.True(parsedClientHello.HasPskKeyExchangeModes);
        Assert.True(parsedClientHello.HasPreSharedKey);
        Assert.False(parsedClientHello.HasEarlyData);
        Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExpose0RttOrBroaderResumptionPromises()
    {
        string[] forbiddenFragments = ["0Rtt", "EarlyData", "Resum", "Psk", "Binder", "AntiReplay"];

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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AcceptedResumptionSuccessRemainsUnchangedWhenTheRicherDetachedCarrierIsPresent()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4096);
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicTransportParameters localTransportParameters = QuicPostHandshakeTicketTestSupport.CreateBootstrapLocalTransportParameters();
        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();

        using QuicConnectionRuntime runtime = new(
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
            byte[] finishedTranscript) = QuicPostHandshakeTicketTestSupport.CreateAcceptedClientHandshakeTranscriptParts(
            bootstrapUpdates[1].CryptoData,
            localTransportParameters,
            detachedResumptionTicketSnapshot,
            nowTicks,
            localHandshakePrivateKey,
            peerTransportParameters);

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
        Assert.NotNull(runtime.DormantDetachedResumptionTicketSnapshot);
        Assert.True(runtime.DormantDetachedResumptionTicketSnapshot!.HasEarlyDataPrerequisiteMaterial);
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }

    private static long ApplyRuntimeUpdates(
        QuicConnectionRuntime runtime,
        IReadOnlyList<QuicTlsStateUpdate> updates,
        long observedAtTicks)
    {
        Assert.NotEmpty(updates);

        foreach (QuicTlsStateUpdate update in updates)
        {
            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionTlsStateUpdatedEvent(observedAtTicks, update),
                nowTicks: observedAtTicks);

            Assert.True(result.StateChanged);
            observedAtTicks++;
        }

        return observedAtTicks;
    }
}

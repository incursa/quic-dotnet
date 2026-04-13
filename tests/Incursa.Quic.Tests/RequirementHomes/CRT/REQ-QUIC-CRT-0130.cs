using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0130")]
public sealed class REQ_QUIC_CRT_0130
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OriginatingClientRuntimeExportsDetachedOpaqueCarrierAfterRealTicketIngress()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            [0x01, 0x02]);

        Assert.False(runtime.TryExportDetachedResumptionTicketSnapshot(out _));

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, ticketUpdates[0]),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.True(runtime.HasOwnedResumptionTicket);
        Assert.False(runtime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
        Assert.True(runtime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        Assert.Equal(expectedTicketBytes, detachedResumptionTicketSnapshot!.TicketBytes.ToArray());
        Assert.Equal(expectedTicketBytes, runtime.OwnedResumptionTicketBytes.ToArray());
        Assert.Equal(expectedTicketBytes, runtime.TlsState.PostHandshakeTicketBytes.ToArray());
        Assert.True(runtime.TlsState.HasPostHandshakeTicket);

        byte[] ownedRuntimeTicketBytes = RequireBackingArray(runtime.OwnedResumptionTicketBytes);
        byte[] detachedCarrierTicketBytes = RequireBackingArray(detachedResumptionTicketSnapshot.TicketBytes);
        Assert.NotSame(ownedRuntimeTicketBytes, detachedCarrierTicketBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OriginatingClientRuntimeDoesNotExportADetachedCarrierBeforeAnyTicketIsCaptured()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.False(runtime.TryExportDetachedResumptionTicketSnapshot(out _));
        Assert.False(runtime.HasOwnedResumptionTicket);
        Assert.False(runtime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LaterManagedClientSetupStoresDetachedCarrierAsDormantStateWithoutChangingHandshakeBehavior()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0x10, 0x20, 0x30, 0x40];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            [0x09, 0x08]);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, ticketUpdates[0]),
            nowTicks: 0).StateChanged);

        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        Assert.False(originRuntime.IsEarlyDataAdmissionOpen);

        using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate("localhost");
        IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

        QuicListenerOptions listenerOptions = new()
        {
            ListenEndPoint = listenEndPoint,
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = 1,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
        };

        await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
        Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();

        QuicClientConnectionOptions clientOptions = QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(
            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
            trustedServerCertificate: serverCertificate);

        QuicClientConnectionSettings clientSettings = QuicClientConnectionOptionsValidator.Capture(
            clientOptions,
            nameof(clientOptions),
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);
        Assert.NotNull(clientSettings.DetachedResumptionTicketSnapshot);
        Assert.Equal(expectedTicketBytes, clientSettings.DetachedResumptionTicketSnapshot!.TicketBytes.ToArray());

        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions, detachedResumptionTicketSnapshot).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
            Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
            Assert.False(clientRuntime.HasOwnedResumptionTicket);
            Assert.Equal(expectedTicketBytes, clientRuntime.DormantDetachedResumptionTicketSnapshot!.TicketBytes.ToArray());
            Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
            Assert.Equal(QuicConnectionPhase.Active, clientRuntime.Phase);
            Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted);
            Assert.True(clientRuntime.TlsState.OneRttKeysAvailable);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DuplicateTicketUpdatesDoNotReplaceTheDetachedCarrierOnceItHasBeenHandedOff()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] firstTicketBytes = [0x11, 0x22, 0x33];
        byte[] duplicateTicketBytes = [0x44, 0x55, 0x66];
        byte[] firstTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            firstTicketBytes,
            [0x01]);
        byte[] duplicateTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            duplicateTicketBytes,
            [0x02]);

        IReadOnlyList<QuicTlsStateUpdate> firstTicketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            firstTicketMessage);
        Assert.Single(firstTicketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                0,
                firstTicketUpdates[0]),
            nowTicks: 0).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);

        using QuicConnectionRuntime laterRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        byte[] detachedCarrierBytesBeforeDuplicate = RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot!.TicketBytes);

        IReadOnlyList<QuicTlsStateUpdate> duplicateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            duplicateTicketMessage);
        Assert.Empty(duplicateUpdates);

        Assert.False(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PostHandshakeTicketAvailable,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed,
                    TicketBytes: duplicateTicketBytes)),
            nowTicks: 1).StateChanged);

        Assert.Equal(firstTicketBytes, detachedResumptionTicketSnapshot.TicketBytes.ToArray());
        Assert.Equal(firstTicketBytes, laterRuntime.DormantDetachedResumptionTicketSnapshot!.TicketBytes.ToArray());
        Assert.Same(detachedCarrierBytesBeforeDuplicate, RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot!.TicketBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotParticipateInDetachedHandoff()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot = new(
            new byte[] { 0x01, 0x02, 0x03 },
            ticketNonce: ReadOnlyMemory<byte>.Empty,
            ticketLifetimeSeconds: 0,
            ticketAgeAdd: 0,
            capturedAtTicks: 0,
            resumptionMasterSecret: new byte[] { 0x04 });

        Assert.Throws<ArgumentException>(() => new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDataGateStaysExplicitlyClosedBeforeAndAfterDetachedHandoff()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketBytes = [0xA1, 0xA2, 0xA3];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            ticketBytes,
            [0x09]);

        Assert.False(originRuntime.IsEarlyDataAdmissionOpen);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, ticketUpdates[0]),
            nowTicks: 0).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.False(originRuntime.IsEarlyDataAdmissionOpen);

        using QuicConnectionRuntime laterRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.False(laterRuntime.IsEarlyDataAdmissionOpen);
        Assert.True(laterRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(laterRuntime.HasOwnedResumptionTicket);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceDoesNotExposeTicketHandoffResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Ownership", "Resum", "Ticket", "EarlyData", "Handoff", "Detached", "Dormant"];

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

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        FieldInfo? runtimeField = typeof(QuicConnection).GetField("runtime", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(runtimeField);
        return Assert.IsType<QuicConnectionRuntime>(runtimeField!.GetValue(connection));
    }

    private static byte[] RequireBackingArray(ReadOnlyMemory<byte> memory)
    {
        Assert.True(MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment));
        Assert.NotNull(segment.Array);
        return segment.Array!;
    }
}

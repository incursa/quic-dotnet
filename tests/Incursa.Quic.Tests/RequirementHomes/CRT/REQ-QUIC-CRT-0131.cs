using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0131")]
public sealed class REQ_QUIC_CRT_0131
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DetachedCarrierCapturesTheMinimumInternalResumptionCredentialMaterialAfterRealTicketIngress()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] expectedTicketNonce = [0x01, 0x02, 0x03];
        const uint expectedTicketLifetimeSeconds = 7200;
        const uint expectedTicketAgeAdd = 0x01020304;
        const long capturedAtTicks = 1234;
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            expectedTicketNonce,
            expectedTicketLifetimeSeconds,
            expectedTicketAgeAdd);

        Assert.True(runtime.HasResumptionMasterSecret);
        byte[] runtimeResumptionMasterSecret = runtime.ResumptionMasterSecret.ToArray();
        byte[] bridgeResumptionMasterSecret = driver.State.ResumptionMasterSecret.ToArray();
        Assert.NotEmpty(runtimeResumptionMasterSecret);
        Assert.True(driver.State.HasResumptionMasterSecret);
        Assert.NotEmpty(bridgeResumptionMasterSecret);
        Assert.False(runtime.TryExportDetachedResumptionTicketSnapshot(out _));

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(capturedAtTicks, ticketUpdates[0]),
            nowTicks: capturedAtTicks).StateChanged);

        Assert.True(runtime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);
        Assert.Equal(expectedTicketBytes, detachedResumptionTicketSnapshot!.TicketBytes.ToArray());
        Assert.Equal(expectedTicketNonce, detachedResumptionTicketSnapshot.TicketNonce.ToArray());
        Assert.Equal(expectedTicketLifetimeSeconds, detachedResumptionTicketSnapshot.TicketLifetimeSeconds);
        Assert.Equal(expectedTicketAgeAdd, detachedResumptionTicketSnapshot.TicketAgeAdd);
        Assert.Equal(capturedAtTicks, detachedResumptionTicketSnapshot.CapturedAtTicks);
        Assert.Equal(runtimeResumptionMasterSecret, detachedResumptionTicketSnapshot.ResumptionMasterSecret.ToArray());
        Assert.True(detachedResumptionTicketSnapshot.HasResumptionCredentialMaterial);
        Assert.Equal(expectedTicketNonce, runtime.OwnedResumptionTicketNonce.ToArray());
        Assert.Equal(expectedTicketLifetimeSeconds, runtime.OwnedResumptionTicketLifetimeSeconds);
        Assert.Equal(expectedTicketAgeAdd, runtime.OwnedResumptionTicketAgeAdd);
        Assert.Equal(capturedAtTicks, runtime.OwnedResumptionTicketCapturedAtTicks);
        Assert.Equal(expectedTicketNonce, driver.State.PostHandshakeTicketNonce.ToArray());
        Assert.Equal(expectedTicketLifetimeSeconds, driver.State.PostHandshakeTicketLifetimeSeconds);
        Assert.Equal(expectedTicketAgeAdd, driver.State.PostHandshakeTicketAgeAdd);

        Assert.NotSame(
            RequireBackingArray(runtime.OwnedResumptionTicketBytes),
            RequireBackingArray(detachedResumptionTicketSnapshot.TicketBytes));
        Assert.NotSame(
            RequireBackingArray(runtime.ResumptionMasterSecret),
            RequireBackingArray(detachedResumptionTicketSnapshot.ResumptionMasterSecret));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LaterManagedClientSetupStoresTheRicherDetachedCarrierAsDormantState()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0x10, 0x20, 0x30, 0x40];
        byte[] expectedTicketNonce = [0x09, 0x08];
        const uint expectedTicketLifetimeSeconds = 3600;
        const uint expectedTicketAgeAdd = 0x0A0B0C0D;
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            expectedTicketNonce,
            expectedTicketLifetimeSeconds,
            expectedTicketAgeAdd);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(321, ticketUpdates[0]),
            nowTicks: 321).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);

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
            Assert.Equal(expectedTicketNonce, clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketNonce.ToArray());
            Assert.Equal(expectedTicketLifetimeSeconds, clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketLifetimeSeconds);
            Assert.Equal(expectedTicketAgeAdd, clientRuntime.DormantDetachedResumptionTicketSnapshot.TicketAgeAdd);
            Assert.Equal(detachedResumptionTicketSnapshot.CapturedAtTicks, clientRuntime.DormantDetachedResumptionTicketSnapshot.CapturedAtTicks);
            Assert.Equal(
                detachedResumptionTicketSnapshot.ResumptionMasterSecret.ToArray(),
                clientRuntime.DormantDetachedResumptionTicketSnapshot.ResumptionMasterSecret.ToArray());
            Assert.True(clientRuntime.DormantDetachedResumptionTicketSnapshot.HasResumptionCredentialMaterial);
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
    public void NoDetachedCredentialCarrierExistsBeforeAnyTicketIsCaptured()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.True(runtime.HasResumptionMasterSecret);
        Assert.False(runtime.HasOwnedResumptionTicket);
        Assert.False(runtime.TryExportDetachedResumptionTicketSnapshot(out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DuplicateTicketUpdatesDoNotReplaceTheRicherDetachedCarrierOnceItHasBeenHandedOff()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] firstTicketBytes = [0x11, 0x22, 0x33];
        byte[] firstTicketNonce = [0x01];
        byte[] duplicateTicketBytes = [0x44, 0x55, 0x66];
        byte[] duplicateTicketNonce = [0x02];
        byte[] firstTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            firstTicketBytes,
            firstTicketNonce,
            ticketLifetimeSeconds: 100,
            ticketAgeAdd: 0x11111111);
        byte[] duplicateTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            duplicateTicketBytes,
            duplicateTicketNonce,
            ticketLifetimeSeconds: 200,
            ticketAgeAdd: 0x22222222);

        IReadOnlyList<QuicTlsStateUpdate> firstTicketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            firstTicketMessage);
        Assert.Single(firstTicketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(100, firstTicketUpdates[0]),
            nowTicks: 100).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.NotNull(detachedResumptionTicketSnapshot);

        using QuicConnectionRuntime laterRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        byte[] detachedTicketBytesBeforeDuplicate = RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot!.TicketBytes);
        byte[] detachedResumptionSecretBeforeDuplicate = RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot.ResumptionMasterSecret);

        IReadOnlyList<QuicTlsStateUpdate> duplicateUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            duplicateTicketMessage);
        Assert.Empty(duplicateUpdates);

        Assert.False(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                101,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PostHandshakeTicketAvailable,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed,
                    TicketNonce: duplicateTicketNonce,
                    TicketLifetimeSeconds: 200,
                    TicketAgeAdd: 0x22222222,
                    TicketBytes: duplicateTicketBytes)),
            nowTicks: 101).StateChanged);

        Assert.Equal(firstTicketBytes, laterRuntime.DormantDetachedResumptionTicketSnapshot.TicketBytes.ToArray());
        Assert.Equal(firstTicketNonce, laterRuntime.DormantDetachedResumptionTicketSnapshot.TicketNonce.ToArray());
        Assert.Equal(100, laterRuntime.DormantDetachedResumptionTicketSnapshot.CapturedAtTicks);
        Assert.Same(detachedTicketBytesBeforeDuplicate, RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot.TicketBytes));
        Assert.Same(detachedResumptionSecretBeforeDuplicate, RequireBackingArray(laterRuntime.DormantDetachedResumptionTicketSnapshot.ResumptionMasterSecret));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleDoesNotParticipateInDetachedCredentialCapture()
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
    public void EarlyDataGateRemainsExplicitlyClosedBeforeAndAfterRicherCaptureAndHandoff()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0xA1, 0xA2, 0xA3],
            [0x09],
            ticketLifetimeSeconds: 500,
            ticketAgeAdd: 0x01010101);

        Assert.False(originRuntime.IsEarlyDataAdmissionOpen);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(200, ticketUpdates[0]),
            nowTicks: 200).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));
        Assert.False(originRuntime.IsEarlyDataAdmissionOpen);

        using QuicConnectionRuntime laterRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Client,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.False(laterRuntime.IsEarlyDataAdmissionOpen);
        Assert.True(laterRuntime.HasDormantDetachedResumptionTicketSnapshot);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceStillDoesNotExposeTicketResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Ownership", "Resum", "Ticket", "EarlyData", "Psk", "Binder", "Dormant"];

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
    public async Task HandshakeBootstrapBehaviorRemainsUnchangedWhenTheRicherDormantCarrierIsPresent()
    {
        using QuicConnectionRuntime originRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            [0x31, 0x32, 0x33],
            [0x07],
            ticketLifetimeSeconds: 90,
            ticketAgeAdd: 0x0F0E0D0C);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);
        Assert.Single(ticketUpdates);
        Assert.True(originRuntime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(400, ticketUpdates[0]),
            nowTicks: 400).StateChanged);
        Assert.True(originRuntime.TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot));

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

        Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(clientOptions, detachedResumptionTicketSnapshot).AsTask();

        await Task.WhenAll(acceptTask, connectTask).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnection serverConnection = await acceptTask;
        QuicConnection clientConnection = await connectTask;

        try
        {
            QuicConnectionRuntime clientRuntime = GetRuntime(clientConnection);
            Assert.Equal(QuicConnectionPhase.Active, clientRuntime.Phase);
            Assert.True(clientRuntime.PeerHandshakeTranscriptCompleted);
            Assert.True(clientRuntime.TlsState.OneRttKeysAvailable);
            Assert.False(clientRuntime.HasOwnedResumptionTicket);
            Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
            Assert.False(clientRuntime.IsEarlyDataAdmissionOpen);
        }
        finally
        {
            await serverConnection.DisposeAsync();
            await clientConnection.DisposeAsync();
        }
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

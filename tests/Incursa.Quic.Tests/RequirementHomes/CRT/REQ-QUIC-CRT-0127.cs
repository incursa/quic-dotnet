using System.Reflection;
using System.Runtime.InteropServices;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0127")]
public sealed class REQ_QUIC_CRT_0127
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleRuntimeOwnsAnOpaqueResumptionTicketSnapshotAfterARealOneRttNewSessionTicketIngress()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] expectedTicketBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            expectedTicketBytes,
            [0x01, 0x02]);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.Equal(QuicTlsUpdateKind.PostHandshakeTicketAvailable, ticketUpdates[0].Kind);
        Assert.False(runtime.HasOwnedResumptionTicket);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, ticketUpdates[0]),
            nowTicks: 0);

        Assert.True(result.StateChanged);
        Assert.True(runtime.HasOwnedResumptionTicket);
        Assert.Equal(expectedTicketBytes, runtime.OwnedResumptionTicketBytes.ToArray());
        Assert.Equal(expectedTicketBytes, runtime.TlsState.PostHandshakeTicketBytes.ToArray());
        Assert.True(runtime.TlsState.HasPostHandshakeTicket);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);

        byte[] ownedRuntimeTicketBytes = RequireBackingArray(runtime.OwnedResumptionTicketBytes);
        byte[] bridgeTicketBytes = RequireBackingArray(runtime.TlsState.PostHandshakeTicketBytes);
        Assert.NotSame(ownedRuntimeTicketBytes, bridgeTicketBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleRuntimeHasNoOwnedResumptionTicketSnapshotBeforeAnyTicketArrives()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.False(runtime.HasOwnedResumptionTicket);
        Assert.True(runtime.OwnedResumptionTicketBytes.IsEmpty);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientRoleRuntimeKeepsTheFirstOpaqueSnapshotWhenDuplicateTicketUpdatesArrive()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] firstTicketBytes = [0x10, 0x20, 0x30];
        byte[] duplicateTicketBytes = [0x40, 0x50, 0x60];
        byte[] firstTicketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            firstTicketBytes,
            [0x01]);

        IReadOnlyList<QuicTlsStateUpdate> firstUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            firstTicketMessage);

        Assert.Single(firstUpdates);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, firstUpdates[0]),
            nowTicks: 0).StateChanged);

        byte[] ownedTicketBytesBeforeDuplicate = RequireBackingArray(runtime.OwnedResumptionTicketBytes);

        QuicTlsStateUpdate duplicateUpdate = new(
            QuicTlsUpdateKind.PostHandshakeTicketAvailable,
            TranscriptPhase: QuicTlsTranscriptPhase.Completed,
            TicketBytes: duplicateTicketBytes);

        QuicConnectionTransitionResult duplicateResult = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(1, duplicateUpdate),
            nowTicks: 1);

        Assert.False(duplicateResult.StateChanged);
        Assert.Equal(firstTicketBytes, runtime.OwnedResumptionTicketBytes.ToArray());
        Assert.Same(ownedTicketBytesBeforeDuplicate, RequireBackingArray(runtime.OwnedResumptionTicketBytes));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerRoleRuntimeDoesNotParticipateInTicketOwnership()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);
        byte[] ticketBytes = [0x01, 0x02, 0x03];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PostHandshakeTicketAvailable,
                    TranscriptPhase: QuicTlsTranscriptPhase.Completed,
                    TicketBytes: ticketBytes)),
            nowTicks: 0);

        Assert.False(result.StateChanged);
        Assert.False(runtime.HasOwnedResumptionTicket);
        Assert.True(runtime.OwnedResumptionTicketBytes.IsEmpty);
        Assert.True(runtime.TlsState.PostHandshakeTicketBytes.IsEmpty);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDataGateStaysExplicitlyClosedBeforeAndAfterTicketCapture()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicTlsTransportBridgeDriver driver = QuicPostHandshakeTicketTestSupport.CreateFinishedClientDriver();
        byte[] ticketBytes = [0xA1, 0xA2, 0xA3];
        byte[] ticketMessage = QuicPostHandshakeTicketTestSupport.CreatePostHandshakeTicketMessage(
            ticketBytes,
            [0x09]);

        Assert.False(runtime.IsEarlyDataAdmissionOpen);

        IReadOnlyList<QuicTlsStateUpdate> ticketUpdates = driver.ProcessCryptoFrame(
            QuicTlsEncryptionLevel.OneRtt,
            ticketMessage);

        Assert.Single(ticketUpdates);
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(0, ticketUpdates[0]),
            nowTicks: 0).StateChanged);
        Assert.True(runtime.HasOwnedResumptionTicket);
        Assert.False(runtime.IsEarlyDataAdmissionOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PublicSurfaceDoesNotExposeTicketOwnershipResumptionOrEarlyDataPromises()
    {
        string[] forbiddenFragments = ["Ownership", "Resum", "Ticket", "EarlyData"];

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

    private static byte[] RequireBackingArray(ReadOnlyMemory<byte> memory)
    {
        Assert.True(MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment));
        Assert.NotNull(segment.Array);
        return segment.Array!;
    }
}

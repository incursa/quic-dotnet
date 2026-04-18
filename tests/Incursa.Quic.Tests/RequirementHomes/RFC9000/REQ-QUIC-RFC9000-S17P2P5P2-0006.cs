namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0006">A client MUST set the Destination Connection ID field of this Initial packet to the value from the Source Connection ID field in the Retry packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0006">A client MUST set the Destination Connection ID field of this Initial packet to the value from the Source Connection ID field in the Retry packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0006")]
    public void ClientUsesTheRetrySourceConnectionIdAsTheNextInitialDestinationConnectionId()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionTransitionResult retryResult = runtime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicConnectionSendDatagramEffect replayDatagram = default!;
        bool observedReplayDatagram = false;
        foreach (QuicConnectionEffect effect in retryResult.Effects)
        {
            if (effect is QuicConnectionSendDatagramEffect sendDatagramEffect)
            {
                replayDatagram = sendDatagramEffect;
                observedReplayDatagram = true;
                break;
            }
        }

        Assert.True(observedReplayDatagram);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.OriginalDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.True(packetCoordinator.TryOpenInitialPacket(
            replayDatagram.Datagram.Span,
            serverProtection,
            out byte[] openedReplayPacket,
            out _,
            out _));

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedReplayPacket,
            out _,
            out _,
            out ReadOnlySpan<byte> openedDestinationConnectionId,
            out _,
            out _));
        Assert.True(QuicS17P2P5P2TestSupport.RetrySourceConnectionId.AsSpan().SequenceEqual(openedDestinationConnectionId));
    }
}

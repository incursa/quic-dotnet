namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0008">The client MUST NOT change the Source Connection ID because the server could include the connection ID as part of its token validation logic; see Section 8.1.4.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0008")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0008">The client MUST NOT change the Source Connection ID because the server could include the connection ID as part of its token validation logic; see Section 8.1.4.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0008")]
    public void ClientPreservesTheSourceConnectionIdWhenReplayingInitialPackets()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);

        QuicConnectionTransitionResult retryResult = runtime.Transition(retryReceivedEvent, nowTicks: 1);
        QuicConnectionSendDatagramEffect replayDatagram = Assert.Single(retryResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator packetCoordinator = new();
        Assert.True(packetCoordinator.TryOpenInitialPacket(
            replayDatagram.Datagram.Span,
            serverProtection,
            out byte[] openedReplayPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedReplayPacket,
            out _,
            out _,
            out ReadOnlySpan<byte> openedDestinationConnectionId,
            out ReadOnlySpan<byte> openedSourceConnectionId,
            out _));
        Assert.Equal(QuicS17P2P5P2TestSupport.RetrySourceConnectionId, openedDestinationConnectionId.ToArray());
        Assert.Equal(QuicS17P2P5P2TestSupport.InitialSourceConnectionId, openedSourceConnectionId.ToArray());
    }
}

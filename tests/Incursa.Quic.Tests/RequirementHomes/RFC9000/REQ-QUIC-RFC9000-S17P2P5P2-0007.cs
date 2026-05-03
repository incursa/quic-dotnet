namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0007">It also MUST set the Token field to the token provided in the Retry packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0007")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0007">It also MUST set the Token field to the token provided in the Retry packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0007")]
    public void ClientSetsTheRetryTokenWhenReplayingInitialPackets()
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
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));
        Assert.True(QuicVariableLengthInteger.TryParse(
            versionSpecificData,
            out ulong tokenLength,
            out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)QuicS17P2P5P2TestSupport.RetryToken.Length, tokenLength);
        Assert.Equal(
            QuicS17P2P5P2TestSupport.RetryToken,
            versionSpecificData.Slice(tokenLengthBytesConsumed, QuicS17P2P5P2TestSupport.RetryToken.Length).ToArray());
    }
}

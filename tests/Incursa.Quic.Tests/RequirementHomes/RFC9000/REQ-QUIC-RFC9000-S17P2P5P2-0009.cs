namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0009">A Retry packet does not include a packet number and MUST NOT be explicitly acknowledged by a client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0009")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P2-0009">A Retry packet does not include a packet number and MUST NOT be explicitly acknowledged by a client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P2-0009")]
    public void RetryPacketsAreNotExplicitlyAcknowledgedByTheClient()
    {
        QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        QuicConnectionRetryReceivedEvent retryReceivedEvent = QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1);

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryReceivedEvent.Datagram.Span, out _));

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

        ReadOnlySpan<byte> payload = openedReplayPacket.AsSpan(payloadOffset, payloadLength);
        Assert.False(QuicFrameCodec.TryParseAckFrame(payload, out _, out _));

        ReadOnlySpan<byte> cryptoPayload = QuicS13AckPiggybackTestSupport.SkipPadding(payload);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            cryptoPayload,
            out QuicCryptoFrame cryptoFrame,
            out int cryptoBytesConsumed));
        Assert.True(cryptoFrame.CryptoData.Length > 0);
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(cryptoPayload[cryptoBytesConsumed..]).IsEmpty);
    }
}

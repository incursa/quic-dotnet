using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0021">For instance, a client MUST NOT send an ACK frame in a 0-RTT packet, because that can only acknowledge a 1-RTT packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0021")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPingPayloadDoesNotParseAsAnAckFrame()
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(QuicS17P2P3TestSupport.CreatePingPayload(), out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AckResponsePayloadParsesAsTheForbiddenZeroRttAckShape()
    {
        byte[] ackResponsePayload = QuicS17P2P3TestSupport.CreateAckResponsePayload();

        Assert.True(QuicFrameCodec.TryParseAckFrame(ackResponsePayload, out QuicAckFrame parsedAckFrame, out _));
        Assert.Equal(0UL, parsedAckFrame.LargestAcknowledged);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void BootstrapZeroRttPacketDoesNotCarryAnAckFrameAtTheEarlyDataBoundary()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 1);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));

        byte[] ackResponsePacket = QuicS17P2P3TestSupport.BuildExpectedZeroRttPacket(
            QuicS17P2P3TestSupport.CreateAckResponsePayload(),
            zeroRttMaterial);

        Assert.False(zeroRttSend.Datagram.Span.SequenceEqual(ackResponsePacket));
    }
}

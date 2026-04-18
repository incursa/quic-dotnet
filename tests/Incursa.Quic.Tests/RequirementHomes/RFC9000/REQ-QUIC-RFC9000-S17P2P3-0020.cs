using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0020")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BootstrapZeroRttPacketsCarryOnlyThePingProbePayload()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
        Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(zeroRttSend.Datagram.Span));

        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        byte[] expectedPingPacket = QuicS17P2P3TestSupport.BuildExpectedZeroRttPacket(
            QuicS17P2P3TestSupport.CreatePingPayload(),
            zeroRttMaterial);

        Assert.True(expectedPingPacket.AsSpan().SequenceEqual(zeroRttSend.Datagram.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BootstrapZeroRttPacketsDoNotMatchAnAckResponsePayload()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        QuicConnectionSendDatagramEffect zeroRttSend = Assert.Single(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
        byte[] pingPacket = zeroRttSend.Datagram.ToArray();

        byte[] ackResponsePayload = QuicS17P2P3TestSupport.CreateAckResponsePayload();
        Assert.True(QuicFrameCodec.TryParseAckFrame(ackResponsePayload, out _, out _));

        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        byte[] ackResponsePacket = QuicS17P2P3TestSupport.BuildExpectedZeroRttPacket(
            ackResponsePayload,
            zeroRttMaterial);

        Assert.False(pingPacket.AsSpan().SequenceEqual(ackResponsePacket));
    }
}

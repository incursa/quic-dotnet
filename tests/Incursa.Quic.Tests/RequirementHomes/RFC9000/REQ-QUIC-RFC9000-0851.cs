namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0851">A UDP datagram MAY include one or more QUIC packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0851")]
public sealed class REQ_QUIC_RFC9000_0851
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-0851")]
    [Trait("Category", "Positive")]
    public void RuntimeAcceptsACoalescedServerFlightDuringHandshake()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        Assert.True(QuicPacketParser.TryGetPacketLength(scenario.CoalescedDatagram, out int firstPacketLength));
        Assert.Equal(scenario.InitialPacket.Length, firstPacketLength);

        ReadOnlySpan<byte> remainingDatagram = scenario.CoalescedDatagram.AsSpan(firstPacketLength);
        Assert.True(QuicPacketParser.TryGetPacketLength(remainingDatagram, out int secondPacketLength));
        Assert.Equal(scenario.HandshakePacket.Length, secondPacketLength);

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }
}

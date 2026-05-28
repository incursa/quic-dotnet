// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1015">Once a client has received a Handshake packet from a server, it MUST use Handshake packets to send subsequent cryptographic handshake messages and acknowledgments to the server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1015")]
public sealed class REQ_QUIC_RFC9000_1015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrailingServerHandshakePacketCommitsPeerTransportParametersAfterTheLeadingInitialPacket()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult initialResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);
        Assert.True(initialResult.StateChanged);

        QuicConnectionTransitionResult handshakeResult = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.HandshakePacket),
            nowTicks: 11);

        Assert.True(handshakeResult.StateChanged);
        Assert.True(scenario.ClientRuntime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(out _));
        Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialServerPacketAloneDoesNotCommitPeerTransportParameters()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.InitialPacket),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.False(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.Null(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CoalescedInitialAndHandshakeFlightCommitsPeerTransportParameters()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }
}

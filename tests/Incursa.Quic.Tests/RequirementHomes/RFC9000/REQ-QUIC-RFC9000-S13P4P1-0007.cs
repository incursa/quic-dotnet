// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0007")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransitionCoalescedServerFlight_ReportsEcnCountsForInitialAndHandshakePacketSpaces()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram,
                EcnCounts: new QuicEcnCounts(1, 0, 0)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, expectEcn: true);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, expectEcn: true);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransitionCoalescedServerFlight_DoesNotReportEcnCountsWithoutAnEcnObservation()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, expectEcn: false);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, expectEcn: false);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TransitionHandshakeBeforeInitialInACoalescedDatagram_StillReportsEcnCountsForBothPacketSpaces()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        byte[] datagram = [.. scenario.HandshakePacket, .. scenario.InitialPacket];

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                PathIdentity: scenario.PathIdentity,
                Datagram: datagram,
                EcnCounts: new QuicEcnCounts(1, 0, 0)),
            nowTicks: 11);

        Assert.True(result.StateChanged);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, expectEcn: true);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, expectEcn: true);
    }

    private static void AssertOutgoingEcnAckFrame(
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario,
        QuicPacketNumberSpace packetNumberSpace,
        bool expectEcn)
    {
        Assert.True(
            scenario.ClientRuntime.SendRuntime.FlowController.TryBuildAckFrame(
                packetNumberSpace,
                nowMicros: 10,
                out QuicAckFrame frame));
        Assert.Equal(expectEcn ? (byte)0x03 : (byte)0x02, frame.FrameType);
        if (expectEcn)
        {
            Assert.NotNull(frame.EcnCounts);
            Assert.Equal(1UL, frame.EcnCounts!.Value.Ect0Count);
            Assert.Equal(0UL, frame.EcnCounts!.Value.Ect1Count);
            Assert.Equal(0UL, frame.EcnCounts!.Value.EcnCeCount);
        }
        else
        {
            Assert.Null(frame.EcnCounts);
        }
    }
}

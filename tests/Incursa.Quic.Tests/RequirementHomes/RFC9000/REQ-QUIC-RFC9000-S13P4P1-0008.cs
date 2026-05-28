// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P1-0008")]
public sealed class REQ_QUIC_RFC9000_S13P4P1_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransitionCoalescedServerFlightWithApplicationPacket_ReportsEcnCountsForInitialHandshakeAndApplicationPacketSpaces()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        byte[] applicationPacket = BuildApplicationPacket(scenario);
        byte[] datagram =
        [
            .. scenario.InitialPacket,
            .. scenario.HandshakePacket,
            .. applicationPacket,
        ];

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: datagram,
                EcnCounts: new QuicEcnCounts(1, 0, 0)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, expectEcn: true);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, expectEcn: true);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.ApplicationData, expectEcn: true);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TransitionCoalescedServerFlightWithApplicationPacket_DoesNotReportEcnCountsWithoutAnEcnObservation()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        byte[] applicationPacket = BuildApplicationPacket(scenario);
        byte[] datagram =
        [
            .. scenario.InitialPacket,
            .. scenario.HandshakePacket,
            .. applicationPacket,
        ];

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: datagram),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, expectEcn: false);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, expectEcn: false);
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.ApplicationData, expectEcn: false);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TransitionHandshakeBeforeInitialAndApplicationInACoalescedDatagram_StillReportsEcnCountsForAllThreePacketSpaces()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        byte[] applicationPacket = BuildApplicationPacket(scenario);
        byte[] datagram =
        [
            .. scenario.HandshakePacket,
            .. scenario.InitialPacket,
            .. applicationPacket,
        ];

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
        AssertOutgoingEcnAckFrame(scenario, QuicPacketNumberSpace.ApplicationData, expectEcn: true);
    }

    private static byte[] BuildApplicationPacket(
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario)
    {
        QuicTransportParameters peerTransportParameters =
            QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(scenario.ServerSourceConnectionId);
        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            scenario.ClientRuntime,
            peerTransportParameters);

        return QuicConnectionIdLifecycleTestSupport.BuildOneRttPacket(
            scenario.ClientRuntime,
            scenario.ServerSourceConnectionId,
            QuicS12P3TestSupport.CreatePingPayload());
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

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S13P4P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AckFramesReportEcnOnlyWhenReceivedEcnFieldsAreAvailable()
    {
        foreach ((ulong packetNumber, QuicEcnCounts? ecnCounts) in new (ulong, QuicEcnCounts?)[]
        {
            (8, null),
            (9, new QuicEcnCounts(1, 0, 0)),
            (10, new QuicEcnCounts(0, 2, 0)),
            (11, new QuicEcnCounts(0, 0, 3)),
        })
        {
            QuicAckGenerationState tracker = new();

            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 1000 + packetNumber,
                ecnCounts: ecnCounts);

            Assert.True(tracker.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 4000,
                out QuicAckFrame frame));
            Assert.Equal(packetNumber, frame.LargestAcknowledged);

            if (ecnCounts is { } expectedEcnCounts)
            {
                Assert.Equal((byte)0x03, frame.FrameType);
                Assert.NotNull(frame.EcnCounts);
                Assert.Equal(expectedEcnCounts.Ect0Count, frame.EcnCounts!.Value.Ect0Count);
                Assert.Equal(expectedEcnCounts.Ect1Count, frame.EcnCounts.Value.Ect1Count);
                Assert.Equal(expectedEcnCounts.EcnCeCount, frame.EcnCounts.Value.EcnCeCount);
            }
            else
            {
                Assert.Equal((byte)0x02, frame.FrameType);
                Assert.Null(frame.EcnCounts);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EachPacketNumberSpaceMaintainsIndependentAckAndEcnState()
    {
        foreach (ulong packetNumber in new[] { 1UL, 9UL, 63UL })
        {
            QuicAckGenerationState tracker = new();

            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.Initial,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 1000,
                ecnCounts: new QuicEcnCounts(1, 0, 0));
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.Handshake,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 1010,
                ecnCounts: new QuicEcnCounts(0, 2, 0));
            tracker.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 1020,
                ecnCounts: new QuicEcnCounts(0, 0, 3));

            AssertEcnAckFrame(tracker, QuicPacketNumberSpace.Initial, packetNumber, new QuicEcnCounts(1, 0, 0));
            AssertEcnAckFrame(tracker, QuicPacketNumberSpace.Handshake, packetNumber, new QuicEcnCounts(0, 2, 0));
            AssertEcnAckFrame(tracker, QuicPacketNumberSpace.ApplicationData, packetNumber, new QuicEcnCounts(0, 0, 3));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CoalescedInitialAndHandshakePacketsIncrementEcnCountsOncePerQuicPacket()
    {
        foreach ((QuicEcnCounts ecnCounts, bool reverseOrder) in new[]
        {
            (new QuicEcnCounts(1, 0, 0), false),
            (new QuicEcnCounts(0, 1, 0), true),
            (new QuicEcnCounts(0, 0, 1), false),
        })
        {
            QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
                QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
            byte[] datagram = reverseOrder
                ? [.. scenario.HandshakePacket, .. scenario.InitialPacket]
                : scenario.CoalescedDatagram;

            QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10,
                    PathIdentity: scenario.PathIdentity,
                    Datagram: datagram,
                    EcnCounts: ecnCounts),
                nowTicks: 10);

            Assert.True(result.StateChanged);
            AssertRuntimeEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, ecnCounts);
            AssertRuntimeEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, ecnCounts);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CoalescedInitialHandshakeAndOneRttPacketsIncrementEcnCountsForAllThreeSpaces()
    {
        foreach ((QuicEcnCounts ecnCounts, bool reverseHandshakeAndInitial) in new[]
        {
            (new QuicEcnCounts(1, 0, 0), false),
            (new QuicEcnCounts(0, 1, 0), true),
            (new QuicEcnCounts(0, 0, 1), false),
        })
        {
            QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
                QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
            byte[] applicationPacket = BuildApplicationPacket(scenario);
            byte[] datagram = reverseHandshakeAndInitial
                ? [.. scenario.HandshakePacket, .. scenario.InitialPacket, .. applicationPacket]
                : [.. scenario.InitialPacket, .. scenario.HandshakePacket, .. applicationPacket];

            QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10,
                    PathIdentity: scenario.PathIdentity,
                    Datagram: datagram,
                    EcnCounts: ecnCounts),
                nowTicks: 10);

            Assert.True(result.StateChanged);
            AssertRuntimeEcnAckFrame(scenario, QuicPacketNumberSpace.Initial, ecnCounts);
            AssertRuntimeEcnAckFrame(scenario, QuicPacketNumberSpace.Handshake, ecnCounts);
            AssertRuntimeEcnAckFrame(scenario, QuicPacketNumberSpace.ApplicationData, ecnCounts);
        }
    }

    private static void AssertEcnAckFrame(
        QuicAckGenerationState tracker,
        QuicPacketNumberSpace packetNumberSpace,
        ulong expectedLargestAcknowledged,
        QuicEcnCounts expectedEcnCounts)
    {
        Assert.True(tracker.TryBuildAckFrame(packetNumberSpace, nowMicros: 1100, out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.Equal(expectedLargestAcknowledged, frame.LargestAcknowledged);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(expectedEcnCounts.Ect0Count, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(expectedEcnCounts.Ect1Count, frame.EcnCounts.Value.Ect1Count);
        Assert.Equal(expectedEcnCounts.EcnCeCount, frame.EcnCounts.Value.EcnCeCount);
    }

    private static void AssertRuntimeEcnAckFrame(
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario,
        QuicPacketNumberSpace packetNumberSpace,
        QuicEcnCounts expectedEcnCounts)
    {
        Assert.True(scenario.ClientRuntime.SendRuntime.FlowController.TryBuildAckFrame(
            packetNumberSpace,
            nowMicros: 10,
            out QuicAckFrame frame));
        Assert.Equal((byte)0x03, frame.FrameType);
        Assert.NotNull(frame.EcnCounts);
        Assert.Equal(expectedEcnCounts.Ect0Count, frame.EcnCounts!.Value.Ect0Count);
        Assert.Equal(expectedEcnCounts.Ect1Count, frame.EcnCounts.Value.Ect1Count);
        Assert.Equal(expectedEcnCounts.EcnCeCount, frame.EcnCounts.Value.EcnCeCount);
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
}

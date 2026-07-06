// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_CoalescedDatagram_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0851")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CoalescedDatagramFuzz_AcceptsCompletePacketSequencesAndRejectsTruncatedTrailingPackets()
    {
        for (int iteration = 0; iteration < 4; iteration++)
        {
            QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
                QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
            byte[] coalescedDatagram = iteration % 2 == 0
                ? [.. scenario.InitialPacket, .. scenario.HandshakePacket]
                : [.. scenario.InitialPacket, .. scenario.HandshakePacket, .. scenario.InitialPacket];

            int packetOffset = 0;
            int observedPackets = 0;
            while (packetOffset < coalescedDatagram.Length)
            {
                Assert.True(QuicPacketParser.TryGetPacketLength(
                    coalescedDatagram.AsSpan(packetOffset),
                    out int packetLength));
                Assert.True(packetLength > 0);
                packetOffset += packetLength;
                observedPackets++;
            }

            Assert.Equal(coalescedDatagram.Length, packetOffset);
            Assert.Equal(iteration % 2 == 0 ? 2 : 3, observedPackets);

            QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10 + iteration,
                    PathIdentity: scenario.PathIdentity,
                    Datagram: coalescedDatagram),
                nowTicks: 10 + iteration);

            Assert.True(result.StateChanged);
            Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable);

            byte[] truncatedTrailingPacketDatagram =
            [
                .. scenario.InitialPacket,
                .. scenario.HandshakePacket.AsSpan(0, scenario.HandshakePacket.Length - 1),
            ];

            Assert.True(QuicPacketParser.TryGetPacketLength(
                truncatedTrailingPacketDatagram,
                out int firstPacketLength));
            Assert.Equal(scenario.InitialPacket.Length, firstPacketLength);
            Assert.False(QuicPacketParser.TryGetPacketLength(
                truncatedTrailingPacketDatagram.AsSpan(firstPacketLength),
                out _));
        }
    }
}

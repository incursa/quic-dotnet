// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S6_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketLossDeclarationRequiresUnacknowledgedInFlightEarlierPacket()
    {
        foreach ((bool acknowledged, bool inFlight, ulong packetNumber, ulong largestAcknowledgedPacketNumber, bool expectedCanDeclareLost) in new[]
        {
            (false, true, 0UL, 1UL, true),
            (false, true, 9UL, 11UL, true),
            (true, true, 9UL, 11UL, false),
            (false, false, 9UL, 11UL, false),
            (false, true, 11UL, 11UL, false),
            (false, true, 12UL, 11UL, false),
        })
        {
            Assert.Equal(expectedCanDeclareLost, QuicRecoveryTiming.CanDeclarePacketLost(
                acknowledged,
                inFlight,
                packetNumber,
                largestAcknowledgedPacketNumber));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoSelectionUsesAvailableCryptoSpaceOrInitialFallback()
    {
        (ulong NowMicros, ulong? InitialPtoMicros, ulong? HandshakePtoMicros, bool HandshakeKeysAvailable, bool ExpectedSelected, ulong ExpectedPtoTimeMicros, QuicPacketNumberSpace ExpectedPacketNumberSpace)[] cases =
        [
            (0UL, 1UL, null, false, true, 1UL, QuicPacketNumberSpace.Initial),
            (1_000UL, 2_500UL, 1_800UL, true, true, 2_800UL, QuicPacketNumberSpace.Handshake),
            (1_000UL, 1_000UL, 5_000UL, true, true, 6_000UL, QuicPacketNumberSpace.Handshake),
            (1_000UL, 1_000UL, 500UL, false, true, 2_000UL, QuicPacketNumberSpace.Initial),
            (1_000UL, null, 500UL, false, false, 0UL, default),
            (1_000UL, null, null, true, false, 0UL, default),
        ];

        foreach ((ulong nowMicros, ulong? initialPtoMicros, ulong? handshakePtoMicros, bool handshakeKeysAvailable, bool expectedSelected, ulong expectedPtoTimeMicros, QuicPacketNumberSpace expectedPacketNumberSpace) in cases)
        {
            Assert.Equal(expectedSelected, QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
                nowMicros,
                initialPtoMicros,
                handshakePtoMicros,
                handshakeKeysAvailable,
                out ulong selectedPtoTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            if (expectedSelected)
            {
                Assert.Equal(expectedPtoTimeMicros, selectedPtoTimeMicros);
                Assert.Equal(expectedPacketNumberSpace, selectedPacketNumberSpace);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PtoComputationIsSeparateForEachPacketNumberSpace()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, bool handshakeConfirmed, ulong maxAckDelayMicros, bool expectedComputed, ulong expectedProbeTimeoutMicros) in new[]
        {
            (QuicPacketNumberSpace.Initial, false, 500UL, true, 2_000UL),
            (QuicPacketNumberSpace.Handshake, false, 500UL, true, 2_000UL),
            (QuicPacketNumberSpace.ApplicationData, false, 500UL, false, 0UL),
            (QuicPacketNumberSpace.ApplicationData, true, 0UL, true, 2_000UL),
            (QuicPacketNumberSpace.ApplicationData, true, 500UL, true, 2_500UL),
        })
        {
            Assert.Equal(expectedComputed, QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                packetNumberSpace,
                smoothedRttMicros: 1_000,
                rttVarMicros: 200,
                maxAckDelayMicros: maxAckDelayMicros,
                handshakeConfirmed: handshakeConfirmed,
                out ulong probeTimeoutMicros));

            if (expectedComputed)
            {
                Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RetryPacketsAreNotClassifiedAsAcknowledgingPacketNumberSpace()
    {
        (byte[] DestinationConnectionId, byte[] SourceConnectionId, byte[] RetrySpecificData)[] cases =
        [
            ([0x11], [0x22], [0x33]),
            ([0x11, 0x12], [0x22], [0x33, 0x34]),
            ([0x11], [0x22, 0x23], [0x33, 0x34, 0x35]),
        ];

        foreach ((byte[] destinationConnectionId, byte[] sourceConnectionId, byte[] retrySpecificData) in cases)
        {
            byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: 1,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], [0x01], [0xBB]));
            byte[] retryPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x70,
                version: 1,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData: retrySpecificData);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialPacketNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.Initial, initialPacketNumberSpace);
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
        }
    }
}

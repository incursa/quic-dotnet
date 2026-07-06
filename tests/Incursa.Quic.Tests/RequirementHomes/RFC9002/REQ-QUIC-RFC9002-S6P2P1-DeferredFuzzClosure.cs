// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S6P2P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryComputeProbeTimeoutMicros_AppliesPtoFormulaAndEarlySpaceAckDelayRules()
    {
        foreach ((QuicPacketNumberSpace packetNumberSpace, ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros, ulong timerGranularityMicros, bool handshakeConfirmed) in new[]
        {
            (QuicPacketNumberSpace.Initial, 0UL, 0UL, 1_000UL, 1UL, false),
            (QuicPacketNumberSpace.Handshake, 1_000UL, 250UL, 500UL, 1UL, false),
            (QuicPacketNumberSpace.ApplicationData, 1_000UL, 250UL, 500UL, 1UL, true),
            (QuicPacketNumberSpace.ApplicationData, 1_000UL, 62UL, 500UL, 252UL, true),
            (QuicPacketNumberSpace.ApplicationData, 1_000UL, 64UL, 500UL, 252UL, true),
        })
        {
            Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                packetNumberSpace,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                handshakeConfirmed,
                out ulong probeTimeoutMicros,
                timerGranularityMicros));

            ulong expectedMaxAckDelayMicros = packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
                ? 0
                : maxAckDelayMicros;
            ulong expectedProbeTimeoutMicros = smoothedRttMicros
                + Math.Max(4 * rttVarMicros, timerGranularityMicros)
                + expectedMaxAckDelayMicros;

            Assert.Equal(Math.Max(expectedProbeTimeoutMicros, timerGranularityMicros), probeTimeoutMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbeTimeoutBackoff_DoublesAndResetsOnlyForEligibleEvents()
    {
        foreach ((ulong baseProbeTimeoutMicros, int ptoCount) in new[]
        {
            (1UL, 0),
            (1_250UL, 1),
            (2_500UL, 2),
            (7_500UL, 3),
        })
        {
            ulong expectedBackedOffProbeTimeoutMicros = baseProbeTimeoutMicros;
            for (int index = 0; index < ptoCount; index++)
            {
                expectedBackedOffProbeTimeoutMicros *= 2;
            }

            Assert.Equal(
                expectedBackedOffProbeTimeoutMicros,
                QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(baseProbeTimeoutMicros, ptoCount));

            Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ptoCount,
                acknowledgmentReceived: true,
                acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.ApplicationData,
                handshakeConfirmed: true));

            Assert.Equal(ptoCount, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ptoCount,
                acknowledgmentReceived: true,
                acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.Initial,
                handshakeConfirmed: false));

            Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
                ptoCount,
                acknowledgmentReceived: true,
                acknowledgmentPacketNumberSpace: QuicPacketNumberSpace.Initial,
                handshakeConfirmed: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P1-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrySelectRecoveryTimerMicros_PrefersLossDetectionOverPto()
    {
        foreach ((ulong? lossDetectionTimerMicros, ulong? probeTimeoutMicros, bool expectedSelected, ulong expectedTimerMicros) in new[]
        {
            ((ulong?)null, (ulong?)null, false, 0UL),
            ((ulong?)null, (ulong?)1_500UL, true, 1_500UL),
            ((ulong?)2_800UL, (ulong?)1_500UL, true, 2_800UL),
            ((ulong?)1_800UL, (ulong?)1_800UL, true, 1_800UL),
            ((ulong?)0UL, (ulong?)3_500UL, true, 0UL),
        })
        {
            Assert.Equal(expectedSelected, QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
                lossDetectionTimerMicros,
                probeTimeoutMicros,
                out ulong selectedTimerMicros));

            if (expectedSelected)
            {
                Assert.Equal(expectedTimerMicros, selectedTimerMicros);
            }
        }
    }
}

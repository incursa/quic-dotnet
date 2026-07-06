// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_2_1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-2-1-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbeTimeoutPeriodIsAtLeastTimerGranularity()
    {
        foreach ((ulong smoothedRttMicros, ulong rttVarMicros, ulong timerGranularityMicros, ulong expectedProbeTimeoutMicros) in new[]
        {
            (0UL, 0UL, 1UL, 1UL),
            (0UL, 0UL, 252UL, 252UL),
            (0UL, 62UL, 252UL, 252UL),
            (0UL, 63UL, 252UL, 252UL),
            (0UL, 64UL, 252UL, 256UL),
            (1_000UL, 0UL, 1_250UL, 2_250UL),
            (1_000UL, 250UL, 1UL, 2_000UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.Initial,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros: 0,
                handshakeConfirmed: false,
                out ulong probeTimeoutMicros,
                timerGranularityMicros));

            Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);
            Assert.True(probeTimeoutMicros >= timerGranularityMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-1-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InitialAndHandshakeProbeTimeoutSelectionUsesTheEarlierDeadline()
    {
        foreach ((ulong? initialProbeTimeoutMicros, ulong? handshakeProbeTimeoutMicros, bool expectedSelected, ulong expectedProbeTimeoutMicros) in new[]
        {
            ((ulong?)null, (ulong?)null, false, 0UL),
            ((ulong?)1_000UL, (ulong?)null, true, 1_000UL),
            ((ulong?)null, (ulong?)1_500UL, true, 1_500UL),
            ((ulong?)1_000UL, (ulong?)1_500UL, true, 1_000UL),
            ((ulong?)1_500UL, (ulong?)1_000UL, true, 1_000UL),
            ((ulong?)1_250UL, (ulong?)1_250UL, true, 1_250UL),
        })
        {
            Assert.Equal(expectedSelected, QuicRecoveryTiming.TrySelectInitialOrHandshakeProbeTimeoutMicros(
                initialProbeTimeoutMicros,
                handshakeProbeTimeoutMicros,
                out ulong selectedProbeTimeoutMicros));

            if (expectedSelected)
            {
                Assert.Equal(expectedProbeTimeoutMicros, selectedProbeTimeoutMicros);
            }
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-1-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationDataProbeTimeoutIsGatedByHandshakeConfirmation()
    {
        foreach ((bool handshakeConfirmed, ulong maxAckDelayMicros, bool expectedComputed, ulong expectedProbeTimeoutMicros) in new[]
        {
            (false, 0UL, false, 0UL),
            (false, 500UL, false, 0UL),
            (true, 0UL, true, 2_000UL),
            (true, 500UL, true, 2_500UL),
            (true, 2_000UL, true, 4_000UL),
        })
        {
            Assert.Equal(expectedComputed, QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.ApplicationData,
                smoothedRttMicros: 1_000,
                rttVarMicros: 250,
                maxAckDelayMicros,
                handshakeConfirmed,
                out ulong probeTimeoutMicros,
                timerGranularityMicros: 1));

            Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);
        }
    }
}

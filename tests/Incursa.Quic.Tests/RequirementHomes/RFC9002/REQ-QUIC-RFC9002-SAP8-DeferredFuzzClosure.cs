// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP8_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP8-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrySelectLossTimeAndSpaceMicros_ReturnsEarliestNonZeroLossTime()
    {
        foreach ((ulong? initialLossTimeMicros, ulong? handshakeLossTimeMicros, ulong? applicationDataLossTimeMicros, bool expectedSelected, ulong expectedLossTimeMicros, QuicPacketNumberSpace expectedSpace) in new[]
        {
            ((ulong?)null, (ulong?)null, (ulong?)null, false, 0UL, QuicPacketNumberSpace.Initial),
            ((ulong?)0UL, (ulong?)0UL, (ulong?)0UL, false, 0UL, QuicPacketNumberSpace.Initial),
            ((ulong?)2_500UL, (ulong?)1_800UL, (ulong?)3_000UL, true, 1_800UL, QuicPacketNumberSpace.Handshake),
            ((ulong?)1UL, (ulong?)1UL, (ulong?)1UL, true, 1UL, QuicPacketNumberSpace.Initial),
            ((ulong?)0UL, (ulong?)4_000UL, (ulong?)2_000UL, true, 2_000UL, QuicPacketNumberSpace.ApplicationData),
        })
        {
            Assert.Equal(expectedSelected, QuicRecoveryTiming.TrySelectLossTimeAndSpaceMicros(
                initialLossTimeMicros,
                handshakeLossTimeMicros,
                applicationDataLossTimeMicros,
                out ulong selectedLossTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            if (expectedSelected)
            {
                Assert.Equal(expectedLossTimeMicros, selectedLossTimeMicros);
                Assert.Equal(expectedSpace, selectedPacketNumberSpace);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP8-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TrySelectPtoTimeAndSpaceMicros_StartsFromNowAndPrefersHandshakeWhenKeysExist()
    {
        foreach ((ulong nowMicros, ulong? initialProbeTimeoutMicros, ulong? handshakeProbeTimeoutMicros, bool handshakeKeysAvailable, bool expectedSelected, ulong expectedPtoTimeMicros, QuicPacketNumberSpace expectedSpace) in new[]
        {
            (1_000UL, (ulong?)2_500UL, (ulong?)1_800UL, true, true, 2_800UL, QuicPacketNumberSpace.Handshake),
            (1_000UL, (ulong?)2_500UL, (ulong?)1_800UL, false, true, 3_500UL, QuicPacketNumberSpace.Initial),
            (0UL, (ulong?)1UL, (ulong?)null, false, true, 1UL, QuicPacketNumberSpace.Initial),
            (ulong.MaxValue - 5, (ulong?)10UL, (ulong?)null, false, true, ulong.MaxValue, QuicPacketNumberSpace.Initial),
            (1_000UL, (ulong?)null, (ulong?)null, false, false, 0UL, QuicPacketNumberSpace.Initial),
        })
        {
            Assert.Equal(expectedSelected, QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
                nowMicros,
                initialProbeTimeoutMicros,
                handshakeProbeTimeoutMicros,
                handshakeKeysAvailable,
                out ulong selectedPtoTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            if (expectedSelected)
            {
                Assert.Equal(expectedPtoTimeMicros, selectedPtoTimeMicros);
                Assert.Equal(expectedSpace, selectedPacketNumberSpace);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP8-0003")]
    [Requirement("REQ-QUIC-RFC9002-SAP8-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationDataProbeTimeout_RequiresHandshakeAndIncludesMaxAckDelayAndBackoff()
    {
        foreach ((ulong smoothedRttMicros, ulong rttVarMicros, ulong maxAckDelayMicros, ulong timerGranularityMicros, int ptoCount) in new[]
        {
            (0UL, 0UL, 0UL, 1UL, 0),
            (1_000UL, 250UL, 500UL, 1UL, 0),
            (1_000UL, 250UL, 500UL, 1UL, 2),
            (1_000UL, 62UL, 500UL, 252UL, 1),
        })
        {
            Assert.False(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.ApplicationData,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                handshakeConfirmed: false,
                out _,
                timerGranularityMicros));

            Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.ApplicationData,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros,
                handshakeConfirmed: true,
                out ulong probeTimeoutMicros,
                timerGranularityMicros));

            ulong expectedProbeTimeoutMicros = Math.Max(
                smoothedRttMicros + Math.Max(4 * rttVarMicros, timerGranularityMicros) + maxAckDelayMicros,
                timerGranularityMicros);
            Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);

            ulong expectedBackedOffProbeTimeoutMicros = expectedProbeTimeoutMicros;
            for (int index = 0; index < ptoCount; index++)
            {
                expectedBackedOffProbeTimeoutMicros *= 2;
            }

            Assert.Equal(expectedBackedOffProbeTimeoutMicros, QuicRecoveryTiming.ComputeProbeTimeoutWithBackoffMicros(
                probeTimeoutMicros,
                ptoCount));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP8-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PeerCompletedAddressValidation_RequiresServerRoleOrHandshakeProof()
    {
        foreach ((bool isServer, bool handshakeAckReceived, bool handshakeConfirmed) in new[]
        {
            (true, false, false),
            (true, true, false),
            (false, true, false),
            (false, false, true),
            (false, false, false),
        })
        {
            bool expectedCompleted = isServer || handshakeAckReceived || handshakeConfirmed;

            Assert.Equal(expectedCompleted, QuicAddressValidation.PeerCompletedAddressValidation(
                isServer,
                handshakeAckReceived,
                handshakeConfirmed));
        }
    }
}

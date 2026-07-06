// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9002_S6_2_2_1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9002-S6-2-2-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerSendBudgetStaysClosedUntilAttributedClientDatagramsArrive()
    {
        foreach ((int receivedPayloadBytes, bool uniquelyAttributed, ulong expectedReceivedBytes, ulong expectedRemainingBudget) in new[]
        {
            (0, true, 0UL, 0UL),
            (1, false, 0UL, 0UL),
            (1, true, 1UL, 3UL),
            (64, true, 64UL, 192UL),
            (1_200, false, 0UL, 0UL),
            (1_200, true, 1_200UL, 3_600UL),
        })
        {
            QuicAntiAmplificationBudget budget = new();

            Assert.False(budget.CanSend(1));
            Assert.Equal(0UL, budget.RemainingSendBudget);
            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
                receivedPayloadBytes,
                uniquelyAttributed));

            Assert.Equal(expectedReceivedBytes, budget.ReceivedPayloadBytes);
            Assert.Equal(expectedRemainingBudget, budget.RemainingSendBudget);
            Assert.Equal(expectedRemainingBudget > 0, budget.CanSend(1));
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientCanArmHandshakeProbeTimeoutBeforeHandshakeConfirmation()
    {
        foreach ((ulong smoothedRttMicros, ulong rttVarMicros, ulong timerGranularityMicros, ulong expectedProbeTimeoutMicros) in new[]
        {
            (0UL, 0UL, 1UL, 1UL),
            (0UL, 0UL, 1_000UL, 1_000UL),
            (1_000UL, 0UL, 1UL, 1_001UL),
            (1_000UL, 250UL, 1UL, 2_000UL),
            (2_000UL, 500UL, 100UL, 4_000UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
                QuicPacketNumberSpace.Handshake,
                smoothedRttMicros,
                rttVarMicros,
                maxAckDelayMicros: 500,
                handshakeConfirmed: false,
                out ulong probeTimeoutMicros,
                timerGranularityMicros));

            Assert.Equal(expectedProbeTimeoutMicros, probeTimeoutMicros);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-1-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientProbeSelectionUsesHandshakeSpaceWhenHandshakeKeysAreAvailable()
    {
        foreach ((ulong nowMicros, ulong? initialProbeTimeoutMicros, ulong handshakeProbeTimeoutMicros, ulong expectedPtoTimeMicros) in new[]
        {
            (0UL, (ulong?)null, 1UL, 1UL),
            (1_000UL, (ulong?)500UL, 1UL, 1_001UL),
            (1_000UL, (ulong?)1UL, 500UL, 1_500UL),
            (4_000UL, (ulong?)9_000UL, 2_000UL, 6_000UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
                nowMicros,
                initialProbeTimeoutMicros,
                handshakeProbeTimeoutMicros,
                handshakeKeysAvailable: true,
                out ulong selectedPtoTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            Assert.Equal(expectedPtoTimeMicros, selectedPtoTimeMicros);
            Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
        }
    }

    [Fact]
    [Requirement("RFC9002-S6-2-2-1-P3-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientProbeSelectionFallsBackToPaddedInitialWhenHandshakeKeysAreUnavailable()
    {
        byte[] padding = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        foreach ((ulong nowMicros, ulong initialProbeTimeoutMicros, ulong? handshakeProbeTimeoutMicros, int currentInitialPayloadLength) in new (ulong, ulong, ulong?, int)[]
        {
            (0UL, 1UL, null, 1),
            (1_000UL, 500UL, 1UL, 37),
            (1_000UL, 1UL, 500UL, 997),
            (4_000UL, 2_000UL, 9_000UL, 1_199),
            (4_000UL, 2_000UL, 9_000UL, 1_200),
        })
        {
            Assert.True(QuicRecoveryTiming.TrySelectPtoTimeAndSpaceMicros(
                nowMicros,
                initialProbeTimeoutMicros,
                handshakeProbeTimeoutMicros,
                handshakeKeysAvailable: false,
                out ulong selectedPtoTimeMicros,
                out QuicPacketNumberSpace selectedPacketNumberSpace));

            Assert.Equal(nowMicros + initialProbeTimeoutMicros, selectedPtoTimeMicros);
            Assert.Equal(QuicPacketNumberSpace.Initial, selectedPacketNumberSpace);

            Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
                currentInitialPayloadLength,
                padding.AsSpan(),
                out int bytesWritten));
            Assert.True(currentInitialPayloadLength + bytesWritten >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);
        }
    }
}

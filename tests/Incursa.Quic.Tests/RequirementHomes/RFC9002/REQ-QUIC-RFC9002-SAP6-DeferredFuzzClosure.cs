// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP6_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP6-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReceivingDatagramThatRestoresAntiAmplificationBudgetArmsLossDetectionTimer()
    {
        foreach ((int receivedPayloadBytes, ulong probeTimeoutMicros) in new[]
        {
            (1, 1UL),
            (10, 250UL),
            (100, 2_800UL),
            (1_200, 30_000UL),
        })
        {
            QuicAntiAmplificationBudget budget = CreateBlockedBudget();

            Assert.False(budget.CanSend(1));
            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(receivedPayloadBytes, uniquelyAttributedToSingleConnection: true));
            Assert.True(budget.CanSend(1));

            Assert.True(QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
                earliestPendingLossTimeMicros: null,
                probeTimeoutMicros: probeTimeoutMicros,
                serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
                noAckElicitingPacketsInFlight: false,
                peerAddressValidationComplete: false,
                out ulong selectedTimerMicros));

            Assert.Equal(probeTimeoutMicros, selectedTimerMicros);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP6-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AlreadyExpiredLossDetectionTimerRunsOnlyAfterAmplificationBlockingEnds()
    {
        foreach ((int receivedPayloadBytes, bool uniquelyAttributedToSingleConnection, bool expectedTimerSelected) in new[]
        {
            (0, true, false),
            (1, false, false),
            (1, true, true),
            (10, true, true),
        })
        {
            QuicAntiAmplificationBudget budget = CreateBlockedBudget();
            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
                receivedPayloadBytes,
                uniquelyAttributedToSingleConnection));

            Assert.Equal(expectedTimerSelected, QuicRecoveryTiming.TrySelectLossDetectionTimerMicros(
                earliestPendingLossTimeMicros: null,
                probeTimeoutMicros: 0,
                serverAtAntiAmplificationLimit: budget.RemainingSendBudget == 0,
                noAckElicitingPacketsInFlight: false,
                peerAddressValidationComplete: false,
                out ulong selectedTimerMicros));

            if (expectedTimerSelected)
            {
                Assert.Equal(0UL, selectedTimerMicros);
            }
        }
    }

    private static QuicAntiAmplificationBudget CreateBlockedBudget()
    {
        QuicAntiAmplificationBudget budget = new();
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(0UL, budget.RemainingSendBudget);
        return budget;
    }
}

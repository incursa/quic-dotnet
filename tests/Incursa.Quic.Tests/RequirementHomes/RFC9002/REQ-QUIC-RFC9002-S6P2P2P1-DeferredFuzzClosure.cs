// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_S6P2P2P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AttributedClientDatagramsIncreaseServerAmplificationBudget()
    {
        foreach (int receivedPayloadBytes in new[] { 1, 64, 1_200, 4_096 })
        {
            QuicAntiAmplificationBudget budget = new();

            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
                receivedPayloadBytes,
                uniquelyAttributedToSingleConnection: true));
            Assert.Equal((ulong)receivedPayloadBytes * 3, budget.RemainingSendBudget);
            Assert.True(budget.TryConsumeSendBudget(receivedPayloadBytes * 3));
            Assert.Equal(0UL, budget.RemainingSendBudget);

            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
                receivedPayloadBytes,
                uniquelyAttributedToSingleConnection: true));

            Assert.Equal((ulong)receivedPayloadBytes * 2, budget.ReceivedPayloadBytes);
            Assert.Equal((ulong)receivedPayloadBytes * 3, budget.RemainingSendBudget);
            Assert.True(budget.CanSend(receivedPayloadBytes * 3));

            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(
                receivedPayloadBytes,
                uniquelyAttributedToSingleConnection: false));
            Assert.Equal((ulong)receivedPayloadBytes * 2, budget.ReceivedPayloadBytes);
            Assert.Equal((ulong)receivedPayloadBytes * 3, budget.RemainingSendBudget);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S6P2P2P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PastDuePtoSelectionExecutesImmediately()
    {
        foreach ((ulong? lossDetectionTimerMicros, ulong? probeTimeoutMicros, ulong expectedTimerMicros) in new (ulong?, ulong?, ulong)[]
        {
            (null, 0UL, 0UL),
            (0UL, 10UL, 0UL),
            (1UL, 0UL, 1UL),
            (100UL, 1UL, 100UL),
        })
        {
            Assert.True(QuicRecoveryTiming.TrySelectRecoveryTimerMicros(
                lossDetectionTimerMicros,
                probeTimeoutMicros,
                out ulong selectedTimerMicros));
            Assert.Equal(expectedTimerMicros, selectedTimerMicros);
        }
    }
}

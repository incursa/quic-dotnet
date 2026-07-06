// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S21P1P1P1-0002">Endpoints MUST NOT send data toward an unvalidated address in excess of three times the data received from that address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S21P1P1P1-0002")]
public sealed class REQ_QUIC_RFC9000_S21P1P1P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("RFC9000-S14-1-P5-S1-R01")]
    [Trait("Category", "Positive")]
    public void CanSend_TracksTheThreeTimesAmplificationCapUntilValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
        Assert.False(budget.CanSend(301));

        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(300UL, budget.SentPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
        Assert.False(budget.CanSend(1));
        Assert.False(budget.TryConsumeSendBudget(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("RFC9000-S14-1-P5-S1-R01")]
    [Trait("Category", "Negative")]
    public void CanSend_RejectsBytesBeyondTheThreeTimesCapBeforeValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
        Assert.Equal(0UL, budget.SentPayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("RFC9000-S14-1-P5-S1-R01")]
    [Trait("Category", "Edge")]
    public void CanSend_AllowsUnlimitedBudgetAfterAddressValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        budget.MarkAddressValidated();

        Assert.True(budget.IsAddressValidated);
        Assert.Equal(ulong.MaxValue, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(int.MaxValue));
        Assert.True(budget.TryConsumeSendBudget(int.MaxValue));
        Assert.Equal((ulong)int.MaxValue, budget.SentPayloadBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Requirement("RFC9000-S14-1-P5-S1-R01")]
    [Trait("Category", "Fuzz")]
    public void CanSendFuzz_EnforcesThreeTimesReceivedPayloadUntilTheAddressIsValidated()
    {
        foreach (int receivedBytes in new[]
        {
            0,
            1,
            64,
            1_200,
            4_096,
            16_384,
        })
        {
            QuicAntiAmplificationBudget budget = new();

            Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(receivedBytes, uniquelyAttributedToSingleConnection: true));

            int allowedBytes = checked(receivedBytes * 3);
            Assert.Equal((ulong)receivedBytes, budget.ReceivedPayloadBytes);
            Assert.Equal((ulong)allowedBytes, budget.RemainingSendBudget);
            Assert.True(budget.CanSend(allowedBytes));
            Assert.False(budget.CanSend(allowedBytes + 1));

            int firstSend = allowedBytes / 2;
            Assert.True(budget.TryConsumeSendBudget(firstSend));
            Assert.True(budget.TryConsumeSendBudget(allowedBytes - firstSend));
            Assert.Equal((ulong)allowedBytes, budget.SentPayloadBytes);
            Assert.Equal(0UL, budget.RemainingSendBudget);
            Assert.False(budget.TryConsumeSendBudget(1));

            budget.MarkAddressValidated();
            Assert.True(budget.CanSend(int.MaxValue));
            Assert.True(budget.TryConsumeSendBudget(int.MaxValue));
        }
    }
}

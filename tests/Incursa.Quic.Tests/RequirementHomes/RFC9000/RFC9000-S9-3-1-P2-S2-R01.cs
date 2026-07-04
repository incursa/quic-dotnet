// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S9-3-1-P2-S2-R01">Until a peer&apos;s address is deemed valid, an endpoint MUST limit the amount of data it sends to that address.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S9-3-1-P2-S2-R01")]
public sealed class RFC9000_S9_3_1_P2_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_TracksTheThreeTimesAmplificationCapBeforeValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.False(budget.IsAddressValidated);
        Assert.Equal(300UL, budget.RemainingSendBudget);
        Assert.True(budget.CanSend(300));
        Assert.False(budget.CanSend(301));
        Assert.True(budget.TryConsumeSendBudget(300));
        Assert.Equal(300UL, budget.SentPayloadBytes);
        Assert.Equal(0UL, budget.RemainingSendBudget);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanSend_AllowsUnlimitedSendingAfterAddressValidation()
    {
        QuicAntiAmplificationBudget budget = new();

        budget.MarkAddressValidated();

        Assert.True(budget.IsAddressValidated);
        Assert.True(budget.CanSend(int.MaxValue));
        Assert.True(budget.TryConsumeSendBudget(int.MaxValue));
        Assert.Equal((ulong)int.MaxValue, budget.SentPayloadBytes);
        Assert.Equal(ulong.MaxValue, budget.RemainingSendBudget);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryConsumeSendBudget_RejectsPayloadsThatExceedThePreValidationBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.False(budget.TryConsumeSendBudget(301));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.SentPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterReceivedDatagramPayloadBytes_RejectsNegativePayloadLengths()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.False(budget.TryRegisterReceivedDatagramPayloadBytes(-1, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(0UL, budget.ReceivedPayloadBytes);
        Assert.False(budget.CanSend(-1));
        Assert.False(budget.TryConsumeSendBudget(-1));
    }
}

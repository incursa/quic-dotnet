// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S14-1-P5-S1-R01">The server MUST also limit the number of bytes it sends before validating the address of the client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S14-1-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S14P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryConsumeSendBudget_RejectsPayloadsThatExceedTheRemainingBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.Equal(300UL, budget.RemainingSendBudget);

        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(0UL, budget.SentPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-1-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S8P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterReceivedDatagramPayloadBytes_IgnoresDatagramsThatAreNotUniquelyAttributed()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(50, uniquelyAttributedToSingleConnection: false));

        Assert.Equal(100UL, budget.ReceivedPayloadBytes);
        Assert.Equal(300UL, budget.RemainingSendBudget);
    }
}

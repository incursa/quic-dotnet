// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-2-2-P2-S2-R01">An endpoint MUST NOT send further packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-2-2-P2-S2-R01")]
public sealed class REQ_QUIC_RFC9000_S10P2P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryEnterClosingState_DisablesFurtherPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryEnterClosingState_ReturnsFalseAfterDraining()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.TryEnterClosingState());
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }
}

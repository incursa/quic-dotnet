// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S10-2-2-P3-S1-R01")]
public sealed class RFC9000_S10_2_2_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryEnterClosingState_ThenTryEnterDrainingState_ReplacesClosingWithDrainingAndStopsSendingPackets()
    {
        QuicConnectionLifecycleState state = new();

        Assert.True(state.CanSendPackets);
        Assert.True(state.TryEnterClosingState());
        Assert.True(state.IsClosing);
        Assert.False(state.IsDraining);

        Assert.True(state.TryEnterDrainingState());
        Assert.False(state.IsClosing);
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [Requirement("RFC9000-S10-2-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryEnterDrainingState_ReplacesClosingStateAcrossRepeatedLifecycleInstances()
    {
        for (int index = 0; index < 8; index++)
        {
            QuicConnectionLifecycleState state = new();

            Assert.True(state.CanSendPackets);
            Assert.True(state.TryEnterClosingState());
            Assert.True(state.IsClosing);
            Assert.False(state.IsDraining);

            Assert.True(state.TryEnterDrainingState());
            Assert.False(state.IsClosing);
            Assert.True(state.IsDraining);
            Assert.False(state.CanSendPackets);

            Assert.False(state.TryEnterClosingState());
            Assert.True(state.IsDraining);
            Assert.False(state.CanSendPackets);
        }
    }
}

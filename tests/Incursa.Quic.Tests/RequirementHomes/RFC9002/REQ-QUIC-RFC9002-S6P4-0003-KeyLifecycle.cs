// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S6-4-P3-S1-R01">An endpoint MUST discard recovery state for all in-flight 0-RTT packets when 0-RTT is rejected.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S6-4-P3-S1-R01")]
public sealed class RFC9002_S6_4_P3_S1_R01_KeyLifecycle
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RejectZeroRtt_MarksKeysUnavailableAndPreventsFurtherUse()
    {
        QuicAeadUsageLimits limits = new(10, 10);
        QuicAeadKeyLifecycle keyLifecycle = new(limits);

        Assert.True(keyLifecycle.TryActivate());
        Assert.True(keyLifecycle.TryUseForProtection());
        Assert.True(keyLifecycle.RejectZeroRtt());

        Assert.True(keyLifecycle.IsZeroRttRejected);
        Assert.True(keyLifecycle.IsDiscarded);
        Assert.False(keyLifecycle.IsAvailable);
        Assert.False(keyLifecycle.CanProtect);
        Assert.False(keyLifecycle.CanOpen);
        Assert.False(keyLifecycle.TryUseForProtection());
        Assert.False(keyLifecycle.TryUseForOpening());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryUseForProtection_FailsWhenKeysAreUnavailable()
    {
        QuicAeadUsageLimits limits = new(10, 10);
        QuicAeadKeyLifecycle keyLifecycle = new(limits);

        Assert.False(keyLifecycle.TryUseForProtection());
        Assert.False(keyLifecycle.TryUseForOpening());
        Assert.False(keyLifecycle.IsAvailable);
        Assert.False(keyLifecycle.CanProtect);
        Assert.False(keyLifecycle.CanOpen);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryActivate_OnlySucceedsFromPendingState()
    {
        QuicAeadUsageLimits limits = new(10, 10);
        QuicAeadKeyLifecycle keyLifecycle = new(limits);

        Assert.True(keyLifecycle.TryActivate());
        Assert.False(keyLifecycle.TryActivate());
        Assert.True(keyLifecycle.RejectZeroRtt());
        Assert.False(keyLifecycle.TryActivate());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryUseForOpening_DiscardsKeysWhenIntegrityLimitReachesBeforeProtectionLimit()
    {
        QuicAeadUsageLimits limits = new(10, 1);
        QuicAeadKeyLifecycle keyLifecycle = new(limits);

        Assert.True(keyLifecycle.TryActivate());
        Assert.True(keyLifecycle.TryUseForOpening());

        Assert.True(keyLifecycle.IsDiscarded);
        Assert.False(keyLifecycle.CanProtect);
        Assert.False(keyLifecycle.CanOpen);
        Assert.False(keyLifecycle.TryUseForOpening());
        Assert.False(keyLifecycle.TryUseForProtection());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RejectZeroRtt_IsIdempotent()
    {
        QuicAeadUsageLimits limits = new(10, 10);
        QuicAeadKeyLifecycle keyLifecycle = new(limits);

        Assert.True(keyLifecycle.TryActivate());
        Assert.True(keyLifecycle.RejectZeroRtt());
        Assert.False(keyLifecycle.RejectZeroRtt());
    }
}

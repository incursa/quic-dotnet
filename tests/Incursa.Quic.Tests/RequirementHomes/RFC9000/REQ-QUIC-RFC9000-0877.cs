// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0877")]
public sealed class REQ_QUIC_RFC9000_0877
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InitialPathStateUsesTheQuicMinimumAsBasePlpmtu()
    {
        QuicDplpmtudState state = new();
        QuicConnectionPathIdentity path = new("203.0.113.12", "192.0.2.10", 443, 55555);

        QuicDplpmtudPathSnapshot snapshot = state.GetPathSnapshot(path);

        Assert.Equal(QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes, snapshot.BasePlpmtuBytes);
        Assert.Equal(snapshot.BasePlpmtuBytes, snapshot.MaximumPacketSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructorRejectsABasePlpmtuBelowTheQuicMinimum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicDplpmtudState(QuicDplpmtudState.BasePlpmtuBytes - 1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ConstructorRejectsABasePlpmtuAboveTheQuicMinimum()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicDplpmtudState(QuicDplpmtudState.BasePlpmtuBytes + 1));
    }
}

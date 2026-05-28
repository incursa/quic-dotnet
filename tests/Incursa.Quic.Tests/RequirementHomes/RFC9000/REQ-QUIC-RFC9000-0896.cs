// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0896">The version 0x00000000 MUST be reserved to represent version negotiation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0896")]
public sealed class REQ_QUIC_RFC9000_0896
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void VersionNegotiationVersion_UsesTheReservedZeroValue()
    {
        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_RejectsTheReservedZeroVersion()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.VersionNegotiationVersion,
            [QuicVersionNegotiation.Version1]));
    }
}

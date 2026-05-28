// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0899">Versions that follow the pattern 0x?a?a?a?a MUST be reserved for use in forcing version negotiation to be exercised.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0899")]
public sealed class REQ_QUIC_RFC9000_0899
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsReservedVersion_RecognizesTheReservedPattern()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x00112233);

        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.Equal((uint)0x0A1A2A3A, reservedVersion);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsReservedVersion_RejectsOrdinaryVersions()
    {
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
    }
}

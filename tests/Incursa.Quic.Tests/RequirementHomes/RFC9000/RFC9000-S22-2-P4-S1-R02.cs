// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S22-2-P4-S1-R02")]
public sealed class REQ_QUIC_RFC9000_S22P2_0003
{
    [Fact]
    [Requirement("RFC9000-S22-2-P4-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReservedVersionPattern_IsExcludedFromAssignedVersionValues()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(QuicVersionNegotiation.Version1));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }
}

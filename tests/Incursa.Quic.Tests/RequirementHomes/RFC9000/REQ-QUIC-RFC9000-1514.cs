// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1514")]
public sealed class REQ_QUIC_RFC9000_1514
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1514")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void VersionNegotiation_DoesNotReserveVersionOneAsTheZeroCodepoint()
    {
        Assert.NotEqual(QuicVersionNegotiation.VersionNegotiationVersion, QuicVersionNegotiation.Version1);
        Assert.False(QuicVersionNegotiation.IsVersionNegotiationVersion(QuicVersionNegotiation.Version1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1514")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void VersionNegotiation_UsesTheReservedCodepoint()
    {
        Assert.Equal(0u, QuicVersionNegotiation.VersionNegotiationVersion);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1514")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void VersionNegotiation_FuzzOnlyZeroIsTheVersionNegotiationCodepoint()
    {
        uint[] nonNegotiationVersions =
        [
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.CreateReservedVersion(0x10203040),
            0xAABBCCDD,
        ];

        Assert.True(QuicVersionNegotiation.IsVersionNegotiationVersion(QuicVersionNegotiation.VersionNegotiationVersion));

        foreach (uint version in nonNegotiationVersions)
        {
            Assert.NotEqual(QuicVersionNegotiation.VersionNegotiationVersion, version);
            Assert.False(QuicVersionNegotiation.IsVersionNegotiationVersion(version));
        }
    }
}

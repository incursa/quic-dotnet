// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S6-1-P3-R01")]
public sealed class REQ_QUIC_RFC9000_0286
{
    [Fact]
    [Requirement("RFC9000-S6-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_DoesNotSendWhenVersionIsSupportedOrResponseWasAlreadySent()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: true));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S6-1-P3-R01">A server MAY limit the number of Version Negotiation packets it sends.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S6-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldSendVersionNegotiation_CanLimitRepeatedResponses()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: false));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            [QuicVersionNegotiation.Version1],
            hasAlreadySentVersionNegotiation: true));
    }
}

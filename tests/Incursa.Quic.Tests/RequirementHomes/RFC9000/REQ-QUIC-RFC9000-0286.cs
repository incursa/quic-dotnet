// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0286")]
public sealed class REQ_QUIC_RFC9000_0286
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0286")]
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0286">A server MAY limit the number of Version Negotiation packets it sends.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0286")]
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

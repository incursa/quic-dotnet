// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P2-0001")]
public sealed class REQ_QUIC_RFC9000_S5P2P2_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P2-0001">If a server receives a packet that indicates an unsupported version and the packet is large enough to initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S5-2-2-P2-S4-R01">Servers SHOULD respond with a Version Negotiation packet, provided that the datagram is sufficiently long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P2P2-0001")]
    [Requirement("RFC9000-S5-2-2-P2-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldSendVersionNegotiation_RequiresAnUnsupportedClientVersionAndSufficientDatagramSize()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            0x11223344,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            []));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_DoesNotSendForSupportedOrUndersizedPackets()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            [QuicVersionNegotiation.Version1]));

        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicS5P2P2ServerPreAcceptanceTestSupport.UnsupportedVersion,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - 1,
            [QuicVersionNegotiation.Version1]));
    }
}

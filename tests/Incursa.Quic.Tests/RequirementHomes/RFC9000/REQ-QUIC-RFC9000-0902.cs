// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0902">A server MAY advertise support for one of these versions and can expect that clients ignore the value.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0900">A client or server MAY advertise support for any of these reserved versions.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0902")]
public sealed class REQ_QUIC_RFC9000_0902
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-0900")]
    public void ShouldDiscardVersionNegotiation_IgnoresReservedVersionsInTheAdvertisedList()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        byte[] packet = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            QuicVersionNegotiation.Version1,
            [0x10, 0x11],
            [0x20],
            [reservedVersion],
            packet,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            packet.AsSpan(0, bytesWritten),
            out QuicVersionNegotiationPacket parsed));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            parsed,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            parsed,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
    }
}

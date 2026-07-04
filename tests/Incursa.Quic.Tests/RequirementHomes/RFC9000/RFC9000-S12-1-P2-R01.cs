// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S12-1-P2-R01">Version Negotiation packets have no cryptographic protection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S12-1-P2-R01")]
public sealed class RFC9000_S12_1_P2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatVersionNegotiationResponse_WritesAStatelessParseablePacket()
    {
        byte[] destination = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            clientSelectedVersion: 0x01020304,
            clientDestinationConnectionId: [0xAA, 0xBB],
            clientSourceConnectionId: [0xCC],
            serverSupportedVersions: [QuicVersionNegotiation.Version1, 0x11223344],
            destination,
            out int bytesWritten));

        Assert.Equal(18, bytesWritten);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination.AsSpan(0, bytesWritten),
            out QuicVersionNegotiationPacket packet));
        Assert.Equal(0u, packet.Version);
        Assert.Equal(2, packet.SupportedVersionCount);
        Assert.Equal(QuicVersionNegotiation.Version1, packet.GetSupportedVersion(0));
        Assert.Equal((uint)0x11223344, packet.GetSupportedVersion(1));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseVersionNegotiation_RejectsOrdinaryProtectedLongHeaders()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: QuicVersionNegotiation.Version1,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData: [0x03, 0x04]);

        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out _));
    }
}

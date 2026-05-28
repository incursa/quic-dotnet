// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-6322")]
public sealed class REQ_QUIC_RFC9000_6322
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-6322")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedInitialPacket_CanCarryAReservedVersionForDiscardTesting()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            QuicS17P2P2TestSupport.InitialSourceConnectionId,
            initialPacketVersion: reservedVersion);

        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            QuicS12P3TestSupport.CreateSequentialBytes(0x30, 8),
            cryptoPayloadOffset: 0,
            protection,
            out byte[] protectedPacket));

        Assert.True(QuicPacketParser.TryParseLongHeader(protectedPacket, out QuicLongHeaderPacket header));
        Assert.Equal(reservedVersion, header.Version);
        Assert.True(QuicVersionNegotiation.IsReservedVersion(header.Version));
        Assert.False(header.IsVersionNegotiation);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-6322">Endpoints MAY send packets with a reserved version to test that a peer correctly discards the packet.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-6322")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseVersionNegotiation_RejectsPacketsWithReservedVersions()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);

        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4C,
            version: reservedVersion,
            destinationConnectionId: [0x01, 0x02],
            sourceConnectionId: [0x03],
            versionSpecificData: [0x04, 0x05]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(reservedVersion, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.False(QuicPacketParser.TryParseVersionNegotiation(packet, out _));
    }
}

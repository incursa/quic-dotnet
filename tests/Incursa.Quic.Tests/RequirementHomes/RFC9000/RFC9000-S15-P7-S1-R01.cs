// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S15-P7-S1-R01">A client MAY use one of these version numbers with the expectation that the server will initiate version negotiation.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S15-P7-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0901
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShouldSendVersionNegotiation_AllowsReservedClientVersionsToElicitNegotiation()
    {
        Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.CreateReservedVersion(0x11223344),
            [QuicVersionNegotiation.Version1]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ShouldSendVersionNegotiation_RejectsReservedClientVersionsWithoutServerSupport()
    {
        Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(
            QuicVersionNegotiation.CreateReservedVersion(0x11223344),
            []));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManagedClientInitialPacket_UsesTheConfiguredReservedVersion()
    {
        byte[] routeConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];
        byte[] initialDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];

        QuicTransportParameters clientTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(routeConnectionId);
        QuicTlsKeySchedule clientKeySchedule = new(QuicTlsRole.Client);
        Assert.True(clientKeySchedule.TryCreateClientHello(clientTransportParameters, out byte[] clientHello));

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection initialPacketProtection));

        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = new(
            initialDestinationConnectionId,
            routeConnectionId,
            initialPacketVersion: reservedVersion);

        Assert.True(handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
            clientHello,
            cryptoPayloadOffset: 0,
            initialPacketProtection,
            out byte[] protectedPacket));

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            protectedPacket,
            out _,
            out uint parsedVersion,
            out ReadOnlySpan<byte> parsedDestinationConnectionId,
            out ReadOnlySpan<byte> parsedSourceConnectionId,
            out _));
        Assert.Equal(reservedVersion, parsedVersion);
        Assert.Equal(initialDestinationConnectionId, parsedDestinationConnectionId.ToArray());
        Assert.Equal(routeConnectionId, parsedSourceConnectionId.ToArray());
        Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, protectedPacket.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReservedClientVersionsFuzz_ElicitVersionNegotiationAndRemainClientSelectable()
    {
        byte[] routeConnectionId =
        [
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        ];
        byte[] initialDestinationConnectionId =
        [
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        uint[] templates =
        [
            0x00112233u,
            0x11223344u,
            0xA5B6C7D8u,
            0xF0E1D2C3u,
        ];

        foreach (uint template in templates)
        {
            uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(template);

            Assert.True(QuicVersionNegotiation.IsReservedVersion(reservedVersion));
            Assert.True(QuicVersionNegotiation.ShouldSendVersionNegotiation(
                reservedVersion,
                [QuicVersionNegotiation.Version1]));
            Assert.False(QuicVersionNegotiation.ShouldSendVersionNegotiation(reservedVersion, []));

            QuicTransportParameters clientTransportParameters = QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(
                routeConnectionId);
            QuicTlsKeySchedule clientKeySchedule = new(QuicTlsRole.Client);
            Assert.True(clientKeySchedule.TryCreateClientHello(clientTransportParameters, out byte[] clientHello));

            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Client,
                initialDestinationConnectionId,
                out QuicInitialPacketProtection initialPacketProtection));

            QuicHandshakeFlowCoordinator handshakeFlowCoordinator = new(
                initialDestinationConnectionId,
                routeConnectionId,
                initialPacketVersion: reservedVersion);

            Assert.True(handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                clientHello,
                cryptoPayloadOffset: 0,
                initialPacketProtection,
                out byte[] protectedPacket));

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                protectedPacket,
                out _,
                out uint parsedVersion,
                out ReadOnlySpan<byte> parsedDestinationConnectionId,
                out ReadOnlySpan<byte> parsedSourceConnectionId,
                out _));
            Assert.Equal(reservedVersion, parsedVersion);
            Assert.Equal(initialDestinationConnectionId, parsedDestinationConnectionId.ToArray());
            Assert.Equal(routeConnectionId, parsedSourceConnectionId.ToArray());
        }
    }
}

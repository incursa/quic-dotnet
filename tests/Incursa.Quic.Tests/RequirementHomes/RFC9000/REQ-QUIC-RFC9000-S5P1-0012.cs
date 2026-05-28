// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
public sealed class REQ_QUIC_RFC9000_S5P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatVersionNegotiationResponse_EchoesTheClientsConnectionIds()
    {
        byte[] destination = new byte[64];
        byte[] clientDestinationConnectionId =
        [
            0x01,
            0x02,
        ];
        byte[] clientSourceConnectionId =
        [
            0x03,
            0x04,
            0x05,
        ];
        uint[] serverSupportedVersions =
        [
            QuicVersionNegotiation.Version1,
            0x11223344,
        ];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatVersionNegotiationResponse_RejectsTooSmallDestinationBuffers()
    {
        byte[] destination = new byte[10];

        Assert.False(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId: [0x01, 0x02],
            clientSourceConnectionId: [0x03, 0x04, 0x05],
            serverSupportedVersions: [QuicVersionNegotiation.Version1],
            destination,
            out _));
    }
}

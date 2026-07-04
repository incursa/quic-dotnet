// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-2-P2-S2-R01")]
public sealed class RFC9000_S7_2_P2_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatVersionNegotiationResponse_UsesTheClientSourceConnectionIdAsDestinationConnectionId()
    {
        byte[] clientDestinationConnectionId = [0x01, 0x02];
        byte[] clientSourceConnectionId = [0x03, 0x04, 0x05];
        uint[] serverSupportedVersions = [QuicVersionNegotiation.Version1, 0x11223344];
        byte[] destination = new byte[64];

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
        Assert.True(packet.ContainsSupportedVersion(QuicVersionNegotiation.Version1));
        Assert.True(packet.ContainsSupportedVersion(0x11223344));
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S3-P1-S1-R01">The packet-level header MUST indicate the encryption level.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S3-P1-S1-R01")]
public sealed class RFC9002_S3_P1_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_ExposesTheEncryptionLevelBits()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            (byte)(QuicPacketHeaderBits.FixedBitMask | (QuicLongPacketTypeBits.Handshake << QuicPacketHeaderBits.LongPacketTypeBitsShift)),
            version: 1,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02],
            versionSpecificData: QuicHeaderTestData.BuildZeroRttVersionSpecificData([0xA1], [0xB2]));

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicLongPacketTypeBits.Handshake, header.LongPacketTypeBits);
    }
}

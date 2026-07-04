// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9002-S3-P1-S1-R02">The packet-level header MUST include a packet sequence number.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9002-S3-P1-S1-R02")]
public sealed class RFC9002_S3_P1_S1_R02
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_PreservesThePacketSequenceNumberBytes()
    {
        byte[] remainder = [0xA1, 0xB2, 0xC3];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x03, remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
        Assert.Equal(remainder.Length, header.Remainder.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsPacketsWithoutHeaderBytes()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseShortHeader_PreservesASinglePacketNumberByte()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xA1]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
        Assert.Equal(1, header.Remainder.Length);
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1073">An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1073")]
public sealed class REQ_QUIC_RFC9000_1073
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_AllowsZeroReservedBits()
    {
        byte[] remainder = [0xA1, 0xB2];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.True(remainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseShortHeader_ParsesTheShortestRecognizablePacket()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, []);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.True(header.Remainder.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_RejectsPacketsWithNonZeroReservedBits()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x18, [0xA1, 0xB2]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }
}

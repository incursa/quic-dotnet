// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1220010">A packet with a short header MUST be the last packet included in a UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-1220010")]
public sealed class REQ_QUIC_RFC9000_1220010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseShortHeader_TreatsEverythingAfterTheFirstByteAsPartOfThePacket()
    {
        byte[] leadingPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] trailingPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [0xDD],
                packetNumber: [0x01, 0x02],
                protectedPayload: [0xEE]));
        byte[] datagram = [.. leadingPacket, .. trailingPacket];

        Assert.True(QuicPacketParser.TryParseShortHeader(datagram, out QuicShortHeaderPacket header));
        Assert.Equal(datagram.Length - 1, header.Remainder.Length);
        Assert.True(header.Remainder.Slice(leadingPacket.Length - 1).SequenceEqual(trailingPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_AcceptsAShortHeaderPacketWhenItIsLastInTheDatagram()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(3, header.Remainder.Length);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryParseShortHeader_FuzzesTrailingDatagramBytesAsPacketRemainder()
    {
        for (int trailingLength = 1; trailingLength <= 9; trailingLength++)
        {
            byte[] trailingBytes = Enumerable.Range(0, trailingLength)
                .Select(value => (byte)(0x80 + value))
                .ToArray();
            byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, trailingBytes);

            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal(trailingBytes.Length, header.Remainder.Length);
            Assert.True(trailingBytes.AsSpan().SequenceEqual(header.Remainder));
        }
    }
}

// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S7-2-P5-S1-R01">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S7-2-P5-S1-R01")]
public sealed class RFC9000_S7_2_P5_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S7-2-P5-S1-R01">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_ExposesTheChosenHandshakeSourceConnectionId()
    {
        byte[] sourceConnectionId = [0x20, 0x21, 0x22];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x10, 0x11, 0x12],
            sourceConnectionId: sourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S7-2-P5-S1-R01">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_RejectsHandshakePacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet[..8], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S7-2-P5-S1-R01">The client MUST populate the Source Connection ID field with a value of its choosing and set the Source Connection ID Length field to indicate the length.</workbench-requirement>
    /// </workbench-requirements>
    public void TryParseLongHeader_AllowsAZeroLengthHandshakeSourceConnectionId()
    {
        byte[] destinationConnectionId = [0x10];
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            destinationConnectionId: destinationConnectionId,
            sourceConnectionId: []);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(header.SourceConnectionId.IsEmpty);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryParseLongHeaderFuzz_ExposesTheChosenHandshakeSourceConnectionIdLength()
    {
        byte[][] sourceConnectionIds =
        [
            [0x20],
            [0x21, 0x22, 0x23, 0x24],
            [0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C],
            [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B],
        ];

        foreach (byte[] sourceConnectionId in sourceConnectionIds)
        {
            byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
                destinationConnectionId: [0x10, 0x11, 0x12],
                sourceConnectionId: sourceConnectionId);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        }
    }
}

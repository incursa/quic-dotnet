// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0006">The Unused field MUST be 4 bits long.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0006")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0006">The Unused field MUST be 4 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0006")]
    public void TryParseLongHeader_ExposesTheRetryUnusedBits()
    {
        byte[] packet = QuicRetryPacketRequirementTestData.BuildRetryPacket(unusedBits: 0x0A);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
    }
}

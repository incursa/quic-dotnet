// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ReportsLongHeaderFormForZeroRttPackets()
    {
        byte[] packet = QuicS17P2P3TestSupport.BuildZeroRttPacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
        Assert.Equal(QuicHeaderForm.Long, headerForm);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x3F)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0005">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsShortHeaderForm(byte headerControlBits)
    {
        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        Assert.False(QuicPacketParser.TryParseLongHeader(shortHeader, out _));
    }
}

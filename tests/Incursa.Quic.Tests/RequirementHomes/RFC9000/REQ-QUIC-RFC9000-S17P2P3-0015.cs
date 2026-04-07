namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0015">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0015
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0015">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsZeroRttPacketsWithTruncatedLengthField()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x40]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}

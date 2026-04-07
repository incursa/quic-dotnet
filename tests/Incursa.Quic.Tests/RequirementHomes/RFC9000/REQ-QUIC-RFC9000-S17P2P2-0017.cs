namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0017">The Token Length field MUST be variable-length integer specifying the length of the Token field, in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0017
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0017">The Token Length field MUST be variable-length integer specifying the length of the Token field, in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseLongHeader_ParsesInitialTokenLengthAsTheTokenFieldLength()
    {
        byte[] token = [0xAA, 0xBB];
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token,
            packetNumber: [0x01],
            protectedPayload: [0xCC]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(QuicVariableLengthInteger.TryParse(header.VersionSpecificData, out ulong tokenLength, out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)token.Length, tokenLength);
        Assert.Equal(token.Length < 64 ? 1 : 2, tokenLengthBytesConsumed);
    }
}

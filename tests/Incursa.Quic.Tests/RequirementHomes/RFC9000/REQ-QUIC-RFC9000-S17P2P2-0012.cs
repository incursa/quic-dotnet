namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0012">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0012">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    public void TryParseLongHeader_AcceptsATokenLengthEncodedAsAMultiByteVarint()
    {
        byte[] token = Enumerable.Repeat((byte)0xA5, 64).ToArray();
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token,
            packetNumber: [0x01],
            protectedPayload: [0xFA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

        Assert.True(
            QuicVariableLengthInteger.TryParse(header.VersionSpecificData, out ulong tokenLength, out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)64, tokenLength);
        Assert.Equal(2, tokenLengthBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0012">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    public void TryParseLongHeader_AllowsATokenLengthAtTheLargestOneByteVarintValue()
    {
        byte[] token = Enumerable.Repeat((byte)0xA5, 63).ToArray();
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token,
            packetNumber: [0x01],
            protectedPayload: [0xFA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

        Assert.True(
            QuicVariableLengthInteger.TryParse(header.VersionSpecificData, out ulong tokenLength, out int tokenLengthBytesConsumed));
        Assert.Equal((ulong)63, tokenLength);
        Assert.Equal(1, tokenLengthBytesConsumed);
    }
}

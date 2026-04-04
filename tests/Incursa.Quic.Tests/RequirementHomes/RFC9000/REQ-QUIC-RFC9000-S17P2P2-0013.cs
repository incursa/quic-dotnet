namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0013">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0013">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    public void TryParseLongHeader_AcceptsALengthEncodedAsAMultiByteVarint()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: Enumerable.Repeat((byte)0xFA, 63).ToArray());
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
        Assert.Equal((ulong)0, tokenLength);
        Assert.Equal(1, tokenLengthBytesConsumed);

        Assert.True(
            QuicVariableLengthInteger.TryParse(
                header.VersionSpecificData[tokenLengthBytesConsumed..],
                out ulong length,
                out int lengthBytesConsumed));
        Assert.Equal((ulong)64, length);
        Assert.Equal(2, lengthBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0013">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    public void TryParseLongHeader_AllowsALengthAtTheLargestOneByteVarintValue()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: Enumerable.Repeat((byte)0xFA, 62).ToArray());
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
        Assert.Equal((ulong)0, tokenLength);
        Assert.Equal(1, tokenLengthBytesConsumed);

        Assert.True(
            QuicVariableLengthInteger.TryParse(
                header.VersionSpecificData[tokenLengthBytesConsumed..],
                out ulong length,
                out int lengthBytesConsumed));
        Assert.Equal((ulong)63, length);
        Assert.Equal(1, lengthBytesConsumed);
    }
}

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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsInitialPacketsWhoseTokenLengthExceedsTheAvailableTokenBytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            QuicS17P2P2TestSupport.BuildInitialHeaderControlBits(),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData: [0x02, 0xAA]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeader_TreatsZeroTokenLengthAsAnEmptyTokenField()
    {
        byte[] versionSpecificData = QuicS17P2P2TestSupport.BuildInitialVersionSpecificData(
            packetNumberLength: 1,
            token: [],
            protectedPayload: []);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            QuicS17P2P2TestSupport.BuildInitialHeaderControlBits(packetNumberLength: 1),
            version: 1,
            destinationConnectionId: [0x10],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(QuicVariableLengthInteger.TryParse(header.VersionSpecificData, out ulong tokenLength, out int tokenLengthBytesConsumed));
        Assert.Equal(0UL, tokenLength);
        Assert.Equal(1, tokenLengthBytesConsumed);
    }
}

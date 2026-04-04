namespace Incursa.Quic.Tests;

public sealed class QuicShortHeaderPacketTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0002">The Key Phase bit MUST indicate which packet protection keys are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0001">QUIC transmissions MUST be sent with a packet-level header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0003">The packet-level header MUST include a packet sequence number.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0003">The Header Form field MUST be 1 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0004">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0005">The Spin Bit field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0006">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0007">The Key Phase field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0012">The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0013">The next bit (0x40) of byte 0 MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0015">The next two bits (those with a mask of 0x18) of byte 0 MUST be reserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0016">The value included prior to protection MUST be set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0017">An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0019">The next bit (0x04) of byte 0 MUST indicate the key phase, which allows a recipient of a packet to identify the packet protection keys that are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0020">The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S6-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseShortHeader_PreservesOpaqueRemainder()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x65,
            remainder: [0xA1, 0xA2, 0xA3, 0xA4]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x65, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.True(header.SpinBit);
        Assert.Equal((byte)0x00, header.ReservedBits);
        Assert.True(header.KeyPhase);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
        Assert.True(packet.AsSpan(1).SequenceEqual(header.Remainder));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0012">The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0013">The next bit (0x40) of byte 0 MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0014">Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsFixedBitZero()
    {
        byte[] packet = [0x3D, 0xA1, 0xA2, 0xA3];

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0016">The value included prior to protection MUST be set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0017">An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsReservedBitsNonZero()
    {
        byte[] packet = [0x5D, 0xA1, 0xA2, 0xA3];

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0012">Endpoints MUST discard packets that are too small to be valid QUIC packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P3-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0012">The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsLongHeaderForm()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x01,
            version: 0x01020304,
            destinationConnectionId: [0x11],
            sourceConnectionId: [0x22],
            versionSpecificData: [0x33]);

        Assert.False(QuicPacketParser.TryParseShortHeader(packet, out _));
    }
}

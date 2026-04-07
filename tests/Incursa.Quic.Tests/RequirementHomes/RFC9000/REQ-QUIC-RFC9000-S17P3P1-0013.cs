using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
public sealed class REQ_QUIC_RFC9000_S17P3P1_0013
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseShortHeader_ExposesTheFixedBit()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x00, [0xAA, 0xBB]);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x40, (byte)(header.HeaderControlBits & 0x40));
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    /// <workbench-requirements generated="true" source="workbench quality sync">
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
    [Trait("Category", "Property")]
    public void TryParseShortHeader_PreservesOpaqueRemainder(ShortHeaderScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(scenario.HeaderControlBits, scenario.Remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal(scenario.HeaderControlBits, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((scenario.HeaderControlBits & 0x20) != 0, header.SpinBit);
        Assert.Equal((byte)((scenario.HeaderControlBits & 0x18) >> 3), header.ReservedBits);
        Assert.Equal((scenario.HeaderControlBits & 0x04) != 0, header.KeyPhase);
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x03), header.PacketNumberLengthBits);
        Assert.True(scenario.Remainder.AsSpan().SequenceEqual(header.Remainder));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0004">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0005">The Spin Bit field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0006">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0007">The Key Phase field MUST be 1 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0008">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0012">The most significant bit (0x80) of byte 0 MUST be set to 0 for the short header.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0013">The next bit (0x40) of byte 0 MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0014">Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0015">The next two bits (those with a mask of 0x18) of byte 0 MUST be reserved.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0016">The value included prior to protection MUST be set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0017">An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0019">The next bit (0x04) of byte 0 MUST indicate the key phase, which allows a recipient of a packet to identify the packet protection keys that are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P3P1-0020">The least significant two bits (those with a mask of 0x03) of byte 0 MUST contain the length of the Packet Number field, encoded as an unsigned two-bit integer that is one less than the length of the Packet Number field in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShortHeaderParsing_RoundTripsValidInputsAndRejectsFixedBitZero()
    {
        Random random = new(0x5150_2029);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte headerControlBits = (byte)(0x40 | (random.Next(0, 0x40) & 0x27));
            byte[] remainder = QuicHeaderTestData.RandomBytes(random, random.Next(0, 32));
            byte[] packet = QuicHeaderTestData.BuildShortHeader(headerControlBits, remainder);

            Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
            Assert.Equal(headerControlBits, header.HeaderControlBits);
            Assert.True(header.FixedBit);
            Assert.Equal((headerControlBits & 0x20) != 0, header.SpinBit);
            Assert.Equal((byte)((headerControlBits & 0x18) >> 3), header.ReservedBits);
            Assert.Equal((headerControlBits & 0x04) != 0, header.KeyPhase);
            Assert.Equal((byte)(headerControlBits & 0x03), header.PacketNumberLengthBits);
            Assert.True(remainder.AsSpan().SequenceEqual(header.Remainder));

            byte[] invalidPacket = packet.ToArray();
            invalidPacket[0] = (byte)(invalidPacket[0] & ~0x40);
            Assert.False(QuicPacketParser.TryParseShortHeader(invalidPacket, out _));

            byte[] invalidReservedPacket = packet.ToArray();
            invalidReservedPacket[0] = (byte)(invalidReservedPacket[0] | 0x18);
            Assert.False(QuicPacketParser.TryParseShortHeader(invalidReservedPacket, out _));
        }
    }
}

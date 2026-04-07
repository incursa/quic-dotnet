using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0002
{
    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0002">The Key Phase bit MUST indicate which packet protection keys are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0002">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0003">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0004">The Long Packet Type field MUST be 2 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0005">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0006">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0007">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2-0001">Incoming packets MUST be classified on receipt.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S6-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P2-0001")]
    [Trait("Category", "Property")]
    public void TryClassifyHeaderForm_UsesTheFirstByteHighBit(HeaderFormPacket packet)
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet.Bytes, out QuicHeaderForm headerForm));

        QuicHeaderForm expectedForm = (packet.Bytes[0] & 0x80) == 0
            ? QuicHeaderForm.Short
            : QuicHeaderForm.Long;

        Assert.Equal(expectedForm, headerForm);
    }

    [Property(Arbitrary = new[] { typeof(QuicHeaderPropertyGenerators) })]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0002">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0003">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0004">The Long Packet Type field MUST be 2 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0005">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0006">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0007">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0012">Packets that use the long header MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0016">The first byte MUST contain the Reserved and Packet Number Length bits; see also Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0001">A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0002">The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0005">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0006">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0007">The Long Packet Type field MUST be 2 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0008">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0009">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0010">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0008">Packets with long headers MUST include Source Connection ID and Destination Connection ID fields.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0008")]
    [Trait("Category", "Property")]
    public void TryParseLongHeader_RoundTripsHeaderFields(LongHeaderScenario scenario)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            scenario.HeaderControlBits,
            scenario.Version,
            scenario.DestinationConnectionId,
            scenario.SourceConnectionId,
            scenario.VersionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x7F), header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)((scenario.HeaderControlBits & 0x30) >> 4), header.LongPacketTypeBits);
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x03), header.PacketNumberLengthBits);
        Assert.Equal((byte)(scenario.HeaderControlBits & 0x0F), header.TypeSpecificBits);
        Assert.Equal((byte)((scenario.HeaderControlBits & 0x0C) >> 2), header.ReservedBits);
        Assert.Equal(scenario.Version, header.Version);
        Assert.Equal(scenario.Version == 0, header.IsVersionNegotiation);
        Assert.True(scenario.DestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.True(scenario.SourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(scenario.VersionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6-0002">The Key Phase bit MUST indicate which packet protection keys are used to protect the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0002">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0003">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0004">The Long Packet Type field MUST be 2 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0005">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0006">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0007">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0016">The first byte MUST contain the Reserved and Packet Number Length bits; see also Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0001">During the handshake, packets with the long header MUST be used to establish the connection IDs used by both endpoints.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0008">Packets with long headers MUST include Source Connection ID and Destination Connection ID fields.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0001">A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0002">The first byte MUST contain the Reserved and Packet Number Length bits; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0005">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0006">The Fixed Bit field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0007">The Long Packet Type field MUST be 2 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0008">The Reserved Bits field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0009">The Packet Number Length field MUST be 2 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0010">The Version field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0008">Packets with long headers MUST include Source Connection ID and Destination Connection ID fields.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S6-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S7P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation()
    {
        Random random = new(0x5150_2026);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte headerControlBits = (byte)(0x40 | random.Next(0, 0x40));
            uint version = (uint)random.Next(0, int.MaxValue);
            if (version == 1)
            {
                version = 2;
            }

            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            byte[] sourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            byte[] versionSpecificData = [];
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits,
                version,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.Equal(headerControlBits, header.HeaderControlBits);
            Assert.True(header.FixedBit);
            Assert.Equal((byte)((headerControlBits & 0x30) >> 4), header.LongPacketTypeBits);
            Assert.Equal((byte)(headerControlBits & 0x03), header.PacketNumberLengthBits);
            Assert.Equal((byte)(headerControlBits & 0x0F), header.TypeSpecificBits);
            Assert.Equal((byte)((headerControlBits & 0x0C) >> 2), header.ReservedBits);
            Assert.Equal(version, header.Version);
            Assert.Equal(version == 0, header.IsVersionNegotiation);
            Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
            Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

            byte[] truncatedPacket = packet[..random.Next(0, 7)];
            Assert.False(QuicPacketParser.TryParseLongHeader(truncatedPacket, out _));
        }
    }
}

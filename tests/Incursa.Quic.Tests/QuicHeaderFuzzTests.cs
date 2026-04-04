namespace Incursa.Quic.Tests;

public sealed class QuicHeaderFuzzTests
{
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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0012">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0013">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0014">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0015">The Initial packet MUST contain a long header as well as the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0017">The Token Length field MUST be variable-length integer specifying the length of the Token field, in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0001">A 0-RTT packet MUST use long headers with a type value of 0x01, followed by the Length and Packet Number fields; see Section 17.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0012">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0014">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0015">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0016">The Packet Number field MUST be between 8 and 32 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_Version1InitialAndZeroRttParsing_RoundTripsValidInputsAndRejectsTailTruncation()
    {
        Random random = new(0x5150_2028);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool isInitial = (iteration & 1) == 0;
            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] sourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] packetNumber = QuicHeaderTestData.RandomBytes(random, random.Next(1, 5));
            byte[] protectedPayload = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            byte[] versionSpecificData = isInitial
                ? QuicHeaderTestData.BuildInitialVersionSpecificData(
                    QuicHeaderTestData.RandomBytes(random, random.Next(0, 8)),
                    packetNumber,
                    protectedPayload)
                : QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload);
            byte headerControlBits = (byte)((isInitial ? 0x40 : 0x50) | (packetNumber.Length - 1));
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits,
                version: 1,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal((byte)(isInitial ? 0x00 : 0x01), header.LongPacketTypeBits);
            Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));

            if (versionSpecificData.Length > 0)
            {
                int truncateBy = random.Next(1, versionSpecificData.Length + 1);
                byte[] truncatedPacket = packet[..^truncateBy];
                Assert.False(QuicPacketParser.TryParseLongHeader(truncatedPacket, out _));
            }
        }
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
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0017")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S17P3P1-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0002">The other seven bits in the first byte of a QUIC long header packet MUST be version-specific.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0003">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0004">The Unused field MUST be 7 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0005">The Version field MUST be 32 bits long with value 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0006">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0007">The Destination Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0008">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0009">The Source Connection ID field MUST be between 0 and 2040 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0013">The Version field of a Version Negotiation packet MUST be set to 0x00000000.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P1-0019">The Version Negotiation packet MUST NOT include the Packet Number and Length fields present in other packets that use the long header form.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0019")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_VersionNegotiationParsing_RoundTripsValidInputsAndRejectsTruncation()
    {
        Random random = new(0x5150_2027);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte headerControlBits = (byte)random.Next(0, 0x80);
            byte[] destinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            byte[] sourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 8));
            uint[] supportedVersions = new uint[random.Next(1, 5)];

            for (int i = 0; i < supportedVersions.Length; i++)
            {
                supportedVersions[i] = (uint)random.Next(1, int.MaxValue);
            }

            byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits,
                destinationConnectionId,
                sourceConnectionId,
                supportedVersions);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.True(header.IsVersionNegotiation);
            Assert.Equal(headerControlBits, header.HeaderControlBits);
            Assert.Equal(supportedVersions.Length, header.SupportedVersionCount);
            Assert.True(header.ContainsSupportedVersion(supportedVersions[random.Next(0, supportedVersions.Length)]));

            for (int i = 0; i < supportedVersions.Length; i++)
            {
                Assert.Equal(supportedVersions[i], header.GetSupportedVersion(i));
            }

            int truncateBy = random.Next(1, 4);
            if (packet.Length > truncateBy)
            {
                byte[] truncatedPacket = packet[..^truncateBy];
                Assert.False(QuicPacketParser.TryParseVersionNegotiation(truncatedPacket, out _));
            }
        }
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0001">The first bit of a QUIC long header packet MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0003">The four bytes after the first byte in a QUIC long header packet MUST contain a 32-bit Version field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0004">The byte after the Version field MUST encode the Destination Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0008">The remainder of a QUIC long header packet MUST contain version-specific content.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0012">A Version Negotiation packet MUST echo the connection IDs selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0001">If the version selected by the client is not acceptable to the server, the server MUST respond with a Version Negotiation packet that includes a list of versions the server will accept.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P1-0002">An endpoint MUST NOT send a Version Negotiation packet in response to receiving a Version Negotiation packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P2-0002">Each endpoint MUST use the Source Connection ID field to specify the connection ID that is used in the Destination Connection ID field of packets being sent to it.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S5-0003">Version Negotiation packets MUST NOT have cryptographic protection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P2-0002")]
    [Requirement("REQ-QUIC-RFC9001-S5-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_VersionNegotiationFormatting_RoundTripsFormattedResponses()
    {
        Random random = new(0x5150_2030);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] clientDestinationConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            byte[] clientSourceConnectionId = QuicHeaderTestData.RandomBytes(random, random.Next(0, 21));
            uint clientSelectedVersion = (uint)random.Next(2, int.MaxValue);
            uint[] serverSupportedVersions = new uint[random.Next(1, 5)];

            for (int index = 0; index < serverSupportedVersions.Length; index++)
            {
                serverSupportedVersions[index] = index == 0 && (iteration & 1) == 0
                    ? QuicVersionNegotiation.CreateReservedVersion((uint)random.Next())
                    : NextAdvertisedVersion(random, clientSelectedVersion);
            }

            byte[] destination = new byte[512];

            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                clientSelectedVersion,
                clientDestinationConnectionId,
                clientSourceConnectionId,
                serverSupportedVersions,
                destination,
                out int bytesWritten));
            Assert.True(QuicPacketParser.TryParseVersionNegotiation(destination.AsSpan(0, bytesWritten), out QuicVersionNegotiationPacket packet));
            Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
            Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
            Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);

            for (int index = 0; index < serverSupportedVersions.Length; index++)
            {
                Assert.Equal(serverSupportedVersions[index], packet.GetSupportedVersion(index));
            }
        }
    }

    private static uint NextAdvertisedVersion(Random random, uint excludedVersion)
    {
        while (true)
        {
            uint candidate = (uint)random.Next(1, int.MaxValue);
            if (candidate != excludedVersion)
            {
                return candidate;
            }
        }
    }
}

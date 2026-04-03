namespace Incursa.Quic.Tests;

public sealed class QuicHeaderFuzzTests
{
    [Fact]
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

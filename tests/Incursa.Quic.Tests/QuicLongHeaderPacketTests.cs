namespace Incursa.Quic.Tests;

public sealed class QuicLongHeaderPacketTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9002-S3-0001")]
    [Requirement("REQ-QUIC-RFC9002-S3-0003")]
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
    [Requirement("REQ-QUIC-RFC9000-S5P1-0008")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_RoundTripsLengthEncodedConnectionIdsAndPayload()
    {
        byte[] destinationConnectionId = [0x10, 0x11, 0x12];
        byte[] sourceConnectionId = [0x20, 0x21];
        byte[] versionSpecificData = [0x30, 0x31, 0x32, 0x33];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x4A,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        Assert.Equal((byte)0x4A, header.HeaderControlBits);
        Assert.True(header.FixedBit);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
        Assert.Equal((byte)0x02, header.ReservedBits);
        Assert.Equal((uint)0x11223344, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Theory]
    [InlineData((byte)0x4A, (byte)0x00)]
    [InlineData((byte)0x5A, (byte)0x01)]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0001")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0002")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0003")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0008")]
    [Requirement("REQ-QUIC-RFC9002-S3-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0009")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesLongPacketTypeAndPacketNumberLengthBits(
        byte headerControlBits,
        byte expectedLongPacketTypeBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 0x11223344,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21],
            versionSpecificData: [0x30, 0x31]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.True(header.FixedBit);
        Assert.Equal(expectedLongPacketTypeBits, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.Equal((byte)0x02, header.ReservedBits);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsVersion1InitialPacketsWithValidStructuralFields()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA0, 0xA1],
            packetNumber: [0x01, 0x02, 0x03],
            protectedPayload: [0xB0, 0xB1]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11, 0x12],
            sourceConnectionId: [0x20, 0x21],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal((byte)0x00, header.LongPacketTypeBits);
        Assert.Equal((byte)0x02, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0013")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsZeroLengthConnectionIds()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [],
            packetNumber: [0x01],
            protectedPayload: [0xAA]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [],
            sourceConnectionId: [],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(0, header.DestinationConnectionIdLength);
        Assert.Equal(0, header.SourceConnectionIdLength);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsVersion1ZeroRttPacketsWithValidStructuralFields()
    {
        byte[] versionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0, 0xB1, 0xB2]);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x51,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20, 0x21, 0x22],
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal((byte)0x01, header.LongPacketTypeBits);
        Assert.Equal((byte)0x01, header.PacketNumberLengthBits);
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    public static TheoryData<byte[]> TruncatedLongHeaderCases => new()
    {
        { [] },
        { [0x80] },
        { [0x80, 0x00, 0x00, 0x00, 0x01] },
        { [0x80, 0x00, 0x00, 0x00, 0x01, 0x00] },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x52, 0x01020304, [0x11, 0x12], [0x21], [], 1) },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x52, 0x01020304, [0x11, 0x12], [0x21, 0x22], [], 1) },
    };

    public static TheoryData<byte[]> InvalidInitialVersionSpecificDataCases => new()
    {
        { [] },
        { [0x40] },
        { [0x02, 0xAA] },
        { [0x00] },
        { [0x00, 0x40] },
        { [0x00, 0x00] },
        { [0x00, 0x02, 0xAA] },
    };

    public static TheoryData<byte[]> InvalidZeroRttVersionSpecificDataCases => new()
    {
        { [] },
        { [0x40] },
        { [0x00] },
        { [0x02, 0xAA] },
    };

    [Theory]
    [MemberData(nameof(TruncatedLongHeaderCases))]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsTruncatedInputs(byte[] packet)
    {
        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [MemberData(nameof(InvalidInitialVersionSpecificDataCases))]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0017")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsVersion1InitialPacketsWithInvalidStructuralFields(
        byte[] versionSpecificData)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x40,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [MemberData(nameof(InvalidZeroRttVersionSpecificDataCases))]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0016")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsVersion1ZeroRttPacketsWithInvalidStructuralFields(
        byte[] versionSpecificData)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x50,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            versionSpecificData);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P1-0013")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_ExposesZeroVersionAsVersionNegotiationState()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x2C,
            version: 0,
            destinationConnectionId: [0x01],
            sourceConnectionId: [0x02, 0x03],
            versionSpecificData: [0x04, 0x05, 0x06, 0x07]);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)0, header.Version);
        Assert.True(header.IsVersionNegotiation);
        Assert.False(header.FixedBit);
    }

    [Theory]
    [InlineData(0x00)]
    [InlineData(0x3F)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0005")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsShortHeaderForm(byte headerControlBits)
    {
        byte[] shortHeader = QuicHeaderTestData.BuildShortHeader(
            headerControlBits,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        Assert.False(QuicPacketParser.TryParseLongHeader(shortHeader, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0006")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsNonVersionNegotiationPacketsWithZeroFixedBit()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x12,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21, 0x22],
            versionSpecificData: [0x33, 0x34]);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildTruncatedLongHeader(
            headerControlBits: 0x52,
            version: 0x01020304,
            destinationConnectionId: [0x11, 0x12],
            sourceConnectionId: [0x21, 0x22],
            versionSpecificData: [],
            truncateBy: 3);

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0005")]
    [Requirement("REQ-QUIC-RFC8999-S5P1-0007")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AcceptsMaximumLengthConnectionIds()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, byte.MaxValue).ToArray();
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, byte.MaxValue).ToArray();
        byte[] versionSpecificData = [0x10, 0x20, 0x30];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(byte.MaxValue, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(byte.MaxValue, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Theory]
    [InlineData(0x40)]
    [InlineData(0x50)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsInitialAndZeroRttConnectionIdsUpTo20Bytes(byte headerControlBits)
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, 20).ToArray();
        byte[] sourceConnectionId = Enumerable.Repeat((byte)0x5C, 20).ToArray();
        byte[] versionSpecificData = BuildValidVersion1VersionSpecificData(headerControlBits);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(20, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(20, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Theory]
    [InlineData(0x40)]
    [InlineData(0x50)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsInitialAndZeroRttDestinationConnectionIdsLongerThan20Bytes(
        byte headerControlBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: Enumerable.Repeat((byte)0xDA, 21).ToArray(),
            sourceConnectionId: [0x5C],
            versionSpecificData: BuildValidVersion1VersionSpecificData(headerControlBits));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Theory]
    [InlineData(0x40)]
    [InlineData(0x50)]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsInitialAndZeroRttSourceConnectionIdsLongerThan20Bytes(
        byte headerControlBits)
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits,
            version: 1,
            destinationConnectionId: [0xDA],
            sourceConnectionId: Enumerable.Repeat((byte)0x5C, 21).ToArray(),
            versionSpecificData: BuildValidVersion1VersionSpecificData(headerControlBits));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0020")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsVersion1DestinationConnectionIdUpTo20Bytes()
    {
        byte[] destinationConnectionId = Enumerable.Repeat((byte)0xDA, 20).ToArray();
        byte[] sourceConnectionId = [0x5C];
        byte[] versionSpecificData = BuildValidVersion1VersionSpecificData(0x41);
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((uint)1, header.Version);
        Assert.Equal(20, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0021")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsVersion1DestinationConnectionIdLongerThan20Bytes()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x41,
            version: 1,
            destinationConnectionId: Enumerable.Repeat((byte)0xDA, 21).ToArray(),
            sourceConnectionId: [0x5C],
            versionSpecificData: BuildValidVersion1VersionSpecificData(0x41));

        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    private static byte[] BuildValidVersion1VersionSpecificData(byte headerControlBits)
    {
        int packetNumberLength = (headerControlBits & 0x03) + 1;
        byte[] packetNumber = Enumerable.Range(0, packetNumberLength).Select(index => (byte)(index + 1)).ToArray();
        byte[] protectedPayload = [0xFA];
        return (headerControlBits & 0x30) == 0x10
            ? QuicHeaderTestData.BuildZeroRttVersionSpecificData(packetNumber, protectedPayload)
            : QuicHeaderTestData.BuildInitialVersionSpecificData([0xAA], packetNumber, protectedPayload);
    }
}

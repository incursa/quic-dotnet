namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0005">Versions (Section 15), packet numbers sent in the header (Section 17.1), and the length of connection IDs in long header packets (Section 17.2) are described using integers but MUST NOT use this encoding.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S16-0005")]
public sealed class REQ_QUIC_RFC9000_S16_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeaderFields_ExposesTheFixedWidthVersionPacketNumberAndConnectionIdFields()
    {
        byte[] destinationConnectionId =
        [
            0x11, 0x12, 0x13,
        ];
        byte[] sourceConnectionId =
        [
            0x21, 0x22,
        ];
        byte[] packetNumber =
        [
            0x31, 0x32, 0x33, 0x34,
        ];
        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId,
            sourceConnectionId,
            token: [],
            packetNumber: packetNumber,
            plaintextPayload:
            [
                0x41, 0x42, 0x43, 0x44,
            ]);

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            plaintextPacket,
            out byte headerControlBits,
            out uint version,
            out ReadOnlySpan<byte> parsedDestinationConnectionId,
            out ReadOnlySpan<byte> parsedSourceConnectionId,
            out ReadOnlySpan<byte> versionSpecificData));

        byte[] expectedVersionBytes =
        [
            0x00, 0x00, 0x00, 0x01,
        ];

        Assert.Equal(QuicVersionNegotiation.Version1, version);
        Assert.True(expectedVersionBytes.AsSpan().SequenceEqual(plaintextPacket.AsSpan(1, 4)));
        Assert.Equal((byte)(packetNumber.Length - 1), (byte)(headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask));
        Assert.Equal(destinationConnectionId.Length, plaintextPacket[5]);
        Assert.Equal(sourceConnectionId.Length, plaintextPacket[6 + destinationConnectionId.Length]);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(parsedDestinationConnectionId));
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(parsedSourceConnectionId));
        Assert.True(packetNumber.AsSpan().SequenceEqual(GetInitialPacketNumberBytes(versionSpecificData, packetNumber.Length)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseLongHeaderFields_RejectsPacketsMissingTheSourceConnectionIdLengthByte()
    {
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x03,
            version: 0x11223344,
            destinationConnectionId:
            [
                0x11, 0x12, 0x13,
            ],
            sourceConnectionId:
            [
                0x21, 0x22,
            ],
            versionSpecificData:
            [
                0x41, 0x42, 0x43,
            ]);

        Assert.False(QuicPacketParsing.TryParseLongHeaderFields(
            packet[..9],
            out _,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseLongHeaderFields_AllowsMaximumLengthConnectionIds()
    {
        byte[] destinationConnectionId = new byte[byte.MaxValue];
        byte[] sourceConnectionId = new byte[byte.MaxValue];
        byte[] packet = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x03,
            version: 0x11223344,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData: []);

        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            packet,
            out _,
            out _,
            out ReadOnlySpan<byte> parsedDestinationConnectionId,
            out ReadOnlySpan<byte> parsedSourceConnectionId,
            out _));

        Assert.Equal(byte.MaxValue, parsedDestinationConnectionId.Length);
        Assert.Equal(byte.MaxValue, parsedSourceConnectionId.Length);
        Assert.Equal(byte.MaxValue, packet[5]);
        Assert.Equal(byte.MaxValue, packet[6 + byte.MaxValue]);
    }

    private static ReadOnlySpan<byte> GetInitialPacketNumberBytes(ReadOnlySpan<byte> versionSpecificData, int packetNumberLength)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes));

        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + checked((int)tokenLength));
        Assert.True(QuicVariableLengthInteger.TryParse(afterToken, out _, out int lengthFieldBytes));

        return afterToken.Slice(lengthFieldBytes, packetNumberLength);
    }
}

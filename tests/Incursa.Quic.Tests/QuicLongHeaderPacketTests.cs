namespace Incursa.Quic.Tests;

public sealed class QuicLongHeaderPacketTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0003")]
    [Trait("Requirement", "REQ-QUIC-HDR-0005")]
    [Trait("Requirement", "REQ-QUIC-HDR-0006")]
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
        Assert.Equal((uint)0x11223344, header.Version);
        Assert.False(header.IsVersionNegotiation);
        Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
        Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
        Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
    }

    public static TheoryData<byte[]> TruncatedLongHeaderCases => new()
    {
        { [] },
        { [0x80] },
        { [0x80, 0x00, 0x00, 0x00, 0x01] },
        { [0x80, 0x00, 0x00, 0x00, 0x01, 0x00] },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x12, 0x01020304, [0x11, 0x12], [0x21], [], 1) },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x12, 0x01020304, [0x11, 0x12], [0x21, 0x22], [], 1) },
    };

    [Theory]
    [MemberData(nameof(TruncatedLongHeaderCases))]
    [Trait("Requirement", "REQ-QUIC-HDR-0004")]
    [Trait("Category", "Negative")]
    public void TryParseLongHeader_RejectsTruncatedInputs(byte[] packet)
    {
        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0006")]
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
    }
}

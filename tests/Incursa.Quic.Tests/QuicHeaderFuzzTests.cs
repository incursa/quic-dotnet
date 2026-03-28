namespace Incursa.Quic.Tests;

public sealed class QuicHeaderFuzzTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-HDR-0001")]
    [Trait("Requirement", "REQ-QUIC-HDR-0002")]
    [Trait("Requirement", "REQ-QUIC-HDR-0003")]
    [Trait("Requirement", "REQ-QUIC-HDR-0004")]
    [Trait("Requirement", "REQ-QUIC-HDR-0005")]
    [Trait("Requirement", "REQ-QUIC-HDR-0006")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeaderParsing_RoundTripsValidInputsAndRejectsTruncation()
    {
        Random random = new(0x5150_2026);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte headerControlBits = (byte)random.Next(0, 0x80);
            uint version = (uint)random.Next(0, int.MaxValue);
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
    [Trait("Requirement", "REQ-QUIC-HDR-0008")]
    [Trait("Requirement", "REQ-QUIC-HDR-0009")]
    [Trait("Requirement", "REQ-QUIC-HDR-0010")]
    [Trait("Category", "Fuzz")]
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
}

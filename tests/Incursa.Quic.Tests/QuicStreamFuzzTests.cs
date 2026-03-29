using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamFuzzTests
{
    [Fact]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Requirement", "REQ-QUIC-VINT-0004")]
    [Trait("Requirement", "REQ-QUIC-VINT-0005")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VarintParsing_RoundTripsRepresentativeValuesAndRejectsTruncation()
    {
        Random random = new(0x5150_2028);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            ulong value = BuildRepresentableValue(random);
            byte[] encoded = QuicVarintTestData.EncodeMinimal(value);

            Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
            Assert.Equal(value, parsed);
            Assert.Equal(encoded.Length, bytesConsumed);

            if (encoded.Length > 1)
            {
                byte[] truncated = encoded[..(encoded.Length - 1)];
                Assert.False(QuicVariableLengthInteger.TryParse(truncated, out _, out _));
            }
        }
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0001")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0003")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0004")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0005")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0006")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0008")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0009")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0010")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0011")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0012")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0013")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0014")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0015")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0016")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0017")]
    [Trait("Requirement", "REQ-QUIC-RFC9000-S19P8-0018")]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StreamParsing_RoundTripsRepresentativeFramesAndRejectsTruncation()
    {
        Random random = new(0x5150_2029);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte frameType = (byte)random.Next(0x0A, 0x10);
            ulong streamId = BuildRepresentableValue(random);
            ulong offset = (ulong)random.Next(0, 4096);
            byte[] streamData = new byte[random.Next(1, 16)];
            random.NextBytes(streamData);

            byte[] packet = QuicStreamTestData.BuildStreamFrame(frameType, streamId, streamData, offset);

            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
            Assert.Equal(frameType, frame.FrameType);
            Assert.Equal(streamId, frame.StreamId.Value);
            Assert.Equal((QuicStreamType)(streamId & 0x03), frame.StreamType);
            Assert.Equal((frameType & 0x04) != 0, frame.HasOffset);
            Assert.Equal((frameType & 0x04) != 0 ? offset : 0, frame.Offset);
            Assert.Equal((frameType & 0x02) != 0, frame.HasLength);
            Assert.Equal((frameType & 0x02) != 0 ? (ulong)streamData.Length : 0, frame.Length);
            Assert.Equal((frameType & 0x01) != 0, frame.IsFin);
            Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));

            int truncatedLength = random.Next(1, 4);
            truncatedLength = Math.Min(packet.Length - 1, truncatedLength);
            byte[] truncated = packet[..truncatedLength];
            Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
        }
    }

    private static ulong BuildRepresentableValue(Random random)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        random.NextBytes(buffer);
        return BinaryPrimitives.ReadUInt64BigEndian(buffer) & QuicVariableLengthInteger.MaxValue;
    }
}

using System.Buffers.Binary;
using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
public sealed class REQ_QUIC_RFC9000_S19P8_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_StreamParsing_RoundTripsRepresentativeFramesAndRejectsTruncation()
    {
        Random random = new(0x5150_2029);
        Span<byte> destination = stackalloc byte[128];

        Span<byte> valueBuffer = stackalloc byte[sizeof(ulong)];
        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte frameType = (byte)random.Next(0x0A, 0x10);

            random.NextBytes(valueBuffer);
            ulong streamId = BinaryPrimitives.ReadUInt64BigEndian(valueBuffer) & QuicVariableLengthInteger.MaxValue;

            ulong offset = (ulong)random.Next(0, 4096);
            byte[] streamData = new byte[random.Next(1, 16)];
            random.NextBytes(streamData);

            byte[] packet = QuicStreamTestData.BuildStreamFrame(frameType, streamId, streamData, offset);

            Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
            Assert.Equal(frameType, frame.FrameType);
            Assert.Equal(streamId, frame.StreamId.Value);
            Assert.Equal((streamId & 0x02) == 0 ? QuicStreamType.Bidirectional : QuicStreamType.Unidirectional, frame.StreamType);
            Assert.Equal((frameType & 0x04) != 0, frame.HasOffset);
            Assert.Equal((frameType & 0x04) != 0 ? offset : 0, frame.Offset);
            Assert.Equal((frameType & 0x02) != 0, frame.HasLength);
            Assert.Equal((frameType & 0x02) != 0 ? (ulong)streamData.Length : 0, frame.Length);
            Assert.Equal((frameType & 0x01) != 0, frame.IsFin);
            Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));

            destination.Clear();
            Assert.True(QuicFrameCodec.TryFormatStreamFrame(
                frame.FrameType,
                frame.StreamId.Value,
                frame.Offset,
                frame.StreamData,
                destination,
                out int bytesWritten));
            Assert.Equal(packet.Length, bytesWritten);
            Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));

            int truncatedLength = random.Next(1, 4);
            truncatedLength = Math.Min(packet.Length - 1, truncatedLength);
            byte[] truncated = packet[..truncatedLength];
            Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
        }
    }

    [Property(Arbitrary = new[] { typeof(QuicStreamFramePropertyGenerators) })]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Property")]
    public void TryParseStreamFrame_RoundTripsRepresentableStreamShapes(StreamFrameScenario scenario)
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            scenario.FrameType,
            scenario.StreamId,
            scenario.StreamData,
            scenario.Offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal(scenario.FrameType, frame.FrameType);
        Assert.Equal(scenario.StreamId, frame.StreamId.Value);
        Assert.Equal((scenario.StreamId & 0x02) == 0 ? QuicStreamType.Bidirectional : QuicStreamType.Unidirectional, frame.StreamType);
        Assert.Equal((scenario.FrameType & 0x04) != 0, frame.HasOffset);
        Assert.Equal((scenario.FrameType & 0x04) != 0 ? scenario.Offset : 0, frame.Offset);
        Assert.Equal((scenario.FrameType & 0x02) != 0, frame.HasLength);
        Assert.Equal((scenario.FrameType & 0x02) != 0 ? (ulong)scenario.StreamData.Length : 0, frame.Length);
        Assert.Equal((scenario.FrameType & 0x01) != 0, frame.IsFin);
        Assert.True(scenario.StreamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(scenario.StreamData.Length, frame.StreamDataLength);
        Assert.Equal(packet.Length, frame.ConsumedLength);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

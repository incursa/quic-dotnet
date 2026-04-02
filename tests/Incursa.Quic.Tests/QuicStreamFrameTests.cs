using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamFrameTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0017")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_ParsesOffsetsLengthsAndPayloadBytes()
    {
        byte frameType = 0x0F;
        byte[] streamData = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType,
            streamId: 0x06,
            streamData,
            offset: 0x11223344);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal(frameType, frame.FrameType);
        Assert.Equal((ulong)0x06, frame.StreamId.Value);
        Assert.Equal(QuicStreamType.ClientInitiatedUnidirectional, frame.StreamType);
        Assert.True(frame.HasOffset);
        Assert.Equal((ulong)0x11223344, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_UsesTheRemainderWhenLengthIsAbsent()
    {
        byte frameType = 0x08;
        byte[] streamData = [0x10, 0x20, 0x30];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType,
            streamId: 0x04,
            streamData);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.False(frame.HasOffset);
        Assert.Equal(0UL, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.False(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Trait("Category", "Negative")]
    public void TryFormatStreamFrame_RejectsInvalidTypesAndOffsetMismatches()
    {
        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x07, 0x04, 0, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x08, 0x04, 1, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x0F, 0x04, QuicVariableLengthInteger.MaxValue, [0xAA], destination, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsFramesWithNonStreamTypes()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x06, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x07, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x10, 0x00], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsEmptyInput()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame(Array.Empty<byte>(), out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsNonShortestFrameTypeEncoding()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrameWithEncodedType(
            frameType: 0x08,
            encodedLength: 2,
            streamId: 0x00,
            streamData: [0x00, 0x00]);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsTruncatedFixedFields(int truncateBy)
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x04,
            streamData: [0xAA, 0xBB],
            offset: 0x11223344);

        byte[] truncated = packet[..Math.Max(0, packet.Length - truncateBy)];

        Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsTruncatedOffsetField()
    {
        Span<byte> offsetEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue, offsetEncoding, out int offsetBytes));

        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x04,
            streamData: [0xAA],
            offset: QuicVariableLengthInteger.MaxValue);

        byte[] truncated = packet[..(1 + 1 + offsetBytes - 1)];

        Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsOffsetsThatExceedTheStreamCeiling()
    {
        Span<byte> offsetEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue, offsetEncoding, out int offsetBytes));

        Span<byte> lengthEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(1, lengthEncoding, out int lengthBytes));

        byte[] packet = new byte[1 + 1 + offsetBytes + lengthBytes + 1];
        int index = 0;
        packet[index++] = 0x0F;
        packet[index++] = 0x00;
        offsetEncoding[..offsetBytes].CopyTo(packet.AsSpan(index));
        index += offsetBytes;
        lengthEncoding[..lengthBytes].CopyTo(packet.AsSpan(index));
        index += lengthBytes;
        packet[index] = 0xFF;

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_AcceptsOffsetsThatExactlyReachTheStreamCeiling()
    {
        byte[] streamData = [0xAB];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x00,
            streamData,
            offset: QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.True(frame.HasLength);
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, frame.Offset);
        Assert.Equal(1UL, frame.Length);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset + frame.Length);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_AcceptsOffsetsThatExactlyReachTheStreamCeilingWithoutALengthField()
    {
        byte[] streamData = [0xCD];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x00,
            streamData,
            offset: QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.Offset + (ulong)frame.StreamDataLength);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
    [Trait("Category", "Negative")]
    public void TryParseStreamFrame_RejectsOffsetsThatExceedTheStreamCeilingWithoutALengthField()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x00,
            streamData: [0xEF],
            offset: QuicVariableLengthInteger.MaxValue);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0017")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_PreservesZeroLengthPayloadOffsets()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x02,
            streamData: [],
            offset: 0x1A2B3C4D);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal((ulong)0x1A2B3C4D, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.StreamData.IsEmpty);
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsPresent()
    {
        byte[] streamData = [0xAA];
        ulong offset = QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal((ulong)0x06, frame.StreamId.Value);
        Assert.True(frame.HasOffset);
        Assert.Equal(offset, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal((ulong)streamData.Length, frame.Length);
        Assert.True(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Trait("Category", "Positive")]
    public void TryParseStreamFrame_AcceptsOffsetsAtTheStreamCeilingWhenLengthIsAbsent()
    {
        byte[] streamData = [0x10];
        ulong offset = QuicVariableLengthInteger.MaxValue - (ulong)streamData.Length;
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x04,
            streamData,
            offset);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.Equal((ulong)0x04, frame.StreamId.Value);
        Assert.True(frame.HasOffset);
        Assert.Equal(offset, frame.Offset);
        Assert.False(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.False(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(streamData.Length, frame.StreamDataLength);
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Property(Arbitrary = new[] { typeof(QuicStreamFramePropertyGenerators) })]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0006")]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0014")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0015")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0016")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0017")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
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
        Assert.Equal((QuicStreamType)(scenario.StreamId & 0x03), frame.StreamType);
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

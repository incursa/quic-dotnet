using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamFrameTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0001">STREAM frames MUST encapsulate data sent by an application.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0002">An endpoint MUST use the Stream ID and Offset fields in STREAM frames to place data in order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0009">Streams MUST be an ordered byte-stream abstraction with no other structure visible to QUIC.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0004">An application protocol MAY end a stream, resulting in a STREAM frame with the FIN bit set.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0006">An application protocol MAY read data from a stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0002">The final size of a stream MUST be the sum of the Offset and Length fields of a STREAM frame with a FIN flag, including any implicit values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S3-0012">QUIC applications that want to send data MUST send it as QUIC STREAM frames or other frame types carried in QUIC packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0001">The OFF bit (0x04) in the frame type MUST be set to indicate that there is an Offset field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0003">The LEN bit (0x02) in the frame type MUST be set to indicate that there is a Length field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0005">If this bit MUST be set to 1, the Length field is present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0006">The FIN bit (0x01) MUST indicate that the frame marks the end of the stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0009">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0010">The Offset field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0011">The Length field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0012">STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0013">The Stream ID field MUST be variable-length integer indicating the stream ID of the stream; see Section 2.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0014">The Offset field MUST be variable-length integer specifying the byte offset in the stream for the data in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0015">This field is present when the OFF bit MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0016">The Length field MUST be variable-length integer specifying the length of the Stream Data field in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0017">This field is present when the LEN bit MUST be set to 1.</workbench-requirement>
    /// </workbench-requirements>
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
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0001">STREAM frames MUST encapsulate data sent by an application.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0002">An endpoint MUST use the Stream ID and Offset fields in STREAM frames to place data in order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0009">Streams MUST be an ordered byte-stream abstraction with no other structure visible to QUIC.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0004">An application protocol MAY end a stream, resulting in a STREAM frame with the FIN bit set.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0006">An application protocol MAY read data from a stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0002">The final size of a stream MUST be the sum of the Offset and Length fields of a STREAM frame with a FIN flag, including any implicit values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S3-0012">QUIC applications that want to send data MUST send it as QUIC STREAM frames or other frame types carried in QUIC packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0002">When set to 0, the Offset field is absent and the Stream Data starts at an offset of 0 (that is, the frame MUST contain the first bytes of the stream, or the end of a stream that includes no data).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0004">If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to the end of the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0009">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0012">STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0013">The Stream ID field MUST be variable-length integer indicating the stream ID of the stream; see Section 2.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0018">When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in the packet.</workbench-requirement>
    /// </workbench-requirements>
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
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S3-0012">QUIC applications that want to send data MUST send it as QUIC STREAM frames or other frame types carried in QUIC packets.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatStreamFrame_RejectsInvalidTypesAndOffsetMismatches()
    {
        Span<byte> destination = stackalloc byte[64];

        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x07, 0x04, 0, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x08, 0x04, 1, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x0F, 0x04, QuicVariableLengthInteger.MaxValue, [0xAA], destination, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0004">Data sent in CRYPTO frames MUST NOT be flow controlled in the same way as stream data.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsFramesWithNonStreamTypes()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x06, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x07, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x10, 0x00], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsEmptyInput()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame(Array.Empty<byte>(), out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0009">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0010">The Offset field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0011">The Length field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0010">The Offset field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0020">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or FLOW_CONTROL_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0004">If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to the end of the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0018">When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0004">If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to the end of the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0018">When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0020">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or FLOW_CONTROL_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S3-0012">QUIC applications that want to send data MUST send it as QUIC STREAM frames or other frame types carried in QUIC packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0001">The OFF bit (0x04) in the frame type MUST be set to indicate that there is an Offset field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0003">The LEN bit (0x02) in the frame type MUST be set to indicate that there is a Length field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0005">If this bit MUST be set to 1, the Length field is present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0006">The FIN bit (0x01) MUST indicate that the frame marks the end of the stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0009">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0010">The Offset field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0011">The Length field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0012">STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0013">The Stream ID field MUST be variable-length integer indicating the stream ID of the stream; see Section 2.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0014">The Offset field MUST be variable-length integer specifying the byte offset in the stream for the data in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0015">This field is present when the OFF bit MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0016">The Length field MUST be variable-length integer specifying the length of the Stream Data field in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0017">This field is present when the LEN bit MUST be set to 1.</workbench-requirement>
    /// </workbench-requirements>
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
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0002">The final size of a stream MUST be the sum of the Offset and Length fields of a STREAM frame with a FIN flag, including any implicit values.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0004">If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to the end of the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0018">When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0019">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1, as it is not possible to provide flow control credit for that data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0002">The final size of a stream MUST be the sum of the Offset and Length fields of a STREAM frame with a FIN flag, including any implicit values.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P8-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0018")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0019")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0001">STREAM frames MUST encapsulate data sent by an application.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0002">An endpoint MUST use the Stream ID and Offset fields in STREAM frames to place data in order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0009">Streams MUST be an ordered byte-stream abstraction with no other structure visible to QUIC.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0004">An application protocol MAY end a stream, resulting in a STREAM frame with the FIN bit set.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0006">An application protocol MAY read data from a stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S3-0012">QUIC applications that want to send data MUST send it as QUIC STREAM frames or other frame types carried in QUIC packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0002">The final size of a stream MUST be the sum of the Offset and Length fields of a STREAM frame with a FIN flag, including any implicit values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0001">The OFF bit (0x04) in the frame type MUST be set to indicate that there is an Offset field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0002">When set to 0, the Offset field is absent and the Stream Data starts at an offset of 0 (that is, the frame MUST contain the first bytes of the stream, or the end of a stream that includes no data).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0003">The LEN bit (0x02) in the frame type MUST be set to indicate that there is a Length field present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0004">If this bit MUST be set to 0, the Length field is absent and the Stream Data field extends to the end of the packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0005">If this bit MUST be set to 1, the Length field is present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0006">The FIN bit (0x01) MUST indicate that the frame marks the end of the stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0008">The Type field MUST be encoded as a variable-length integer with value 0x08..0x0f.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0009">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0010">The Offset field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0011">The Length field MUST be encoded as a variable-length integer when present.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0012">STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0013">The Stream ID field MUST be variable-length integer indicating the stream ID of the stream; see Section 2.1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0014">The Offset field MUST be variable-length integer specifying the byte offset in the stream for the data in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0015">This field is present when the OFF bit MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0016">The Length field MUST be variable-length integer specifying the length of the Stream Data field in this STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0017">This field is present when the LEN bit MUST be set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0018">When the LEN bit MUST be set to 0, the Stream Data field consumes all the remaining bytes in the packet.</workbench-requirement>
    /// </workbench-requirements>
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

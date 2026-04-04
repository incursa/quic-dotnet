namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecPart4Tests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0003">The Type field MUST be encoded as a variable-length integer with value 0x14.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0004">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0005">DATA_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0006">The Maximum Data field MUST be variable-length integer indicating the connection-level limit at which blocking occurred.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0014">A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver that it has data to write but is blocked by flow control limits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseDataBlockedFrame_ParsesAndFormatsTheMaximumDataField()
    {
        QuicDataBlockedFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(encoded, out QuicDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0004">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0005">DATA_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0006">The Maximum Data field MUST be variable-length integer indicating the connection-level limit at which blocking occurred.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseDataBlockedFrame_RejectsTruncatedInput()
    {
        byte[] encoded = QuicFrameTestData.BuildDataBlockedFrame(new QuicDataBlockedFrame(0x01));

        Assert.False(QuicFrameCodec.TryParseDataBlockedFrame(encoded[..^1], out _, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0003">The Type field MUST be encoded as a variable-length integer with value 0x15.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0004">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0005">The Maximum Stream Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0006">STREAM_DATA_BLOCKED frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0007">The Stream ID field MUST be variable-length integer indicating the stream that is blocked due to flow control.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0008">The Maximum Stream Data field MUST be variable-length integer indicating the offset of the stream at which the blocking occurred.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0014">A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver that it has data to write but is blocked by flow control limits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamDataBlockedFrame_ParsesAndFormatsTheFrameFields()
    {
        QuicStreamDataBlockedFrame frame = new(0x06, 0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(encoded, out QuicStreamDataBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStreamDataBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0004">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0005">The Maximum Stream Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0006">STREAM_DATA_BLOCKED frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0007">The Stream ID field MUST be variable-length integer indicating the stream that is blocked due to flow control.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P13-0008">The Maximum Stream Data field MUST be variable-length integer indicating the offset of the stream at which the blocking occurred.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamDataBlockedFrame_RejectsTruncatedInput()
    {
        byte[] encoded = QuicFrameTestData.BuildStreamDataBlockedFrame(new QuicStreamDataBlockedFrame(0x06, 0x01));

        Assert.False(QuicFrameCodec.TryParseStreamDataBlockedFrame(encoded[..^1], out _, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0002">A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0004">The Type field MUST be encoded as a variable-length integer with value 0x16..0x17.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0005">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0006">STREAMS_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0007">The Maximum Streams field MUST be variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0012">An endpoint that is unable to open a new stream due to the peer&apos;s limits SHOULD send a STREAMS_BLOCKED frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamsBlockedFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicStreamsBlockedFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0002">A STREAMS_BLOCKED frame of type 0x16 MUST be used to indicate reaching the bidirectional stream limit, and a STREAMS_BLOCKED frame of type 0x17 is used to indicate reaching the unidirectional stream limit.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0004">The Type field MUST be encoded as a variable-length integer with value 0x16..0x17.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0005">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0006">STREAMS_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0007">The Maximum Streams field MUST be variable-length integer indicating the maximum number of streams allowed at the time the frame was sent.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0008">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamsBlockedFrame_AcceptsValueAtTheEncodingLimit(bool isBidirectional)
    {
        ulong limit = 1UL << 60;
        QuicStreamsBlockedFrame frame = new(isBidirectional, limit);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out QuicStreamsBlockedFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(limit, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatStreamsBlockedFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0008">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P14-0009">Receipt of a frame that encodes a larger stream ID MUST be treated as a connection error of type STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamsBlockedFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicStreamsBlockedFrame frame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0002">The Type field MUST be encoded as a variable-length integer with value 0x18.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0003">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0004">The Retire Prior To field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0005">The Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0006">The Connection ID field MUST be between 8 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0007">The Stateless Reset Token field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0008">NEW_CONNECTION_ID frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0009">The Retire Prior To field MUST be a variable-length integer indicating which connection IDs should be retired; see Section 5.1.2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0017">An endpoint MUST issue a stateless reset token by including the value in the Stateless Reset Token field of a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0008">An endpoint MAY cause its peer to retire connection IDs by sending a NEW_CONNECTION_ID frame with an increased Retire Prior To field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewConnectionIdFrame_ParsesAndFormatsTheEncodedFields()
    {
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(20)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0008">An endpoint MAY cause its peer to retire connection IDs by sending a NEW_CONNECTION_ID frame with an increased Retire Prior To field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0005">The Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0006">The Connection ID field MUST be between 8 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0011">Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0017">An endpoint MUST issue a stateless reset token by including the value in the Stateless Reset Token field of a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0005">Additional connection IDs MUST be communicated to the peer using NEW_CONNECTION_ID frames.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewConnectionIdFrame_AcceptsBoundaryConnectionIdLengths(int connectionIdLength)
    {
        byte[] connectionId = Enumerable.Repeat((byte)0xDA, connectionIdLength).ToArray();
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();
        QuicNewConnectionIdFrame frame = new(0x09, 0x01, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
        Assert.Equal(connectionIdLength, parsed.ConnectionId.Length);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0010">The Length field MUST be 8-bit unsigned integer containing the length of the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0011">Values less than 1 and greater than 20 are invalid and MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0003">A stateless reset token MUST be 16 bytes long and difficult to guess.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0011")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsInvalidConnectionIdLengthValues()
    {
        byte[] statelessResetToken = Enumerable.Repeat((byte)0x5C, 16).ToArray();

        QuicNewConnectionIdFrame zeroLengthFrame = new(0x01, 0x00, Array.Empty<byte>(), statelessResetToken);
        byte[] zeroLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(zeroLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(zeroLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame longLengthFrame = new(0x02, 0x01, Enumerable.Repeat((byte)0xDA, 21).ToArray(), statelessResetToken);
        byte[] longLengthEncoded = QuicFrameTestData.BuildNewConnectionIdFrame(longLengthFrame);
        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(longLengthEncoded, out _, out _));

        QuicNewConnectionIdFrame invalidTokenFrame = new(0x03, 0x01, [0xAA], Enumerable.Repeat((byte)0xCC, 15).ToArray());
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(invalidTokenFrame, stackalloc byte[64], out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0008">NEW_CONNECTION_ID frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0012">The Connection ID field MUST be connection ID of the specified length.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0013">A 128-bit value that will be used for a stateless reset when the associated connection ID MUST be used; see Section 10.3.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        byte[] connectionId = [0x10];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x06, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded[..Math.Max(0, encoded.Length - truncateBy)], out _, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsRetirePriorToGreaterThanSequenceNumber()
    {
        byte[] connectionId = [0x10, 0x11];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x03, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, stackalloc byte[64], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0004">When the endpoint wishes to remove a connection ID from use, it MUST send a RETIRE_CONNECTION_ID frame to its peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0005">Sending a RETIRE_CONNECTION_ID frame MUST indicate that the connection ID will not be used again and request that the peer replace it with a new connection ID using a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0004">The Type field MUST be encoded as a variable-length integer with value 0x19.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0005">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0006">RETIRE_CONNECTION_ID frames MUST contain the following field:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseRetireConnectionIdFrame_ParsesAndFormatsTheSequenceNumber()
    {
        QuicRetireConnectionIdFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(1)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0004">When the endpoint wishes to remove a connection ID from use, it MUST send a RETIRE_CONNECTION_ID frame to its peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0005">Sending a RETIRE_CONNECTION_ID frame MUST indicate that the connection ID will not be used again and request that the peer replace it with a new connection ID using a NEW_CONNECTION_ID frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0005">The Sequence Number field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0006">RETIRE_CONNECTION_ID frames MUST contain the following field:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseRetireConnectionIdFrame_RejectsTruncatedInput(int truncateBy)
    {
        QuicRetireConnectionIdFrame frame = new(0x01);
        byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded[..Math.Max(0, encoded.Length - truncateBy)], out _, out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0002">The Type field MUST be encoded as a variable-length integer with value 0x1a.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0003">The Data field MUST be 64 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0004">PATH_CHALLENGE frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0005">This 8-byte field MUST contain arbitrary data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0001">The Type field MUST be encoded as a variable-length integer with value 0x1b.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0002">The Data field MUST be 64 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParsePathFrames_ParsesAndFormatsTheEightBytePayload(bool isChallenge)
    {
        byte[] data = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        if (isChallenge)
        {
            QuicPathChallengeFrame frame = new(data);
            byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(encoded, out QuicPathChallengeFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(encoded.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathChallengeFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
        else
        {
            QuicPathResponseFrame frame = new(data);
            byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(frame);

            Assert.True(QuicFrameCodec.TryParsePathResponseFrame(encoded, out QuicPathResponseFrame parsed, out int bytesConsumed));
            Assert.True(data.AsSpan().SequenceEqual(parsed.Data));
            Assert.Equal(encoded.Length, bytesConsumed);

            Span<byte> destination = stackalloc byte[16];
            Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0002">The Type field MUST be encoded as a variable-length integer with value 0x1a.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0003">The Data field MUST be 64 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0004">PATH_CHALLENGE frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0005">This 8-byte field MUST contain arbitrary data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0001">The Type field MUST be encoded as a variable-length integer with value 0x1b.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0002">The Data field MUST be 64 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P17-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParsePathFrames_RejectsTruncatedInput(bool isChallenge)
    {
        byte[] invalidData = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        byte[] validData = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        if (isChallenge)
        {
            QuicPathChallengeFrame invalidFrame = new(invalidData);
            Assert.False(QuicFrameCodec.TryFormatPathChallengeFrame(invalidFrame, stackalloc byte[16], out _));

            byte[] encoded = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(validData));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(encoded[..^1], out _, out _));
        }
        else
        {
            QuicPathResponseFrame invalidFrame = new(invalidData);
            Assert.False(QuicFrameCodec.TryFormatPathResponseFrame(invalidFrame, stackalloc byte[16], out _));

            byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame(validData));
            Assert.False(QuicFrameCodec.TryParsePathResponseFrame(encoded[..^1], out _, out _));
        }
    }
}

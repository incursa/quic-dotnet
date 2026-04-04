namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0003">Permanent registrations in this registry MUST include the Frame Type Name field.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0004">The Frame Type Name field MUST be a short mnemonic for the frame type.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P4-0006">Specifications for permanent registrations MUST describe the format and assigned semantics of any fields in the frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P4-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P4-0004")]
[Requirement("REQ-QUIC-RFC9000-S22P4-0006")]
public sealed class QuicFrameCodecPart3Tests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0004">Data sent in CRYPTO frames MUST NOT be flow controlled in the same way as stream data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0004">The Type field MUST be encoded as a variable-length integer with value 0x06.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0005">The Offset field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0006">The Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0007">CRYPTO frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0008">The Offset field MUST be variable-length integer specifying the byte offset in the stream for the data in this CRYPTO frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0009">The Length field MUST be variable-length integer specifying the length of the Crypto Data field in this CRYPTO frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0012">Unlike STREAM frames, which MUST include a stream ID indicating to which stream the data belongs, the CRYPTO frame carries data for a single stream per encryption level.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0013">The stream MUST NOT have an explicit end, so CRYPTO frames do not have a FIN bit.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseCryptoFrame_ParsesAndFormatsAllFields()
    {
        byte[] cryptoData = [0xAA, 0xBB, 0xCC];
        QuicCryptoFrame frame = new(0x1122_3344, cryptoData);
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(frame);

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Offset, parsed.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0004">Data sent in CRYPTO frames MUST NOT be flow controlled in the same way as stream data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0010">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0011">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseCryptoFrame_AcceptsFramesThatExactlyReachTheStreamCeiling()
    {
        byte[] cryptoData = [0xAB];
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue - 1, cryptoData));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, parsed.Offset);
        Assert.True(cryptoData.AsSpan().SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4-0004">Data sent in CRYPTO frames MUST NOT be flow controlled in the same way as stream data.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0010">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0011">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(encoded, out _, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0010">The largest offset delivered on a stream -- the sum of the offset and data length -- MUST NOT exceed 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P6-0011">Receipt of a frame that exceeds this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue, [0xAA]);

        Assert.False(QuicFrameCodec.TryFormatCryptoFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0001">The Type field MUST be encoded as a variable-length integer with value 0x07.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0002">The Token Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0003">NEW_TOKEN frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0004">The Token Length field MUST be variable-length integer specifying the length of the token in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0005">An opaque blob that the client MAY use with a future Initial packet.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0006">The token MUST NOT be empty.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseNewTokenFrame_ParsesAndFormatsAllFields()
    {
        byte[] token = [0x10, 0x20, 0x30, 0x40];
        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0006">The token MUST NOT be empty.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P7-0007">A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(emptyFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewTokenFrame(emptyFrame, destination, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0002">The Type field MUST be encoded as a variable-length integer with value 0x10.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0003">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0004">MAX_DATA frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P9-0005">A variable-length integer indicating the maximum amount of data that MAY be sent on the entire connection, in units of bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0006">Subsequently, a receiver MUST send MAX_STREAM_DATA or MAX_DATA frames to advertise larger limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0009">A receiver MAY advertise a larger limit for a connection by sending a MAX_DATA frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P9-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseMaxDataFrame_ParsesAndFormatsTheMaximumDataField()
    {
        QuicMaxDataFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0009">QUIC MAY allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0005">The Type field MUST be encoded as a variable-length integer with value 0x11.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0007">The Maximum Stream Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0008">MAX_STREAM_DATA frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0009">The Stream ID field MUST be stream ID of the affected stream, encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P10-0010">A variable-length integer indicating the maximum amount of data that MAY be sent on the identified stream, in units of bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0006">Subsequently, a receiver MUST send MAX_STREAM_DATA or MAX_DATA frames to advertise larger limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0007">A receiver MAY advertise a larger limit for a stream by sending a MAX_STREAM_DATA frame with the corresponding stream ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0008">A MAX_STREAM_DATA frame MUST indicate the maximum absolute byte offset of a stream.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseMaxStreamDataFrame_ParsesAndFormatsTheFrameFields()
    {
        QuicMaxStreamDataFrame frame = new(0x06, 0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out QuicMaxStreamDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0001">The Type field MUST be encoded as a variable-length integer with value 0x12..0x13.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0002">The Maximum Streams field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0003">MAX_STREAMS frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0004">A count of the cumulative number of streams of the corresponding type that MAY be opened over the lifetime of the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0005">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0004">Subsequent limits MUST be advertised using MAX_STREAMS frames.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseMaxStreamsFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicMaxStreamsFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0008">QUIC MAY allow an arbitrary number of streams to operate concurrently.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0005">This value MUST NOT exceed 260, as it is not possible to encode stream IDs larger than 262-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P11-0006">Receipt of a frame that permits opening of a stream larger than this limit MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0007">If an oversized max_streams value is received in a frame, the connection MUST be closed immediately with FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicMaxStreamsFrame invalidFrame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatMaxStreamsFrame(invalidFrame, destination, out _));
    }
}

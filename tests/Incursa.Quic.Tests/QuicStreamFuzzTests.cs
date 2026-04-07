using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamFuzzTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0001">STREAM frames MUST encapsulate data sent by an application.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0003">This means that integers are encoded on 1, 2, 4, or 8 bytes and MAY encode 6-, 14-, 30-, or 62-bit values, respectively.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0004">Values MUST NOT need to be encoded on the minimum number of bytes necessary, with the sole exception of the Frame Type field; see Section 12.4.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S16-0003")]
    [Requirement("REQ-QUIC-RFC9000-S16-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
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
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9001-S3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
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
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_StreamParsing_RoundTripsRepresentativeFramesAndRejectsTruncation()
    {
        Random random = new(0x5150_2029);
        Span<byte> destination = stackalloc byte[128];

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

    private static ulong BuildRepresentableValue(Random random)
    {
        Span<byte> buffer = stackalloc byte[sizeof(ulong)];
        random.NextBytes(buffer);
        return BinaryPrimitives.ReadUInt64BigEndian(buffer) & QuicVariableLengthInteger.MaxValue;
    }
}

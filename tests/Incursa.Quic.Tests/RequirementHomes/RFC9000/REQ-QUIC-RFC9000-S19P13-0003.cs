namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0003")]
public sealed class REQ_QUIC_RFC9000_S19P13_0003
{
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_StreamDataBlockedFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzStreamDataBlockedFrame();
    }
}

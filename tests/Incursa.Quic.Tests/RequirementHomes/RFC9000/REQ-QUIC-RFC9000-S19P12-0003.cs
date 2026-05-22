namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
public sealed class REQ_QUIC_RFC9000_S19P12_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0026">QUIC MUST allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0003">The Type field MUST be encoded as a variable-length integer with value 0x14.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0004">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0005">DATA_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0006">The Maximum Data field MUST be variable-length integer indicating the connection-level limit at which blocking occurred.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0176">A sender SHOULD send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame to indicate to the receiver that it has data to write but is blocked by flow control limits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0026")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [Requirement("REQ-QUIC-RFC9000-0176")]
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0026">QUIC MUST allow an arbitrary amount of data to be sent on any stream, subject to flow control constraints and stream limits.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0004">The Maximum Data field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0005">DATA_BLOCKED frames MUST contain the following field:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P12-0006">The Maximum Data field MUST be variable-length integer indicating the connection-level limit at which blocking occurred.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0026")]
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
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseDataBlockedFrame_RejectsNonMinimalTypeEncoding()
    {
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrameWithEncodedType([0x40, 0x14]);

        QuicS19P12DataBlockedFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseDataBlockedFrame_ConsumesOnlyTheDataBlockedFrame()
    {
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrameWithTrailingFrame(maximumData: 0x40);

        Assert.True(QuicFrameCodec.TryParseDataBlockedFrame(
            encoded,
            out QuicDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(0x40UL, frame.MaximumData);
        Assert.Equal(encoded.Length - QuicFrameTestData.BuildPingFrame().Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_DataBlockedFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzDataBlockedFrame();
    }
}

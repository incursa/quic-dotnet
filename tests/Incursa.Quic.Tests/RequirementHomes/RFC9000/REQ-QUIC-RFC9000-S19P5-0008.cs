namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
public sealed class REQ_QUIC_RFC9000_S19P5_0008
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0007">An application protocol MAY abort reading a stream and request closure, possibly resulting in a STOP_SENDING frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0005">The Type field MUST be encoded as a variable-length integer with value 0x05.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0007">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0008">STOP_SENDING frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0009">The Stream ID field MUST be variable-length integer carrying the stream ID of the stream being ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0010">The Application Protocol Error Code field MUST be variable-length integer containing the application-specified reason the sender is ignoring the stream; see Section 20.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStopSendingFrame_ParsesAndFormatsAllFields()
    {
        QuicStopSendingFrame frame = new(0x44, 0x66);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0005">The Type field MUST be encoded as a variable-length integer with value 0x05.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0006">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0007">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0008">STOP_SENDING frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0009">The Stream ID field MUST be variable-length integer carrying the stream ID of the stream being ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P5-0010">The Application Protocol Error Code field MUST be variable-length integer containing the application-specified reason the sender is ignoring the stream; see Section 20.2.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStopSendingFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0x44, 0x66));

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseStopSendingFrame([0x04], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzStopSendingFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecFuzzSupport.FuzzStopSendingFrame();
    }
}

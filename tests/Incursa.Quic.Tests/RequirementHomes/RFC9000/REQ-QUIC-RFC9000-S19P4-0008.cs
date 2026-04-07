namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
public sealed class REQ_QUIC_RFC9000_S19P4_0008
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0005">An application protocol MAY reset a stream if the stream is not already in a terminal state, resulting in a RESET_STREAM frame.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P5-0003">The Final Size field of a RESET_STREAM frame MUST carry the final size value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0004">The Type field MUST be encoded as a variable-length integer with value 0x04.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0005">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0006">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0007">The Final Size field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0008">RESET_STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0009">The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream being terminated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0010">A variable-length integer containing the application protocol error code (see Section 20.2) that MUST indicate why the stream is being closed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0011">The Final Size field MUST be variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes; see Section 4.5.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseResetStreamFrame_ParsesAndFormatsAllFields()
    {
        QuicResetStreamFrame frame = new(0x1234, 0x55, 0x200);
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(frame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(encoded, out QuicResetStreamFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.ApplicationProtocolErrorCode, parsed.ApplicationProtocolErrorCode);
        Assert.Equal(frame.FinalSize, parsed.FinalSize);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2-0006">Streams in QUIC MAY be canceled.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0004">The Type field MUST be encoded as a variable-length integer with value 0x04.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0005">The Stream ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0006">The Application Protocol Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0007">The Final Size field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0008">RESET_STREAM frames MUST contain the following fields:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0009">The Stream ID field MUST be variable-length integer encoding of the stream ID of the stream being terminated.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0010">A variable-length integer containing the application protocol error code (see Section 20.2) that MUST indicate why the stream is being closed.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P4-0011">The Final Size field MUST be variable-length integer indicating the final size of the stream by the RESET_STREAM sender, in units of bytes; see Section 4.5.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseResetStreamFrame_RejectsTruncatedInputs()
    {
        byte[] encoded = QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0x1234, 0x55, 0x200));

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(encoded[..(encoded.Length - 1)], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame([0x05], out _, out _));
    }
}

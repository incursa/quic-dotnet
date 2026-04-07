namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0004")]
public sealed class REQ_QUIC_RFC9000_S19P16_0004
{
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_RetireConnectionIdFrame_RoundTripsRepresentativeShapesAndRejectsTruncation()
    {
        QuicFrameCodecPart4FuzzSupport.FuzzRetireConnectionIdFrame();
    }
}

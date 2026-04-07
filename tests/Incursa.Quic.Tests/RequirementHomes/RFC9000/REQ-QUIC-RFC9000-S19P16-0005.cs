namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
public sealed class REQ_QUIC_RFC9000_S19P16_0005
{
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
}

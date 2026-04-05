namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0013">Packets containing only frames with the N marking MUST NOT be ack-eliciting.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0013")]
public sealed class REQ_QUIC_RFC9000_S12P4_0013
{
    [Theory]
    [InlineData(0x01UL, true)]
    [InlineData(0x06UL, true)]
    [InlineData(0x10UL, true)]
    [InlineData(0x1AUL, true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IsAckElicitingFrameType_RecognizesAckElicitingFrameTypes(ulong frameType, bool expected)
    {
        Assert.Equal(expected, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }

    [Theory]
    [InlineData(0x00UL, false)]
    [InlineData(0x02UL, false)]
    [InlineData(0x03UL, false)]
    [InlineData(0x1CUL, false)]
    [InlineData(0x1DUL, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IsAckElicitingFrameType_RejectsNonAckElicitingFrameTypes(ulong frameType, bool expected)
    {
        Assert.Equal(expected, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }

    [Theory]
    [InlineData(0x1BUL, true)]
    [InlineData(0x1CUL, false)]
    [InlineData(0x1DUL, false)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IsAckElicitingFrameType_HandlesTheBoundaryBetweenAckElicitingAndNonAckElicitingTypes(ulong frameType, bool expected)
    {
        Assert.Equal(expected, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }
}

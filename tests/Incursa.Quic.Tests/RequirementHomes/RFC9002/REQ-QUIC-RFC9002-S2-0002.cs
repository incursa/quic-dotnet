namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S2-0002")]
public sealed class REQ_QUIC_RFC9002_S2_0002
{
    [Theory]
    [InlineData(0x00UL, false)]
    [InlineData(0x01UL, true)]
    [InlineData(0x02UL, false)]
    [InlineData(0x03UL, false)]
    [InlineData(0x06UL, true)]
    [InlineData(0x07UL, true)]
    [InlineData(0x10UL, true)]
    [InlineData(0x1AUL, true)]
    [InlineData(0x1EUL, true)]
    [InlineData(0x1CUL, false)]
    [InlineData(0x1DUL, false)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1P1-0001">An endpoint MAY send a PING or another ack-eliciting frame to test the connection for liveness if the peer could time out soon.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0002">Frames other than ACK, PADDING, and CONNECTION_CLOSE MUST be treated as ack-eliciting.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S3-0017">PADDING frames MUST NOT directly cause an acknowledgment to be sent.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S10P1P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S2-0002")]
    [Requirement("REQ-QUIC-RFC9002-S3-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsAckElicitingFrameType_ClassifiesKnownFrameTypes(ulong frameType, bool expectedAckEliciting)
    {
        Assert.Equal(expectedAckEliciting, QuicFrameCodec.IsAckElicitingFrameType(frameType));
    }
}

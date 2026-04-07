namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
public sealed class REQ_QUIC_RFC9000_S19P15_0019
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0019">The value in the Retire Prior To field MUST be less than or equal to the value in the Sequence Number field.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P15-0020">Receiving a value in the Retire Prior To field that is greater than that in the Sequence Number field MUST be treated as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P15-0019")]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseNewConnectionIdFrame_RejectsRetirePriorToGreaterThanSequenceNumber()
    {
        byte[] connectionId = [0x10, 0x11];
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];
        QuicNewConnectionIdFrame frame = new(0x03, 0x04, connectionId, statelessResetToken);
        byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

        Assert.False(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, stackalloc byte[64], out _));
    }
}

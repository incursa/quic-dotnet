namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0001">Errors that result in the connection being unusable, such as an obvious violation of protocol semantics or corruption of state that affects an entire connection, MUST be signaled using a CONNECTION_CLOSE frame (Section 19.19).</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0002">Application-specific protocol errors MUST be signaled using the CONNECTION_CLOSE frame with a frame type of 0x1d.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0003">Transport errors, including all those described in this document, MUST be carried in the CONNECTION_CLOSE frame with a frame type of 0x1c.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0003">The Type field MUST be encoded as a variable-length integer with value 0x1c..0x1d.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0004">The Error Code field MUST be encoded as a variable-length integer.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0005">The Frame Type field MUST be encoded as a variable-length integer when present.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0006">The Reason Phrase Length field MUST be encoded as a variable-length integer.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0007">CONNECTION_CLOSE frames MUST contain the following fields:</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0008">A variable-length integer that MUST indicate the reason for closing this connection.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0009">A CONNECTION_CLOSE frame of type 0x1c MUST use codes from the space defined in Section 20.1.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0010">A CONNECTION_CLOSE frame of type 0x1d MUST use codes defined by the application protocol; see Section 20.2.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0011">The Frame Type field MUST be variable-length integer encoding the type of frame that triggered the error.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0013">The application-specific variant of CONNECTION_CLOSE (type 0x1d) MUST NOT include this field.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0014">The Reason Phrase Length field MUST be variable-length integer specifying the length of the reason phrase in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0001")]
[Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
[Requirement("REQ-QUIC-RFC9000-S11P1-0003")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0003")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0004")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0005")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0006")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0007")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0008")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0009")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0010")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0011")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0013")]
[Requirement("REQ-QUIC-RFC9000-S19P19-0014")]
public sealed class REQ_QUIC_RFC9000_S19P19_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseConnectionCloseFrame_RejectsTruncatedOrUnknownTypes()
    {
        QuicConnectionCloseFrame transportFrame = new(0x1234, 0x02, [0x6F, 0x6B]);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(transportFrame);

        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(encoded[..^1], out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame([0x1B], out _, out _));
    }
}

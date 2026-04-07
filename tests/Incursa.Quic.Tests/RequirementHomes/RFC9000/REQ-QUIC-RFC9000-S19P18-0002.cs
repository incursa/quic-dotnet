namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
public sealed class REQ_QUIC_RFC9000_S19P18_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0001">The Type field MUST be encoded as a variable-length integer with value 0x1b.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P18-0002">The Data field MUST be 64 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P18-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParsePathResponseFrame_RejectsTruncatedInput()
    {
        byte[] invalidData = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        byte[] validData = [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7];

        QuicPathResponseFrame invalidFrame = new(invalidData);
        Assert.False(QuicFrameCodec.TryFormatPathResponseFrame(invalidFrame, stackalloc byte[16], out _));

        byte[] encoded = QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame(validData));
        Assert.False(QuicFrameCodec.TryParsePathResponseFrame(encoded[..^1], out _, out _));
    }
}

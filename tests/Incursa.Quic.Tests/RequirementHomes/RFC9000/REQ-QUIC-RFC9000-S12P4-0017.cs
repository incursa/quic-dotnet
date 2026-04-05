namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0017">An endpoint MUST treat receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0017")]
public sealed class REQ_QUIC_RFC9000_S12P4_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseKnownFrameTypes_AcceptsRecognizedFrameEncodings()
    {
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(QuicFrameTestData.BuildPaddingFrame(), out int paddingBytesConsumed));
        Assert.Equal(1, paddingBytesConsumed);

        Assert.True(QuicFrameCodec.TryParsePingFrame(QuicFrameTestData.BuildPingFrame(), out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseUnknownFrameTypes_RejectsAnUnrecognizedFrameType()
    {
        ReadOnlySpan<byte> unknownFrameType = [0x1F];

        Assert.False(QuicFrameCodec.TryParsePaddingFrame(unknownFrameType, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(unknownFrameType, out _));
        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(unknownFrameType, out _, out _));
        Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(unknownFrameType, out _, out _));
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0012">A value of 0 (equivalent to the mention of the PADDING frame) MUST be used when the frame type is unknown.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0012")]
public sealed class REQ_QUIC_RFC9000_S19P19_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatConnectionCloseFrame_UsesZeroWhenTheTriggeringFrameTypeIsUnknown()
    {
        QuicConnectionCloseFrame frame = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0,
            []);
        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.False(parsedFrame.IsApplicationError);
        Assert.Equal(0UL, parsedFrame.TriggeringFrameType);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsedFrame, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

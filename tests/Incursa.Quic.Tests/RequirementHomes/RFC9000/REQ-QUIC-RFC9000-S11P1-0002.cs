namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0002">Application-specific protocol errors MUST be signaled using the CONNECTION_CLOSE frame with a frame type of 0x1d.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0002")]
public sealed class REQ_QUIC_RFC9000_S11P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationErrorsUseConnectionCloseTypeOneD()
    {
        byte[] reasonPhrase = [0x61, 0x70, 0x70];
        QuicConnectionCloseFrame frame = new(0x1234, reasonPhrase);

        Assert.True(frame.IsApplicationError);
        Assert.Equal((byte)0x1D, frame.FrameType);
        Assert.False(frame.HasTriggeringFrameType);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
        Assert.True(parsed.IsApplicationError);
        Assert.Equal((byte)0x1D, parsed.FrameType);
        Assert.Equal(0x1234UL, parsed.ErrorCode);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

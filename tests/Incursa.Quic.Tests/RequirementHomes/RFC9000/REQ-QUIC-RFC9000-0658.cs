namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0658">An endpoint MAY use any applicable error code when it detects an error condition.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0658")]
public sealed class REQ_QUIC_RFC9000_0658
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InternalErrorCanStandInForAnApplicableTransportErrorCode()
    {
        byte[] reasonPhrase = [0x61, 0x70, 0x70];
        QuicConnectionCloseFrame frame = new(
            QuicTransportErrorCode.InternalError,
            triggeringFrameType: 0x02,
            reasonPhrase);

        Assert.False(frame.IsApplicationError);
        Assert.Equal((byte)0x1C, frame.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.InternalError, frame.ErrorCode);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(
            QuicFrameCodec.TryParseConnectionCloseFrame(
                encoded,
                out QuicConnectionCloseFrame parsed,
                out int bytesConsumed));
        Assert.False(parsed.IsApplicationError);
        Assert.Equal((byte)0x1C, parsed.FrameType);
        Assert.Equal((ulong)QuicTransportErrorCode.InternalError, parsed.ErrorCode);
        Assert.True(parsed.HasTriggeringFrameType);
        Assert.Equal(0x02UL, parsed.TriggeringFrameType);
        Assert.True(reasonPhrase.AsSpan().SequenceEqual(parsed.ReasonPhrase));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

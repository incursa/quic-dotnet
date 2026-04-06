namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0018">All frames MUST be idempotent in this version of QUIC.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P4-0018")]
public sealed class REQ_QUIC_RFC9000_S12P4_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P4-0018">All frames MUST be idempotent in this version of QUIC.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S12P4-0018")]
    public void TryParseAndTryFormatSelectedFrames_AreDeterministicAcrossRepeatedCalls()
    {
        byte[] paddingFrame = QuicFrameTestData.BuildPaddingFrame();
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(paddingFrame, out int firstPaddingConsumed));
        Assert.True(QuicFrameCodec.TryParsePaddingFrame(paddingFrame, out int secondPaddingConsumed));
        Assert.Equal(firstPaddingConsumed, secondPaddingConsumed);
        Assert.Equal(paddingFrame.Length, firstPaddingConsumed);

        QuicConnectionCloseFrame connectionCloseFrame = new(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reasonPhrase: [0x6F, 0x6B]);
        byte[] encodedConnectionClose = QuicFrameTestData.BuildConnectionCloseFrame(connectionCloseFrame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encodedConnectionClose, out QuicConnectionCloseFrame firstParsedConnectionClose, out int firstConnectionCloseConsumed));
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encodedConnectionClose, out QuicConnectionCloseFrame secondParsedConnectionClose, out int secondConnectionCloseConsumed));
        Assert.Equal(firstConnectionCloseConsumed, secondConnectionCloseConsumed);
        Assert.Equal(firstParsedConnectionClose.FrameType, secondParsedConnectionClose.FrameType);
        Assert.Equal(firstParsedConnectionClose.ErrorCode, secondParsedConnectionClose.ErrorCode);
        Assert.True(firstParsedConnectionClose.ReasonPhrase.SequenceEqual(secondParsedConnectionClose.ReasonPhrase));

        Span<byte> firstDestination = stackalloc byte[16];
        Span<byte> secondDestination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(firstDestination, out int firstPaddingWritten));
        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(secondDestination, out int secondPaddingWritten));
        Assert.Equal(firstPaddingWritten, secondPaddingWritten);
        Assert.True(firstDestination[..firstPaddingWritten].SequenceEqual(secondDestination[..secondPaddingWritten]));

        Span<byte> firstConnectionCloseDestination = stackalloc byte[16];
        Span<byte> secondConnectionCloseDestination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(firstParsedConnectionClose, firstConnectionCloseDestination, out int firstConnectionCloseWritten));
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(secondParsedConnectionClose, secondConnectionCloseDestination, out int secondConnectionCloseWritten));
        Assert.Equal(firstConnectionCloseWritten, secondConnectionCloseWritten);
        Assert.True(firstConnectionCloseDestination[..firstConnectionCloseWritten].SequenceEqual(secondConnectionCloseDestination[..secondConnectionCloseWritten]));
        Assert.True(encodedConnectionClose.AsSpan().SequenceEqual(firstConnectionCloseDestination[..firstConnectionCloseWritten]));
    }
}

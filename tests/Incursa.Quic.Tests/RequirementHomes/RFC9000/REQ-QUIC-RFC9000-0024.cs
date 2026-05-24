namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0024")]
public sealed class REQ_QUIC_RFC9000_0024
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamCancellationFrames_RoundTripResetAndStopSendingPaths()
    {
        QuicResetStreamFrame resetFrame = new(
            streamId: 0x44,
            applicationProtocolErrorCode: 0x66,
            finalSize: 0x88);
        byte[] resetEncoded = QuicFrameTestData.BuildResetStreamFrame(resetFrame);

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
            resetEncoded,
            out QuicResetStreamFrame parsedResetFrame,
            out int resetBytesConsumed));
        Assert.Equal(resetEncoded.Length, resetBytesConsumed);
        Assert.Equal(resetFrame.StreamId, parsedResetFrame.StreamId);
        Assert.Equal(resetFrame.ApplicationProtocolErrorCode, parsedResetFrame.ApplicationProtocolErrorCode);
        Assert.Equal(resetFrame.FinalSize, parsedResetFrame.FinalSize);

        QuicStopSendingFrame stopSendingFrame = new(
            streamId: 0x44,
            applicationProtocolErrorCode: 0x77);
        byte[] stopSendingEncoded = QuicFrameTestData.BuildStopSendingFrame(stopSendingFrame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(
            stopSendingEncoded,
            out QuicStopSendingFrame parsedStopSendingFrame,
            out int stopSendingBytesConsumed));
        Assert.Equal(stopSendingEncoded.Length, stopSendingBytesConsumed);
        Assert.Equal(stopSendingFrame.StreamId, parsedStopSendingFrame.StreamId);
        Assert.Equal(stopSendingFrame.ApplicationProtocolErrorCode, parsedStopSendingFrame.ApplicationProtocolErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0024")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StreamCancellationFrames_RejectTruncatedResetAndStopSendingPaths()
    {
        QuicResetStreamFrame resetFrame = new(
            streamId: 0x44,
            applicationProtocolErrorCode: 0x66,
            finalSize: 0x88);
        byte[] resetEncoded = QuicFrameTestData.BuildResetStreamFrame(resetFrame);

        Assert.False(QuicFrameCodec.TryParseResetStreamFrame(
            resetEncoded.AsSpan(0, resetEncoded.Length - 1),
            out _,
            out _));

        QuicStopSendingFrame stopSendingFrame = new(
            streamId: 0x44,
            applicationProtocolErrorCode: 0x77);
        byte[] stopSendingEncoded = QuicFrameTestData.BuildStopSendingFrame(stopSendingFrame);

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(
            stopSendingEncoded.AsSpan(0, stopSendingEncoded.Length - 1),
            out _,
            out _));
    }
}

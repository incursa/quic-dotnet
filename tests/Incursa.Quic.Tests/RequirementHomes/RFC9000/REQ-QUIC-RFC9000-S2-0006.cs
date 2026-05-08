namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S2-0006")]
public sealed class REQ_QUIC_RFC9000_S2_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0006")]
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
}

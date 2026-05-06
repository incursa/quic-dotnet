namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0008")]
public sealed class REQ_QUIC_RFC9000_S18P2_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerTransportParameterCommitInstallsInitialMaximumDataAsConnectionSendLimit()
    {
        using QuicConnectionRuntime runtime =
            QuicS18P2InitialMaxDataTestSupport.CreateFinishedClientRuntime(
                initialConnectionSendLimit: 0,
                peerInitialMaxData: 96);

        Assert.Equal(96UL, runtime.StreamRegistry.Bookkeeping.ConnectionSendLimit);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 96,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PeerTransportParameterCommitReplacesAnySpeculativeConnectionSendLimit()
    {
        using QuicConnectionRuntime runtime =
            QuicS18P2InitialMaxDataTestSupport.CreateFinishedClientRuntime(
                initialConnectionSendLimit: 256,
                peerInitialMaxData: 64);

        Assert.Equal(64UL, runtime.StreamRegistry.Bookkeeping.ConnectionSendLimit);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(runtime.StreamRegistry.Bookkeeping.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 65,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(64UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
    }

    private static class QuicS18P2InitialMaxDataTestSupport
    {
        internal static QuicConnectionRuntime CreateFinishedClientRuntime(
            ulong initialConnectionSendLimit,
            ulong peerInitialMaxData)
        {
            return QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
                connectionSendLimit: initialConnectionSendLimit,
                localBidirectionalSendLimit: 128,
                peerInitialMaxData: peerInitialMaxData);
        }
    }
}

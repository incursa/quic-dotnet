namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0025">These frames MUST always include the limit that is causing blocking at the time that they are transmitted.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0025")]
public sealed class REQ_QUIC_RFC9000_S13P3_0025
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_CarriesTheCurrentBlockingLimitInEveryBlockedFrame()
    {
        QuicConnectionStreamState connectionBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 1,
            localBidirectionalSendLimit: 8);

        Assert.True(connectionBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId connectionBlockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(connectionBlockedState.TryReserveSendCapacity(
            connectionBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);

        QuicConnectionStreamState streamBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 1);

        Assert.True(streamBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamBlockedStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(streamBlockedState.TryReserveSendCapacity(
            streamBlockedStreamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(streamBlockedStreamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(1UL, streamDataBlockedFrame.MaximumStreamData);

        QuicConnectionStreamState streamsBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 1,
            peerUnidirectionalStreamLimit: 1);

        Assert.True(streamsBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(streamsBlockedState.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame bidirectionalStreamsBlockedFrame));
        Assert.True(bidirectionalStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, bidirectionalStreamsBlockedFrame.MaximumStreams);

        Assert.True(streamsBlockedState.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.False(streamsBlockedState.TryOpenLocalStream(
            bidirectional: false,
            out _,
            out QuicStreamsBlockedFrame unidirectionalStreamsBlockedFrame));
        Assert.False(unidirectionalStreamsBlockedFrame.IsBidirectional);
        Assert.Equal(1UL, unidirectionalStreamsBlockedFrame.MaximumStreams);
    }
}

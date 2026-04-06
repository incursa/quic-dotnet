namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStateFlowControlTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReadStreamData_AccountsConnectionCreditAndAdvertisesMoreCreditPerStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8,
            localBidirectionalReceiveLimit: 8,
            localUnidirectionalSendLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 5, [0x33, 0x44, 0x55], offset: 0),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
        Assert.Equal(16UL, state.ConnectionReceiveLimit);

        Span<byte> firstDestination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            firstDestination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan().SequenceEqual(firstDestination));
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(10UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, firstSnapshot.ReceiveState);
        Assert.Equal(10UL, firstSnapshot.ReceiveLimit);
        Assert.Equal(2UL, firstSnapshot.ReadOffset);

        Span<byte> secondDestination = stackalloc byte[3];
        Assert.True(state.TryReadStreamData(
            5,
            secondDestination,
            out bytesWritten,
            out completed,
            out maxDataFrame,
            out maxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(3, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x33, 0x44, 0x55 }.AsSpan().SequenceEqual(secondDestination));
        Assert.Equal(21UL, maxDataFrame.MaximumData);
        Assert.Equal(5UL, maxStreamDataFrame.StreamId);
        Assert.Equal(11UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, secondSnapshot.ReceiveState);
        Assert.Equal(11UL, secondSnapshot.ReceiveLimit);
        Assert.Equal(3UL, secondSnapshot.ReadOffset);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
        Assert.Equal(21UL, state.ConnectionReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryApplyMaxFrames_IgnoresNonIncreasingLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            peerBidirectionalSendLimit: 4,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.Equal(12UL, state.ConnectionSendLimit);
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(11)));
        Assert.Equal(12UL, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
        Assert.Equal(10UL, streamSnapshot.SendLimit);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 9), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out streamSnapshot));
        Assert.Equal(10UL, streamSnapshot.SendLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 3)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 2)));
        Assert.Equal(3UL, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 4)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, 3)));
        Assert.Equal(4UL, state.PeerUnidirectionalStreamLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReceiveStreamFrame_RejectsFinalSizeRegressionAfterHigherOffsetData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        ulong streamId = 1;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId, [0xAA, 0xBB], offset: 4),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0xCC], offset: 0),
            out QuicStreamFrame regressionFrame));
        Assert.False(state.TryReceiveStreamFrame(regressionFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReceiveResetStreamFrame_RejectsFinalSizeRegressionAfterHigherOffsetData()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        ulong streamId = 1;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x08, streamId, [0xAA, 0xBB], offset: 4),
            out QuicStreamFrame leadingFrame));
        Assert.True(state.TryReceiveStreamFrame(leadingFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: streamId, applicationProtocolErrorCode: 0x99, finalSize: 1),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReserveSendCapacity_RejectsFinalSizeRegressionAfterHigherOffsetReservation()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 32,
            localUnidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 4,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesSent);
        Assert.Equal(2UL, state.ConnectionUniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.UniqueBytesSent);
        Assert.Equal(2UL, state.ConnectionUniqueBytesSent);
    }
}

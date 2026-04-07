namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStateTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0014")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryOpenLocalStream_TracksPeerLimitsAndSendCapacity()
    {
        QuicConnectionStreamState state = CreateState(peerBidirectionalStreamLimit: 1, connectionSendLimit: 3, localBidirectionalSendLimit: 2);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(0UL, streamId.Value);
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, readySnapshot.ReceiveState);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.Equal(2UL, sendSnapshot.UniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 2,
            length: 1,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(2UL, streamDataBlockedFrame.MaximumStreamData);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(5)));
        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 5), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(5)));
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 5), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 2,
            length: 1,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(3UL, dataSentSnapshot.FinalSize);

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out _, out blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0019")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveStreamFrame_BuffersPeerDataAndReadsInOrder()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);
        ulong streamId = 5;

        byte[] tail = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x33, 0x44], offset: 2);
        byte[] head = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x11, 0x22], offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(tail, out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(head, out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, sizeKnownSnapshot.ReceiveState);
        Assert.True(sizeKnownSnapshot.HasFinalSize);
        Assert.Equal(4UL, sizeKnownSnapshot.FinalSize);
        Assert.Equal(2UL, sizeKnownSnapshot.UniqueBytesReceived);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
        Assert.Equal(4UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            streamId,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(36UL, maxDataFrame.MaximumData);
        Assert.Equal(streamId, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(streamId, out snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);

        byte[] extraPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x55], offset: 4);
        Assert.True(QuicStreamParser.TryParseStreamFrame(extraPacket, out QuicStreamFrame extraFrame));
        Assert.False(state.TryReceiveStreamFrame(extraFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReceiveStreamFrame_RejectsStreamLimitFlowControlAndFinalSizeViolations()
    {
        QuicConnectionStreamState limitedCredit = CreateState(peerBidirectionalReceiveLimit: 3, connectionReceiveLimit: 3);
        byte[] initialPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x10, 0x11], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(initialPacket, out QuicStreamFrame initialFrame));
        Assert.True(limitedCredit.TryReceiveStreamFrame(initialFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] tooLargePacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x12, 0x13], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(tooLargePacket, out QuicStreamFrame tooLargeFrame));
        Assert.False(limitedCredit.TryReceiveStreamFrame(tooLargeFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

        QuicConnectionStreamState finalSizeState = CreateState(peerBidirectionalReceiveLimit: 8, connectionReceiveLimit: 8);
        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x01, 0x02], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));
        Assert.True(finalSizeState.TryReceiveStreamFrame(finFrame, out errorCode));
        Assert.Equal(default, errorCode);

        byte[] changedFinalPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, streamData: [0x03], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(changedFinalPacket, out QuicStreamFrame changedFinalFrame));
        Assert.False(finalSizeState.TryReceiveStreamFrame(changedFinalFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReadStreamData_DoesNotAdvertiseCreditWhenTheReceiveLimitsAreAlreadyAtTheMaximum()
    {
        QuicConnectionStreamState state = CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: QuicVariableLengthInteger.MaxValue);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x11]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveResetStreamFrame_DoesNotAdvertiseConnectionCreditWhenTheLimitCannotIncrease()
    {
        QuicConnectionStreamState state = CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: 8);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, streamData: [0x21, 0x22], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x99, finalSize: 5),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveStreamFrame_AdvancesReceiveStateThroughOrderedFragmentArrival()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);
        ulong streamId = 5;

        byte[] tailPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x33, 0x44], offset: 2);
        byte[] headPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x11, 0x22], offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(tailPacket, out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(headPacket, out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, sizeKnownSnapshot.ReceiveState);
        Assert.True(sizeKnownSnapshot.HasFinalSize);
        Assert.Equal(4UL, sizeKnownSnapshot.FinalSize);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot dataRecvdSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, dataRecvdSnapshot.ReceiveState);
        Assert.Equal(4UL, dataRecvdSnapshot.UniqueBytesReceived);
        Assert.Equal(4UL, dataRecvdSnapshot.AccountedBytesReceived);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            streamId,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot dataReadSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, dataReadSnapshot.ReceiveState);
        Assert.Equal(4UL, dataReadSnapshot.ReadOffset);
    }

    private static QuicConnectionStreamState CreateState(
        ulong connectionReceiveLimit = 64,
        ulong connectionSendLimit = 64,
        ulong incomingBidirectionalStreamLimit = 4,
        ulong incomingUnidirectionalStreamLimit = 4,
        ulong peerBidirectionalStreamLimit = 4,
        ulong peerUnidirectionalStreamLimit = 4,
        ulong localBidirectionalReceiveLimit = 8,
        ulong peerBidirectionalReceiveLimit = 8,
        ulong peerUnidirectionalReceiveLimit = 8,
        ulong localBidirectionalSendLimit = 8,
        ulong localUnidirectionalSendLimit = 8,
        ulong peerBidirectionalSendLimit = 8)
    {
        return new QuicConnectionStreamState(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: connectionReceiveLimit,
                InitialConnectionSendLimit: connectionSendLimit,
                InitialIncomingBidirectionalStreamLimit: incomingBidirectionalStreamLimit,
                InitialIncomingUnidirectionalStreamLimit: incomingUnidirectionalStreamLimit,
                InitialPeerBidirectionalStreamLimit: peerBidirectionalStreamLimit,
                InitialPeerUnidirectionalStreamLimit: peerUnidirectionalStreamLimit,
                InitialLocalBidirectionalReceiveLimit: localBidirectionalReceiveLimit,
                InitialPeerBidirectionalReceiveLimit: peerBidirectionalReceiveLimit,
                InitialPeerUnidirectionalReceiveLimit: peerUnidirectionalReceiveLimit,
                InitialLocalBidirectionalSendLimit: localBidirectionalSendLimit,
                InitialLocalUnidirectionalSendLimit: localUnidirectionalSendLimit,
                InitialPeerBidirectionalSendLimit: peerBidirectionalSendLimit));
    }
}

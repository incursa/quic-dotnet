namespace Incursa.Quic.Tests.RequirementHomes;

public sealed class QuicConnectionStreamStateTransitionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReserveSendCapacity_TransitionsThroughReadyAndSendStateBeforeFinalDataIsSent()
    {
        QuicConnectionStreamState state = CreateState(connectionSendLimit: 16, localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
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
        Assert.Equal(3UL, dataSentSnapshot.FinalSize);
        Assert.True(dataSentSnapshot.HasFinalSize);
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryReserveSendCapacity_RejectsWritesPastFinalSizeAfterDataSent()
    {
        QuicConnectionStreamState state = CreateState(connectionSendLimit: 16, localBidirectionalSendLimit: 8);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 2,
            fin: true,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: dataSentSnapshot.FinalSize,
            length: 1,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot blockedSnapshot));
        Assert.Equal(QuicStreamSendState.DataSent, blockedSnapshot.SendState);
        Assert.Equal(dataSentSnapshot.FinalSize, blockedSnapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReceiveResetStreamFrame_TransitionsReceiveStateFromResetRecvdToResetRead()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 16, peerBidirectionalReceiveLimit: 4);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 1, streamData: [0xAA, 0xBB], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x0A, finalSize: 2),
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);

        Assert.True(state.TryAcknowledgeReset(1));

        Assert.True(state.TryGetStreamSnapshot(1, out var resetReadSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRead, resetReadSnapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryAcknowledgeReset_RejectsRedundantAcknowledgementsAfterResetIsRead()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 16, peerBidirectionalReceiveLimit: 4);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 1, streamData: [0x11, 0x22], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out _));

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x0B, finalSize: 2),
            out _,
            out _));

        Assert.True(state.TryAcknowledgeReset(1));
        Assert.False(state.TryAcknowledgeReset(1));
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

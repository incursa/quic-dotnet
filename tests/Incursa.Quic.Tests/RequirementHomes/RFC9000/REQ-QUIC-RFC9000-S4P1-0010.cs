namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
public sealed class REQ_QUIC_RFC9000_S4P1_0010
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0010">A receiver MUST maintain a cumulative sum of bytes received on all streams to check for violations of the advertised connection or stream data limits.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_TracksConnectionReceivedBytesAcrossStreams()
    {
        QuicConnectionStreamState state = CreateState(connectionReceiveLimit: 4, peerBidirectionalReceiveLimit: 8);

        byte[] firstPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0xAA, 0xBB], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(firstPacket, out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode firstErrorCode));
        Assert.Equal(default, firstErrorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        byte[] secondPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0xCC, 0xDD], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(secondPacket, out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out QuicTransportErrorCode secondErrorCode));
        Assert.Equal(default, secondErrorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        byte[] excessPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0xEE], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(excessPacket, out QuicStreamFrame excessFrame));
        Assert.False(state.TryReceiveStreamFrame(excessFrame, out QuicTransportErrorCode excessErrorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, excessErrorCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_TracksConnectionCreditAndAdvertisesMoreCreditPerStream()
    {
        QuicConnectionStreamState state = CreateState(
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
        return new QuicConnectionStreamState(new QuicConnectionStreamStateOptions(
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

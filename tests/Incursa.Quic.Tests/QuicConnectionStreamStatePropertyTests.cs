using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStatePropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicConnectionStreamStatePropertyGenerators) })]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0014")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S4P5-0002")]
    [Trait("Category", "Property")]
    public void TryReceiveStreamFrame_ReassemblesTwoSegmentsRegardlessOfArrivalOrder(OrderedReceiveScenario scenario)
    {
        ulong streamId = 1;
        QuicConnectionStreamState state = new(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: 128,
                InitialConnectionSendLimit: 128,
                InitialIncomingBidirectionalStreamLimit: 4,
                InitialIncomingUnidirectionalStreamLimit: 4,
                InitialPeerBidirectionalStreamLimit: 4,
                InitialPeerUnidirectionalStreamLimit: 4,
                InitialLocalBidirectionalReceiveLimit: 32,
                InitialPeerBidirectionalReceiveLimit: 32,
                InitialPeerUnidirectionalReceiveLimit: 32,
                InitialLocalBidirectionalSendLimit: 32,
                InitialLocalUnidirectionalSendLimit: 32,
                InitialPeerBidirectionalSendLimit: 32));

        byte[] firstPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, scenario.Tail, (ulong)scenario.Head.Length);
        byte[] secondPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, scenario.Head, 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(firstPacket, out QuicStreamFrame firstFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(secondPacket, out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        byte[] expected = [.. scenario.Head, .. scenario.Tail];
        byte[] destination = new byte[expected.Length];
        Assert.True(state.TryReadStreamData(
            streamId,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(completed);
        Assert.True(expected.AsSpan().SequenceEqual(destination));
    }

    [Property(Arbitrary = new[] { typeof(QuicConnectionStreamStatePropertyGenerators) })]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0012")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0017")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0020")]
    [Trait("Category", "Property")]
    public void TryReserveSendCapacity_TracksOutOfOrderSendReservations(OrderedReceiveScenario scenario)
    {
        QuicConnectionStreamState state = new(
            new QuicConnectionStreamStateOptions(
                IsServer: false,
                InitialConnectionReceiveLimit: 128,
                InitialConnectionSendLimit: 128,
                InitialIncomingBidirectionalStreamLimit: 4,
                InitialIncomingUnidirectionalStreamLimit: 4,
                InitialPeerBidirectionalStreamLimit: 4,
                InitialPeerUnidirectionalStreamLimit: 4,
                InitialLocalBidirectionalReceiveLimit: 32,
                InitialPeerBidirectionalReceiveLimit: 32,
                InitialPeerUnidirectionalReceiveLimit: 32,
                InitialLocalBidirectionalSendLimit: 32,
                InitialLocalUnidirectionalSendLimit: 32,
                InitialPeerBidirectionalSendLimit: 32));

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        byte[] expected = [.. scenario.Head, .. scenario.Tail];

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: (ulong)scenario.Head.Length,
            length: scenario.Tail.Length,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: scenario.Head.Length,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: (ulong)expected.Length,
            length: 0,
            fin: true,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.DataSent, snapshot.SendState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal((ulong)expected.Length, snapshot.FinalSize);
        Assert.Equal((ulong)expected.Length, snapshot.UniqueBytesSent);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: (ulong)expected.Length + 1,
            length: 1,
            fin: false,
            out dataBlockedFrame,
            out streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
    }
}

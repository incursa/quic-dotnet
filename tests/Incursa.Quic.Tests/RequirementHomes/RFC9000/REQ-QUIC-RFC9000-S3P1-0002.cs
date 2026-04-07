using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0002")]
public sealed class REQ_QUIC_RFC9000_S3P1_0002
{
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P1-0002">An implementation MAY buffer stream data in the Ready state in preparation for sending.</workbench-requirement>
    /// </workbench-requirements>
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_BuffersDataInReadyState()
    {
        QuicConnectionStreamState state = CreateState(localBidirectionalSendLimit: 8, connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

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

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
    }

    [Property(Arbitrary = new[] { typeof(QuicConnectionStreamStatePropertyGenerators) })]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0002")]
    [Trait("Category", "Property")]
    public void TryReserveSendCapacity_BuffersOutOfOrderFragmentsInReadyState(OrderedReceiveScenario scenario)
    {
        QuicConnectionStreamState state = CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            localBidirectionalReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalSendLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 32);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out _));
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);

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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryReserveSendCapacity_ReachesDataSentOnlyAfterOrderedFragments()
    {
        Random random = new(0x5150_2031);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            int payloadLength = random.Next(1, 33);
            byte[] payload = new byte[payloadLength];
            random.NextBytes(payload);

            List<(ulong Offset, byte[] Data, bool Fin)> fragments = [];
            int cursor = 0;
            while (cursor < payloadLength)
            {
                int remaining = payloadLength - cursor;
                int fragmentLength = random.Next(1, remaining + 1);
                fragments.Add(((ulong)cursor, payload[cursor..(cursor + fragmentLength)], cursor + fragmentLength == payloadLength));
                cursor += fragmentLength;
            }

            QuicConnectionStreamState state = CreateState(
                connectionReceiveLimit: 512,
                connectionSendLimit: 512,
                incomingBidirectionalStreamLimit: 4,
                incomingUnidirectionalStreamLimit: 4,
                peerBidirectionalStreamLimit: 4,
                peerUnidirectionalStreamLimit: 4,
                localBidirectionalReceiveLimit: 128,
                peerBidirectionalReceiveLimit: 128,
                peerUnidirectionalReceiveLimit: 128,
                localBidirectionalSendLimit: 128,
                localUnidirectionalSendLimit: 128,
                peerBidirectionalSendLimit: 128);

            Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            foreach ((ulong offset, byte[] data, bool fin) in fragments)
            {
                Assert.True(state.TryReserveSendCapacity(
                    streamId.Value,
                    offset,
                    data.Length,
                    fin,
                    out QuicDataBlockedFrame dataBlockedFrame,
                    out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                    out QuicTransportErrorCode errorCode));
                Assert.Equal(default, dataBlockedFrame);
                Assert.Equal(default, streamDataBlockedFrame);
                Assert.Equal(default, errorCode);

                Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
                if (fin)
                {
                    Assert.Equal(QuicStreamSendState.DataSent, snapshot.SendState);
                    Assert.True(snapshot.HasFinalSize);
                    Assert.Equal((ulong)payloadLength, snapshot.FinalSize);
                }
                else
                {
                    Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
                    Assert.False(snapshot.HasFinalSize);
                }
            }

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot completedSnapshot));
            Assert.Equal((ulong)payloadLength, completedSnapshot.UniqueBytesSent);
            Assert.Equal(QuicStreamSendState.DataSent, completedSnapshot.SendState);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: (ulong)payloadLength,
                length: 1,
                fin: false,
                out QuicDataBlockedFrame finalDataBlockedFrame,
                out QuicStreamDataBlockedFrame finalStreamDataBlockedFrame,
                out QuicTransportErrorCode finalErrorCode));
            Assert.Equal(default, finalDataBlockedFrame);
            Assert.Equal(default, finalStreamDataBlockedFrame);
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, finalErrorCode);
        }
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

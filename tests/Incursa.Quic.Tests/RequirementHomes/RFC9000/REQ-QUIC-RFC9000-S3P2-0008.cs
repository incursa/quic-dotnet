using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0008">An endpoint MUST interpret MAX_STREAM_DATA on an unopened stream as the peer opening that stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0008")]
public sealed class REQ_QUIC_RFC9000_S3P2_0008
{
    [Property]
    [Trait("Category", "Property")]
    public void TryApplyMaxStreamDataFrame_OpensAnUnopenedPeerBidirectionalStream(byte streamIndex)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalReceiveLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 8);

        ulong streamId = ((ulong)streamIndex << 2) | 1UL;

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(16UL, snapshot.SendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TryApplyMaxStreamDataFrame_OpensUnopenedPeerBidirectionalStreamAndIgnoresDuplicates()
    {
        Random random = new(0x5150_2032);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 256,
                connectionSendLimit: 256,
                incomingBidirectionalStreamLimit: 64,
                incomingUnidirectionalStreamLimit: 64,
                peerBidirectionalStreamLimit: 64,
                peerUnidirectionalStreamLimit: 64,
                localBidirectionalReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64,
                peerUnidirectionalReceiveLimit: 64,
                localBidirectionalSendLimit: 64,
                localUnidirectionalSendLimit: 64,
                peerBidirectionalSendLimit: 8);

            byte streamIndex = (byte)random.Next(0, 32);
            ulong streamId = ((ulong)streamIndex << 2) | 1UL;
            ulong maxData = (ulong)random.Next(9, 64);

            Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, maxData), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
            Assert.Equal(maxData, snapshot.SendLimit);

            Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, maxData), out QuicTransportErrorCode repeatedErrorCode));
            Assert.Equal(default, repeatedErrorCode);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_OpensUnopenedPeerBidirectionalStreamAndCreatesLowerNumberedPeers()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(5, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot peerStreamSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, peerStreamSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, peerStreamSnapshot.ReceiveState);
        Assert.Equal(16UL, peerStreamSnapshot.SendLimit);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot lowerStreamSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, lowerStreamSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, lowerStreamSnapshot.ReceiveState);
        Assert.Equal(8UL, lowerStreamSnapshot.SendLimit);

        Assert.False(state.TryGetStreamSnapshot(9, out _));
    }
}

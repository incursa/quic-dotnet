using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamStateFlowControlPropertyTests
{
    [Property]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0013")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0011")]
    [Trait("Category", "Property")]
    public void TryApplyMaxFrames_MaintainMonotonicLimits(byte step)
    {
        ulong connectionCredit = 16UL + 1UL + (ulong)(step % 16);
        ulong streamCredit = 8UL + 1UL + (ulong)((step / 2) % 16);
        ulong bidirectionalStreamLimit = 3UL + (ulong)(step % 5);
        ulong unidirectionalStreamLimit = 4UL + (ulong)(step % 5);

        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            peerBidirectionalSendLimit: 8,
            peerBidirectionalStreamLimit: 2,
            peerUnidirectionalStreamLimit: 2);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(connectionCredit)));
        Assert.Equal(connectionCredit, state.ConnectionSendLimit);
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(connectionCredit)));
        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(connectionCredit - 1)));
        Assert.Equal(connectionCredit, state.ConnectionSendLimit);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, streamCredit), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot streamSnapshot));
        Assert.Equal(streamCredit, streamSnapshot.SendLimit);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, streamCredit), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, streamCredit - 1), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(1, out streamSnapshot));
        Assert.Equal(streamCredit, streamSnapshot.SendLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, bidirectionalStreamLimit)));
        Assert.Equal(bidirectionalStreamLimit, state.PeerBidirectionalStreamLimit);
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, bidirectionalStreamLimit)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, bidirectionalStreamLimit - 1)));
        Assert.Equal(bidirectionalStreamLimit, state.PeerBidirectionalStreamLimit);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, unidirectionalStreamLimit)));
        Assert.Equal(unidirectionalStreamLimit, state.PeerUnidirectionalStreamLimit);
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, unidirectionalStreamLimit)));
        Assert.False(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, unidirectionalStreamLimit - 1)));
        Assert.Equal(unidirectionalStreamLimit, state.PeerUnidirectionalStreamLimit);
    }
}

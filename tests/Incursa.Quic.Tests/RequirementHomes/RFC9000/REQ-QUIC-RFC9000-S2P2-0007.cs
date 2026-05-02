namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P2-0007">The data at a given offset MUST NOT change if it is sent multiple times.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P2-0007")]
public sealed class REQ_QUIC_RFC9000_S2P2_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_PreservesAnIdenticalRetransmissionAtTheSameOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(20UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_IgnoresAConflictingRetransmissionAtTheSameOffset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0xAA, 0xBB, 0xCC, 0xDD], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(20UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AppendsOnlyTheNewTailBytesOfAnOverlappingRetransmission()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x33, 0x44, 0x55, 0x66], offset: 2), out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(6UL, state.ConnectionAccountedBytesReceived);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(6, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(22UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(14UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] data, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset: offset),
            out QuicStreamFrame frame));
        return frame;
    }
}

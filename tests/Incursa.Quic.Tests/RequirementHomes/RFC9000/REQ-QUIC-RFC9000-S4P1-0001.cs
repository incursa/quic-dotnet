namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0001">QUIC MUST employ a limit-based flow control scheme in which a receiver advertises the total bytes it is prepared to receive on a given stream or for the entire connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0001")]
public sealed class REQ_QUIC_RFC9000_S4P1_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_AdvertisesTotalBytesPreparedToReceive()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        ulong streamId = 5;
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x33, 0x44], offset: 2),
            out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x11, 0x22], offset: 0),
            out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

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

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
    }
}

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0014">An endpoint MUST advertise more receive credit as data is consumed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0014")]
public sealed class REQ_QUIC_RFC9000_S3P2_0014
{
    [Fact]
    [Trait("Category", "Positive")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryReadStreamData_AdvertisesMoreReceiveCreditAsDataIsConsumed()
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

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preReadSnapshot));
        Assert.Equal(8UL, preReadSnapshot.ReceiveLimit);
        Assert.Equal(0UL, preReadSnapshot.ReadOffset);

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
    }
}

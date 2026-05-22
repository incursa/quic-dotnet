namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0025">QUIC MUST NOT provide any means of ensuring ordering between bytes on different streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0025")]
public sealed class REQ_QUIC_RFC9000_0025
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_DeliversOnePeerStreamWhileAnotherPeerStreamRemainsMissingItsPrefix()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, [0x21, 0x22], offset: 2),
            out QuicStreamFrame firstTailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 3, [0x31, 0x32], offset: 0),
            out QuicStreamFrame secondCompleteFrame));

        Assert.True(state.TryReceiveStreamFrame(firstTailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(secondCompleteFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            3,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x31, 0x32 }.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.False(state.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, firstSnapshot.ReceiveState);
        Assert.True(firstSnapshot.HasFinalSize);
        Assert.Equal(4UL, firstSnapshot.FinalSize);
        Assert.Equal(2, firstSnapshot.BufferedReadableBytes);
        Assert.Equal(0UL, firstSnapshot.ReadOffset);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0025")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotCompleteOneStreamFromAnotherStreamsBufferedTail()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 1, [0x21, 0x22], offset: 2),
            out QuicStreamFrame firstTailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 3, [0x31, 0x32], offset: 0),
            out QuicStreamFrame secondCompleteFrame));

        Assert.True(state.TryReceiveStreamFrame(firstTailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(secondCompleteFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            3,
            destination,
            out int bytesWritten,
            out bool completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.True(completed);

        Assert.False(state.TryReadStreamData(
            1,
            destination,
            out bytesWritten,
            out completed,
            out _,
            out _,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, firstSnapshot.ReceiveState);
        Assert.Equal(2, firstSnapshot.BufferedReadableBytes);
        Assert.Equal(0UL, firstSnapshot.ReadOffset);
    }
}

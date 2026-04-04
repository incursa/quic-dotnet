namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0007">Implementations MAY use alternative strategies for determining the content of probe packets, including sending new or retransmitted data based on the application&apos;s priorities.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0007")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProbeContent_CanUseEitherNewOrPreviouslySentStreamData()
    {
        byte[] newDataPacket = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData: [0x40, 0x41, 0x42],
            offset: 0);

        byte[] retransmittedDataPacket = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x06,
            streamData: [0x10, 0x20, 0x30],
            offset: 0x11223344);

        Assert.True(QuicStreamParser.TryParseStreamFrame(newDataPacket, out QuicStreamFrame newDataFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(retransmittedDataPacket, out QuicStreamFrame retransmittedDataFrame));
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(newDataFrame.FrameType));
        Assert.True(QuicFrameCodec.IsAckElicitingFrameType(retransmittedDataFrame.FrameType));

        Span<byte> newDataDestination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            newDataFrame.FrameType,
            newDataFrame.StreamId.Value,
            newDataFrame.Offset,
            newDataFrame.StreamData,
            newDataDestination,
            out int newDataBytesWritten));
        Assert.True(newDataPacket.AsSpan().SequenceEqual(newDataDestination[..newDataBytesWritten]));

        Span<byte> retransmittedDataDestination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            retransmittedDataFrame.FrameType,
            retransmittedDataFrame.StreamId.Value,
            retransmittedDataFrame.Offset,
            retransmittedDataFrame.StreamData,
            retransmittedDataDestination,
            out int retransmittedDataBytesWritten));
        Assert.True(retransmittedDataPacket.AsSpan().SequenceEqual(retransmittedDataDestination[..retransmittedDataBytesWritten]));
    }
}

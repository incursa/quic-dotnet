namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P8-0001">The OFF bit (0x04) in the frame type MUST be set to indicate that there is an Offset field present.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P8-0001")]
public sealed class REQ_QUIC_RFC9000_S19P8_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_SetsTheOffsetBitWhenOffsetIsPresent()
    {
        byte[] streamData = [0xAA, 0xBB, 0xCC, 0xDD];
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x04,
            streamData,
            offset: 0x11223344);

        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));
        Assert.True(frame.HasOffset);
        Assert.Equal(0x11223344UL, frame.Offset);
        Assert.Equal((byte)0x0C, frame.FrameType);
        Assert.Equal(QuicStreamType.ClientInitiatedBidirectional, frame.StreamType);
        Assert.True((frame.FrameType & 0x04) != 0);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatStreamFrame(
            frame.FrameType,
            frame.StreamId.Value,
            frame.Offset,
            frame.StreamData,
            destination,
            out int bytesWritten));
        Assert.Equal(packet.Length, bytesWritten);
        Assert.True(packet.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}

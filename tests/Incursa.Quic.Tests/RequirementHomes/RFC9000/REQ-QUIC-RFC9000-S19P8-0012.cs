namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0012")]
public sealed class REQ_QUIC_RFC9000_S19P8_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_ExposesAllStreamFrameFields()
    {
        byte[] streamData = [0xAA, 0xBB];
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0F,
            streamId: 0x05,
            streamData,
            offset: 0x20);

        Assert.Equal((byte)0x0F, frame.FrameType);
        Assert.Equal(0x05UL, frame.StreamId.Value);
        Assert.True(frame.HasOffset);
        Assert.Equal(0x20UL, frame.Offset);
        Assert.True(frame.HasLength);
        Assert.Equal(2UL, frame.Length);
        Assert.True(frame.IsFin);
        Assert.True(streamData.AsSpan().SequenceEqual(frame.StreamData));
    }
}

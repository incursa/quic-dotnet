namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0016")]
public sealed class REQ_QUIC_RFC9000_S19P8_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_LengthFieldLimitsStreamData()
    {
        byte[] packet = QuicS19P8StreamFrameTestSupport.BuildStreamFrameWithDeclaredLength(
            frameType: 0x0A,
            streamId: 0x04,
            declaredLength: 2,
            streamData: [0xAA, 0xBB, 0xCC]);

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.ParsePacket(packet);

        Assert.True(frame.HasLength);
        Assert.Equal(2UL, frame.Length);
        Assert.True(new byte[] { 0xAA, 0xBB }.AsSpan().SequenceEqual(frame.StreamData));
        Assert.Equal(packet.Length - 1, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsLengthThatExceedsAvailableStreamData()
    {
        byte[] packet = QuicS19P8StreamFrameTestSupport.BuildStreamFrameWithDeclaredLength(
            frameType: 0x0A,
            streamId: 0x04,
            declaredLength: 3,
            streamData: [0xAA, 0xBB]);

        QuicS19P8StreamFrameTestSupport.AssertRejects(packet);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ZeroLengthFieldConsumesNoStreamData()
    {
        byte[] packet = QuicS19P8StreamFrameTestSupport.BuildStreamFrameWithDeclaredLength(
            frameType: 0x0A,
            streamId: 0x04,
            declaredLength: 0,
            streamData: [0xCC]);

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.ParsePacket(packet);

        Assert.Equal(0UL, frame.Length);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.Equal(packet.Length - 1, frame.ConsumedLength);
    }
}

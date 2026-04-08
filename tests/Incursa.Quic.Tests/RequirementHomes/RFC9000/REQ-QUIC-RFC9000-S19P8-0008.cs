namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
public sealed class REQ_QUIC_RFC9000_S19P8_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsFramesWithNonStreamTypes()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x06, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x07, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x10, 0x00], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsEmptyInput()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame(Array.Empty<byte>(), out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsNonShortestFrameTypeEncoding()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrameWithEncodedType(
            frameType: 0x08,
            encodedLength: 2,
            streamId: 0x00,
            streamData: [0x00, 0x00]);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }
}

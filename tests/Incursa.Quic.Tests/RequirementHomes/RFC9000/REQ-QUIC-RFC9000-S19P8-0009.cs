namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
public sealed class REQ_QUIC_RFC9000_S19P8_0009
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsTruncatedFixedFields(int truncateBy)
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x04,
            streamData: [0xAA, 0xBB],
            offset: 0x11223344);

        byte[] truncated = packet[..Math.Max(0, packet.Length - truncateBy)];

        Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
    }
}

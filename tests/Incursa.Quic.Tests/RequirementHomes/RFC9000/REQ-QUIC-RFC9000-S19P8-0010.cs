namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0010")]
public sealed class REQ_QUIC_RFC9000_S19P8_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsTruncatedOffsetField()
    {
        Span<byte> offsetEncoding = stackalloc byte[8];
        Assert.True(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue, offsetEncoding, out int offsetBytes));

        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0C,
            streamId: 0x04,
            streamData: [0xAA],
            offset: QuicVariableLengthInteger.MaxValue);

        byte[] truncated = packet[..(1 + 1 + offsetBytes - 1)];

        Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
    }
}

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0002")]
public sealed class REQ_QUIC_RFC9000_S19P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPaddingFrame_WritesBytesThatCanBeRepeatedToIncreasePacketSize()
    {
        Span<byte> packet = stackalloc byte[2];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet, out int firstBytesWritten));
        Assert.Equal(1, firstBytesWritten);
        Assert.Equal(0x00, packet[0]);

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet[firstBytesWritten..], out int secondBytesWritten));
        Assert.Equal(1, secondBytesWritten);
        Assert.Equal(2, firstBytesWritten + secondBytesWritten);
        Assert.Equal(0x00, packet[1]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatPaddingFrame_RejectsEmptyDestinations()
    {
        Assert.False(QuicFrameCodec.TryFormatPaddingFrame(Span<byte>.Empty, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(ReadOnlySpan<byte>.Empty, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParsePaddingFrame_ConsumesOnlyTheSinglePaddingByteAtThePacketBoundary()
    {
        Span<byte> packet = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet, out int bytesWritten));
        Assert.Equal(1, bytesWritten);

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet[..bytesWritten], out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }
}

namespace Incursa.Quic.Tests;

public sealed class QuicHandshakeDoneFrameTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseHandshakeDoneFrame_ParsesAndFormatsTheTypeOnlyFrame()
    {
        byte[] encoded = QuicFrameTestData.BuildHandshakeDoneFrame();
        byte[] encodedWithTrailingBytes = [0x1E, 0xAA, 0xBB];

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encoded, out QuicHandshakeDoneFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(encodedWithTrailingBytes, out _, out int trailingBytesConsumed));
        Assert.Equal(1, trailingBytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseHandshakeDoneFrame_RejectsEmptyAndMismatchedTypes()
    {
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([], out _, out _));
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x1D], out _, out _));
        Assert.False(QuicFrameCodec.TryFormatHandshakeDoneFrame(default, stackalloc byte[0], out _));
    }
}

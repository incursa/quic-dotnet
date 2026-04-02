namespace Incursa.Quic.Tests;

public sealed class QuicFrameCodecPart3Tests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0012")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0013")]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_ParsesAndFormatsAllFields()
    {
        byte[] cryptoData = [0xAA, 0xBB, 0xCC];
        QuicCryptoFrame frame = new(0x1122_3344, cryptoData);
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(frame);

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.Offset, parsed.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_AcceptsFramesThatExactlyReachTheStreamCeiling()
    {
        byte[] cryptoData = [0xAB];
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue - 1, cryptoData));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(encoded, out QuicCryptoFrame parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue - 1, parsed.Offset);
        Assert.True(cryptoData.AsSpan().SequenceEqual(parsed.CryptoData));
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [Trait("Category", "Negative")]
    public void TryParseCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        byte[] encoded = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(QuicVariableLengthInteger.MaxValue, [0xAA]));

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0010")]
    [Requirement("REQ-QUIC-RFC9000-S19P6-0011")]
    [Trait("Category", "Negative")]
    public void TryFormatCryptoFrame_RejectsFramesThatExceedTheStreamCeiling()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue, [0xAA]);

        Assert.False(QuicFrameCodec.TryFormatCryptoFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [Trait("Category", "Positive")]
    public void TryParseNewTokenFrame_ParsesAndFormatsAllFields()
    {
        byte[] token = [0x10, 0x20, 0x30, 0x40];
        QuicNewTokenFrame frame = new(token);
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(frame);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(encoded, out QuicNewTokenFrame parsed, out int bytesConsumed));
        Assert.True(token.AsSpan().SequenceEqual(parsed.Token));
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicFrameCodec.TryFormatNewTokenFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P7-0007")]
    [Trait("Category", "Negative")]
    public void TryParseNewTokenFrame_RejectsEmptyTokens()
    {
        QuicNewTokenFrame emptyFrame = new(Array.Empty<byte>());
        byte[] encoded = QuicFrameTestData.BuildNewTokenFrame(emptyFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseNewTokenFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatNewTokenFrame(emptyFrame, destination, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P9-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Trait("Category", "Positive")]
    public void TryParseMaxDataFrame_ParsesAndFormatsTheMaximumDataField()
    {
        QuicMaxDataFrame frame = new(0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(encoded, out QuicMaxDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.MaximumData, parsed.MaximumData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0007")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0009")]
    [Requirement("REQ-QUIC-RFC9000-S19P10-0010")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0008")]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_ParsesAndFormatsTheFrameFields()
    {
        QuicMaxStreamDataFrame frame = new(0x06, 0x1234_5678);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamDataFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out QuicMaxStreamDataFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.StreamId, parsed.StreamId);
        Assert.Equal(frame.MaximumStreamData, parsed.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamDataFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0002")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0003")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0004")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0004")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamsFrame_ParsesAndFormatsBidirectionalAndUnidirectionalVariants(bool isBidirectional)
    {
        QuicMaxStreamsFrame frame = new(isBidirectional, 0x1234);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(frame);

        Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out QuicMaxStreamsFrame parsed, out int bytesConsumed));
        Assert.Equal(frame.IsBidirectional, parsed.IsBidirectional);
        Assert.Equal(frame.MaximumStreams, parsed.MaximumStreams);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatMaxStreamsFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P11-0006")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0007")]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        QuicMaxStreamsFrame invalidFrame = new(true, (1UL << 60) + 1);
        byte[] encoded = QuicFrameTestData.BuildMaxStreamsFrame(invalidFrame);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatMaxStreamsFrame(invalidFrame, destination, out _));
    }
}

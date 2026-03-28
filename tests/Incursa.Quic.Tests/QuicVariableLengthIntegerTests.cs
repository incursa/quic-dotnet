namespace Incursa.Quic.Tests;

public sealed class QuicVariableLengthIntegerTests
{
    public static TheoryData<ulong, int> EncodedLengthCases => new()
    {
        { 0, 1 },
        { 63, 1 },
        { 64, 2 },
        { 16_383, 2 },
        { 16_384, 4 },
        { 1_073_741_823, 4 },
        { 1_073_741_824, 8 },
        { QuicVariableLengthInteger.MaxValue, 8 },
    };

    public static TheoryData<byte[], ulong, int> ExactParseCases => new()
    {
        { new byte[] { 0x00 }, 0UL, 1 },
        { new byte[] { 0x3F }, 63UL, 1 },
        { new byte[] { 0x40, 0x40 }, 64UL, 2 },
        { new byte[] { 0x7F, 0xFF }, 16_383UL, 2 },
        { new byte[] { 0x80, 0x00, 0x40, 0x00 }, 16_384UL, 4 },
        { new byte[] { 0x92, 0x34, 0x56, 0x78 }, 0x1234_5678UL, 4 },
        { new byte[] { 0xBF, 0xFF, 0xFF, 0xFF }, 1_073_741_823UL, 4 },
        { new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, 1_073_741_824UL, 8 },
        { new byte[] { 0xC1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }, 0x0123_4567_89AB_CDEFUL, 8 },
        { new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, QuicVariableLengthInteger.MaxValue, 8 },
    };

    public static TheoryData<ulong, byte[]> ExactFormatCases => new()
    {
        { 0UL, new byte[] { 0x00 } },
        { 63UL, new byte[] { 0x3F } },
        { 64UL, new byte[] { 0x40, 0x40 } },
        { 16_383UL, new byte[] { 0x7F, 0xFF } },
        { 16_384UL, new byte[] { 0x80, 0x00, 0x40, 0x00 } },
        { 0x1234_5678UL, new byte[] { 0x92, 0x34, 0x56, 0x78 } },
        { 1_073_741_823UL, new byte[] { 0xBF, 0xFF, 0xFF, 0xFF } },
        { 1_073_741_824UL, new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
        { 0x0123_4567_89AB_CDEFUL, new byte[] { 0xC1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF } },
        { QuicVariableLengthInteger.MaxValue, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    };

    [Theory]
    [MemberData(nameof(EncodedLengthCases))]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Positive")]
    public void TryParse_DecodesValuesUsingTheExpectedEncodedLength(ulong value, int expectedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeMinimal(value);

        Assert.Equal(expectedLength, encoded.Length);
        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(expectedLength, bytesConsumed);
    }

    [Theory]
    [MemberData(nameof(ExactParseCases))]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Positive")]
    public void TryParse_DecodesExactWireEncodings(byte[] encoded, ulong expectedValue, int expectedLength)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(expectedValue, parsed);
        Assert.Equal(expectedLength, bytesConsumed);
    }

    [Theory]
    [InlineData(0UL, 2)]
    [InlineData(1UL, 4)]
    [InlineData(63UL, 8)]
    [Trait("Requirement", "REQ-QUIC-VINT-0005")]
    [Trait("Category", "Positive")]
    public void TryParse_AcceptsNonMinimalEncodings(ulong value, int encodedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(encodedLength, bytesConsumed);
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-VINT-0004")]
    [Trait("Category", "Negative")]
    public void TryParse_RejectsEmptyInput()
    {
        Assert.False(QuicVariableLengthInteger.TryParse(Array.Empty<byte>(), out _, out _));
    }

    [Theory]
    [InlineData(new byte[] { 0x40 })]
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })]
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [Trait("Requirement", "REQ-QUIC-VINT-0004")]
    [Trait("Category", "Negative")]
    public void TryParse_RejectsTruncatedInputs(byte[] encoded)
    {
        Assert.False(QuicVariableLengthInteger.TryParse(encoded, out _, out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Positive")]
    public void TryFormat_WritesTheShortestRoundTrippableEncoding()
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue, buffer, out int bytesWritten));
        Assert.Equal(8, bytesWritten);
        Assert.True(QuicVariableLengthInteger.TryParse(buffer[..bytesWritten], out ulong parsed, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed);
        Assert.Equal(8, bytesConsumed);
    }

    [Theory]
    [MemberData(nameof(ExactFormatCases))]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Positive")]
    public void TryFormat_WritesExactWireEncodings(ulong value, byte[] expectedEncoding)
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.Equal(expectedEncoding.Length, bytesWritten);
        Assert.True(expectedEncoding.AsSpan().SequenceEqual(buffer[..bytesWritten]));
    }

    [Theory]
    [InlineData(0UL, 0)]
    [InlineData(64UL, 1)]
    [InlineData(16_384UL, 3)]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Negative")]
    public void TryFormat_RejectsInsufficientDestinationSpace(ulong value, int destinationLength)
    {
        Span<byte> destination = destinationLength == 0 ? Span<byte>.Empty : new byte[destinationLength];

        Assert.False(QuicVariableLengthInteger.TryFormat(value, destination, out _));
    }

    [Fact]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
    [Trait("Category", "Negative")]
    public void TryFormat_RejectsValuesAboveTheCeiling()
    {
        Span<byte> destination = stackalloc byte[8];

        Assert.False(QuicVariableLengthInteger.TryFormat(QuicVariableLengthInteger.MaxValue + 1, destination, out _));
    }
}

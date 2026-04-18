namespace Incursa.Quic.Tests;

public sealed class QuicVariableLengthIntegerUnitTests
{
    public static TheoryData<ulong, int> RoundTripCases => new()
    {
        { 0UL, 1 },
        { 63UL, 1 },
        { 64UL, 2 },
        { 16_383UL, 2 },
        { 16_384UL, 4 },
        { 1_073_741_823UL, 4 },
        { 1_073_741_824UL, 8 },
        { QuicVariableLengthInteger.MaxValue, 8 },
    };

    [Theory]
    [MemberData(nameof(RoundTripCases))]
    public void TryFormatAndTryParse_RoundTripBoundaryValues(ulong value, int expectedLength)
    {
        byte[] buffer = new byte[QuicVariableLengthInteger.MaxEncodedLength];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.Equal(expectedLength, bytesWritten);
        Assert.Equal(expectedLength switch
        {
            1 => 0x00,
            2 => 0x40,
            4 => 0x80,
            8 => 0xC0,
            _ => throw new InvalidOperationException(),
        }, buffer[0] & 0xC0);

        Assert.True(QuicVariableLengthInteger.TryParse(buffer[..bytesWritten], out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(expectedLength, bytesConsumed);
    }

    public static TheoryData<ulong> OversizedValues => new()
    {
        { QuicVariableLengthInteger.MaxValue + 1 },
        { ulong.MaxValue },
    };

    [Theory]
    [MemberData(nameof(OversizedValues))]
    public void TryFormat_RejectsValuesAboveTheMaximum(ulong value)
    {
        Span<byte> destination = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];

        Assert.False(QuicVariableLengthInteger.TryFormat(value, destination, out _));
    }

    public static TheoryData<ulong, int> TruncatedEncodingCases => new()
    {
        { 63UL, 1 },
        { 64UL, 2 },
        { 16_384UL, 4 },
        { 1_073_741_824UL, 8 },
    };

    [Theory]
    [MemberData(nameof(TruncatedEncodingCases))]
    public void TryParse_RejectsTruncatedEncodings(ulong value, int encodedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

        Assert.False(QuicVariableLengthInteger.TryParse(encoded[..^1], out _, out _));
    }

    public static TheoryData<ulong, int, byte> PrefixMismatchCases => new()
    {
        { 63UL, 1, 0x40 },
        { 63UL, 2, 0x80 },
        { 16_383UL, 4, 0xC0 },
    };

    [Theory]
    [MemberData(nameof(PrefixMismatchCases))]
    public void TryParse_RejectsLengthPrefixesThatPromiseMoreBytesThanArePresent(
        ulong value,
        int encodedLength,
        byte lengthPrefix)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);
        encoded[0] = (byte)((encoded[0] & 0x3F) | lengthPrefix);

        Assert.False(QuicVariableLengthInteger.TryParse(encoded, out _, out _));
    }
}

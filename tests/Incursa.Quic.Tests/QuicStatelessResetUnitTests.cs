using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

public sealed class QuicStatelessResetUnitTests
{
    public static TheoryData<int, int> UndersizedFormatCases => new()
    {
        { QuicStatelessReset.MinimumDatagramLength - 1, QuicStatelessReset.MinimumDatagramLength },
        { QuicStatelessReset.MinimumDatagramLength, QuicStatelessReset.MinimumDatagramLength - 1 },
    };

    public static TheoryData<byte[]> MalformedFlattenedTokenCases => new()
    {
        Array.Empty<byte>(),
        CreateBytes(15, 0x01),
        CreateBytes(17, 0x01),
    };

    [Fact]
    public void TryGenerateStatelessResetToken_ReturnsTheFirstSixteenBytesOfTheHmac()
    {
        byte[] connectionId = CreateBytes(4, 0x10);
        byte[] secretKey = CreateBytes(8, 0x90);
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);

        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedToken = hmac.ComputeHash(connectionId);

        Assert.True(token.SequenceEqual(expectedToken.AsSpan(..QuicStatelessReset.StatelessResetTokenLength)));
    }

    [Fact]
    public void TryFormatStatelessResetDatagram_WritesTheMinimumLengthDatagramAndKeepsTheTokenAtTheTail()
    {
        byte[] token = CreateToken(0x30);
        byte[] datagram = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagram.Length, datagram, out int bytesWritten));
        Assert.Equal(datagram.Length, bytesWritten);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken));
        Assert.True(token.AsSpan().SequenceEqual(trailingToken));
    }

    [Theory]
    [MemberData(nameof(UndersizedFormatCases))]
    public void TryFormatStatelessResetDatagram_RejectsUndersizedDestinationOrDatagramLength(
        int destinationLength,
        int datagramLength)
    {
        byte[] token = CreateToken(0x30);
        byte[] destination = new byte[destinationLength];

        Assert.False(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagramLength, destination, out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    public void TryGetTrailingStatelessResetToken_RejectsDatagramsShorterThanTheToken()
    {
        byte[] datagram = CreateBytes(QuicStatelessReset.StatelessResetTokenLength - 1, 0x10);

        Assert.False(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out _));
    }

    [Fact]
    public void MatchesAnyStatelessResetToken_ReturnsTrueForATrailingTokenHit()
    {
        byte[] matchingToken = CreateToken(0x30);
        byte[] nonMatchingToken = CreateToken(0x50);
        byte[] datagram = CreateFormattedDatagram(0x30);
        Span<byte> flattenedTokens = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength * 2];

        nonMatchingToken.AsSpan().CopyTo(flattenedTokens);
        matchingToken.AsSpan().CopyTo(flattenedTokens[QuicStatelessReset.StatelessResetTokenLength..]);

        Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, flattenedTokens));
    }

    [Fact]
    public void MatchesAnyStatelessResetToken_ReturnsFalseForATrailingTokenMiss()
    {
        byte[] matchingToken = CreateToken(0x30);
        byte[] nonMatchingToken = CreateToken(0x50);
        byte[] datagram = CreateFormattedDatagram(0x30);

        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, nonMatchingToken));
    }

    [Theory]
    [MemberData(nameof(MalformedFlattenedTokenCases))]
    public void MatchesAnyStatelessResetToken_RejectsMalformedFlattenedTokenLists(byte[] candidateTokens)
    {
        byte[] datagram = CreateFormattedDatagram(0x30);

        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, candidateTokens));
    }

    private static byte[] CreateFormattedDatagram(byte tokenStart)
    {
        byte[] token = CreateToken(tokenStart);
        byte[] datagram = new byte[QuicStatelessReset.MinimumDatagramLength];

        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(token, datagram.Length, datagram, out int bytesWritten));
        Assert.Equal(datagram.Length, bytesWritten);
        return datagram;
    }

    private static byte[] CreateToken(byte start = 0x20)
    {
        return CreateBytes(QuicStatelessReset.StatelessResetTokenLength, start);
    }

    private static byte[] CreateBytes(int length, byte start)
    {
        byte[] bytes = new byte[length];

        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(start + index);
        }

        return bytes;
    }
}

using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

public sealed class QuicStatelessResetTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0016")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGenerateStatelessResetToken_GeneratesStable16ByteTokensPerConnectionId()
    {
        byte[] secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        byte[] connectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] otherConnectionId = [0x20, 0x21, 0x22, 0x23];

        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> otherToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        Span<byte> otherConnectionToken = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, otherToken, out int otherBytesWritten));
        Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(otherConnectionId, secretKey, otherConnectionToken, out int otherConnectionBytesWritten));

        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherBytesWritten);
        Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, otherConnectionBytesWritten);
        Assert.True(token.SequenceEqual(otherToken));
        Assert.False(token.SequenceEqual(otherConnectionToken));

        Span<byte> expected = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        using HMACSHA256 hmac = new(secretKey);
        byte[] expectedHash = hmac.ComputeHash(connectionId);
        expectedHash.AsSpan(..QuicStatelessReset.StatelessResetTokenLength).CopyTo(expected);
        Assert.True(expected.SequenceEqual(token));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P2-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGenerateStatelessResetToken_RejectsZeroLengthConnectionIds()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];

        Assert.False(QuicStatelessReset.TryGenerateStatelessResetToken([], [0xAA, 0xBB], token, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatStatelessResetDatagram_WritesShortHeaderLayoutWithTokenAtTheTail()
    {
        byte[] statelessResetToken = [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F];

        Span<byte> destination = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten));

        Assert.Equal(QuicStatelessReset.MinimumDatagramLength, bytesWritten);
        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(destination[..bytesWritten]));
        Assert.Equal((byte)0x40, (byte)(destination[0] & 0x40));
        Assert.Equal(0, destination[0] & 0x80);
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(destination[(bytesWritten - QuicStatelessReset.StatelessResetTokenLength)..bytesWritten]));

        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(destination[..bytesWritten], out ReadOnlySpan<byte> trailingToken));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(trailingToken));
    }

    [Theory]
    [InlineData(43, 42)]
    [InlineData(22, 21)]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetRecommendedDatagramLength_UsesOneByteShorterWhenPossible(int triggeringPacketLength, int expectedLength)
    {
        Assert.True(QuicStatelessReset.TryGetRecommendedDatagramLength(triggeringPacketLength, out int datagramLength));
        Assert.Equal(expectedLength, datagramLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetRecommendedDatagramLength_RejectsLengthsThatCannotBeMadeShorter()
    {
        Assert.False(QuicStatelessReset.TryGetRecommendedDatagramLength(QuicStatelessReset.MinimumDatagramLength, out _));
    }

    [Theory]
    [InlineData(0, 22)]
    [InlineData(8, 30)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetMinimumPacketLengthForResetResistance_OffsetsByTwentyTwoBytes(int minimumConnectionIdLength, int expectedLength)
    {
        Assert.True(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(minimumConnectionIdLength, out int minimumPacketLength));
        Assert.Equal(expectedLength, minimumPacketLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P3P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CanSendStatelessReset_RejectsAmplificationAndLoopingViolations()
    {
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 100, hasLoopPreventionState: false));
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 99, hasLoopPreventionState: false));
        Assert.False(QuicStatelessReset.CanSendStatelessReset(100, 300, hasLoopPreventionState: true));
        Assert.True(QuicStatelessReset.CanSendStatelessReset(100, 100, hasLoopPreventionState: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void MatchesAnyStatelessResetToken_UsesTheTrailingSixteenBytes()
    {
        byte[] matchingToken = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F];
        byte[] nonMatchingToken = [
            0x50, 0x51, 0x52, 0x53,
            0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B,
            0x5C, 0x5D, 0x5E, 0x5F];

        Span<byte> datagram = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            matchingToken,
            QuicStatelessReset.MinimumDatagramLength,
            datagram,
            out int bytesWritten));

        Span<byte> flattenedTokens = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength * 2];
        nonMatchingToken.AsSpan().CopyTo(flattenedTokens);
        matchingToken.AsSpan().CopyTo(flattenedTokens[QuicStatelessReset.StatelessResetTokenLength..]);

        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram[..bytesWritten]));
        Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram[..bytesWritten], flattenedTokens));
        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram[..bytesWritten], nonMatchingToken));
        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram[..bytesWritten], []));
        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram[..bytesWritten], [0x01, 0x02]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void IsPotentialStatelessReset_RejectsTooShortOrWronglyFormedDatagrams()
    {
        Assert.False(QuicStatelessReset.IsPotentialStatelessReset([0x40, 0x00, 0x00, 0x00, 0x00]));
        Assert.False(QuicStatelessReset.IsPotentialStatelessReset([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]));
    }
}

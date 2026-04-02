using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3P1-0003")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MatchesAnyStatelessResetToken_UsesTheTrailingSixteenBytes()
    {
        byte[] matchingToken =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];

        byte[] nonMatchingToken =
        [
            0x50, 0x51, 0x52, 0x53,
            0x54, 0x55, 0x56, 0x57,
            0x58, 0x59, 0x5A, 0x5B,
            0x5C, 0x5D, 0x5E, 0x5F,
        ];

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
}

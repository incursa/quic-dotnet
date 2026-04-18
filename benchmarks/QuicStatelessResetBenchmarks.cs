using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the stateless-reset token generation, formatting, and matching helpers.
/// </summary>
[MemoryDiagnoser]
public class QuicStatelessResetBenchmarks
{
    private const int LargerFlattenedTokenCount = 8;
    private const int LargerDatagramLength = QuicStatelessReset.MinimumDatagramLength + 32;

    private byte[] secretKey = [];
    private byte[] connectionId = [];
    private byte[] alternateConnectionId = [];
    private byte[] statelessResetToken = [];
    private byte[] matchingFlattenedTokens = [];
    private byte[] missingFlattenedTokens = [];
    private byte[] largerFlattenedTokens = [];
    private byte[] formattedDatagram = [];
    private byte[] largerFormattedDatagram = [];
    private byte[] destination = [];
    private byte[] largerDestination = [];

    /// <summary>
    /// Prepares representative stateless-reset inputs and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        connectionId = [0x10, 0x11, 0x12, 0x13];
        alternateConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
            0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B,
        ];
        statelessResetToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
        destination = new byte[QuicStatelessReset.MinimumDatagramLength];
        largerDestination = new byte[LargerDatagramLength];

        if (!QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, statelessResetToken, out _))
        {
            throw new InvalidOperationException("Failed to generate a representative stateless reset token.");
        }

        if (!QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten))
        {
            throw new InvalidOperationException("Failed to format a representative stateless reset datagram.");
        }

        formattedDatagram = destination[..bytesWritten].ToArray();

        if (!QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            LargerDatagramLength,
            largerDestination,
            out bytesWritten))
        {
            throw new InvalidOperationException("Failed to format a larger representative stateless reset datagram.");
        }

        largerFormattedDatagram = largerDestination[..bytesWritten].ToArray();
        matchingFlattenedTokens = BuildFlattenedTokenSet(statelessResetToken, 2);

        byte[] missingToken = statelessResetToken.ToArray();
        missingToken[^1] ^= 0xFF;
        missingFlattenedTokens = BuildFlattenedTokenSet(missingToken, 2);
        largerFlattenedTokens = BuildFlattenedTokenSetWithMatchAtEnd(
            missingToken,
            statelessResetToken,
            LargerFlattenedTokenCount);
    }

    /// <summary>
    /// Measures stateless-reset token generation.
    /// </summary>
    [Benchmark]
    public int GenerateStatelessResetToken()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        return QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secretKey, token, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset token generation with a longer connection ID.
    /// </summary>
    [Benchmark]
    public int GenerateStatelessResetTokenWithAlternateConnectionIdLength()
    {
        Span<byte> token = stackalloc byte[QuicStatelessReset.StatelessResetTokenLength];
        return QuicStatelessReset.TryGenerateStatelessResetToken(alternateConnectionId, secretKey, token, out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset formatting.
    /// </summary>
    [Benchmark]
    public int FormatStatelessResetDatagram()
    {
        return QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            destination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures Stateless Reset formatting for a larger datagram.
    /// </summary>
    [Benchmark]
    public int FormatLargerStatelessResetDatagram()
    {
        return QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            LargerDatagramLength,
            largerDestination,
            out int bytesWritten)
            ? bytesWritten
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching across a small token set when the token is present.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenHit()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(formattedDatagram, matchingFlattenedTokens)
            ? formattedDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching across a small token set when the token is absent.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenMiss()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(formattedDatagram, missingFlattenedTokens)
            ? formattedDatagram.Length
            : -1;
    }

    /// <summary>
    /// Measures trailing-token matching against a larger flattened token set.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetTokenAgainstLargerFlattenedTokenSet()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(largerFormattedDatagram, largerFlattenedTokens)
            ? largerFormattedDatagram.Length
            : -1;
    }

    private static byte[] BuildFlattenedTokenSet(ReadOnlySpan<byte> token, int tokenCount)
    {
        byte[] flattenedTokens = new byte[tokenCount * QuicStatelessReset.StatelessResetTokenLength];

        for (int index = 0; index < tokenCount; index++)
        {
            token.CopyTo(flattenedTokens.AsSpan(index * QuicStatelessReset.StatelessResetTokenLength));
        }

        return flattenedTokens;
    }

    private static byte[] BuildFlattenedTokenSetWithMatchAtEnd(
        ReadOnlySpan<byte> missToken,
        ReadOnlySpan<byte> matchToken,
        int tokenCount)
    {
        byte[] flattenedTokens = BuildFlattenedTokenSet(missToken, tokenCount);
        matchToken.CopyTo(flattenedTokens.AsSpan((tokenCount - 1) * QuicStatelessReset.StatelessResetTokenLength));
        return flattenedTokens;
    }
}

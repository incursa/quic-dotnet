using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the stateless-reset token generation, formatting, and matching helpers.
/// </summary>
[MemoryDiagnoser]
public class QuicStatelessResetBenchmarks
{
    private byte[] secretKey = [];
    private byte[] connectionId = [];
    private byte[] statelessResetToken = [];
    private byte[] flattenedTokens = [];
    private byte[] formattedDatagram = [];
    private byte[] destination = [];

    /// <summary>
    /// Prepares representative stateless-reset inputs and output buffers.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        secretKey = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
        connectionId = [0x10, 0x11, 0x12, 0x13];
        statelessResetToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
        destination = new byte[QuicStatelessReset.MinimumDatagramLength];
        flattenedTokens = new byte[QuicStatelessReset.StatelessResetTokenLength * 2];

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
        statelessResetToken.AsSpan().CopyTo(flattenedTokens);
        statelessResetToken.AsSpan().CopyTo(flattenedTokens[QuicStatelessReset.StatelessResetTokenLength..]);
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
    /// Measures trailing-token matching across a small token set.
    /// </summary>
    [Benchmark]
    public int MatchStatelessResetToken()
    {
        return QuicStatelessReset.MatchesAnyStatelessResetToken(formattedDatagram, flattenedTokens)
            ? formattedDatagram.Length
            : -1;
    }
}

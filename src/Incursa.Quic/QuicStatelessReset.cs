using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Provides helpers for RFC 9000 stateless-reset token generation, packet formatting, and token matching.
/// </summary>
public static class QuicStatelessReset
{
    /// <summary>
    /// Stateless Reset tokens are 16 bytes long.
    /// </summary>
    public const int StatelessResetTokenLength = 16;

    /// <summary>
    /// RFC 9000 requires at least 38 unpredictable bits in the visible prefix.
    /// </summary>
    public const int MinimumUnpredictableBits = 38;

    /// <summary>
    /// Five whole bytes are enough to satisfy the 38-bit minimum.
    /// </summary>
    public const int MinimumUnpredictableBytes = 5;

    /// <summary>
    /// The minimum datagram length this helper can format while still satisfying the visible-bit requirement.
    /// </summary>
    public const int MinimumDatagramLength = StatelessResetTokenLength + MinimumUnpredictableBytes;

    /// <summary>
    /// Generates a 16-byte stateless reset token from a connection ID and a secret key.
    /// </summary>
    public static bool TryGenerateStatelessResetToken(
        ReadOnlySpan<byte> connectionId,
        ReadOnlySpan<byte> secretKey,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (connectionId.IsEmpty || secretKey.IsEmpty || destination.Length < StatelessResetTokenLength)
        {
            return false;
        }

        using HMACSHA256 hmac = new(secretKey.ToArray());
        byte[] hash = hmac.ComputeHash(connectionId.ToArray());
        hash.AsSpan(..StatelessResetTokenLength).CopyTo(destination);
        bytesWritten = StatelessResetTokenLength;
        return true;
    }

    /// <summary>
    /// Computes a recommended Stateless Reset datagram length for a response packet.
    /// </summary>
    /// <remarks>
    /// This helper keeps the response one byte shorter than the triggering packet when possible, while preserving the
    /// minimum length required for a valid Stateless Reset prefix.
    /// </remarks>
    public static bool TryGetRecommendedDatagramLength(int triggeringPacketLength, out int datagramLength)
    {
        datagramLength = default;

        if (triggeringPacketLength <= MinimumDatagramLength)
        {
            return false;
        }

        datagramLength = Math.Max(MinimumDatagramLength, triggeringPacketLength - 1);
        return datagramLength < triggeringPacketLength;
    }

    /// <summary>
    /// Computes the minimum packet length that keeps ordinary packets at least 22 bytes longer than the minimum CID length.
    /// </summary>
    public static bool TryGetMinimumPacketLengthForResetResistance(
        int minimumConnectionIdLength,
        out int minimumPacketLength)
    {
        minimumPacketLength = default;

        if (minimumConnectionIdLength < 0 || minimumConnectionIdLength > int.MaxValue - 22)
        {
            return false;
        }

        minimumPacketLength = minimumConnectionIdLength + 22;
        return true;
    }

    /// <summary>
    /// Checks whether a Stateless Reset response length obeys the RFC 9000 anti-amplification and loop-prevention rules.
    /// </summary>
    public static bool CanSendStatelessReset(
        int triggeringPacketLength,
        int datagramLength,
        bool hasLoopPreventionState)
    {
        if (triggeringPacketLength <= 0 || datagramLength < MinimumDatagramLength)
        {
            return false;
        }

        if (!hasLoopPreventionState && datagramLength >= triggeringPacketLength)
        {
            return false;
        }

        return (long)datagramLength < (long)triggeringPacketLength * 3L;
    }

    /// <summary>
    /// Formats a Stateless Reset datagram with a short-header layout and a 16-byte token at the tail.
    /// </summary>
    public static bool TryFormatStatelessResetDatagram(
        ReadOnlySpan<byte> statelessResetToken,
        int datagramLength,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (statelessResetToken.Length != StatelessResetTokenLength
            || datagramLength < MinimumDatagramLength
            || destination.Length < datagramLength)
        {
            return false;
        }

        int unpredictableBytesLength = datagramLength - StatelessResetTokenLength;
        Span<byte> unpredictableBytes = destination[..unpredictableBytesLength];
        RandomNumberGenerator.Fill(unpredictableBytes);

        unpredictableBytes[0] = (byte)((unpredictableBytes[0] & 0x7F) | 0x40);
        statelessResetToken.CopyTo(destination.Slice(unpredictableBytesLength, StatelessResetTokenLength));

        bytesWritten = datagramLength;
        return true;
    }

    /// <summary>
    /// Returns the trailing 16 bytes from a datagram when it is long enough to contain a Stateless Reset token.
    /// </summary>
    public static bool TryGetTrailingStatelessResetToken(ReadOnlySpan<byte> datagram, out ReadOnlySpan<byte> statelessResetToken)
    {
        statelessResetToken = default;

        if (datagram.Length < StatelessResetTokenLength)
        {
            return false;
        }

        statelessResetToken = datagram[^StatelessResetTokenLength..];
        return true;
    }

    /// <summary>
    /// Determines whether a datagram has the structural shape of a Stateless Reset.
    /// </summary>
    public static bool IsPotentialStatelessReset(ReadOnlySpan<byte> datagram)
    {
        return datagram.Length >= MinimumDatagramLength
            && (datagram[0] & 0x80) == 0
            && (datagram[0] & 0x40) != 0;
    }

    /// <summary>
    /// Compares the trailing 16 bytes of a datagram against a flattened token set.
    /// </summary>
    public static bool MatchesAnyStatelessResetToken(ReadOnlySpan<byte> datagram, ReadOnlySpan<byte> candidateTokens)
    {
        if (!TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken)
            || candidateTokens.IsEmpty
            || (candidateTokens.Length % StatelessResetTokenLength) != 0)
        {
            return false;
        }

        for (int offset = 0; offset < candidateTokens.Length; offset += StatelessResetTokenLength)
        {
            if (CryptographicOperations.FixedTimeEquals(
                trailingToken,
                candidateTokens.Slice(offset, StatelessResetTokenLength)))
            {
                return true;
            }
        }

        return false;
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Provides helpers for RFC 9000 path-validation behavior that can be expressed without connection state.
/// </summary>
public static class QuicPathValidation
{
    private static int pathChallengeSequence;

    /// <summary>
    /// The number of payload bytes used by PATH_CHALLENGE and PATH_RESPONSE frames.
    /// </summary>
    public const int PathChallengeDataLength = 8;

    /// <summary>
    /// Fills an 8-byte PATH_CHALLENGE payload using fresh entropy and a monotonic nonce so successive calls differ.
    /// </summary>
    public static bool TryGeneratePathChallengeData(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = default;

        if (destination.Length < PathChallengeDataLength)
        {
            return false;
        }

        RandomNumberGenerator.Fill(destination[..PathChallengeDataLength]);
        BinaryPrimitives.WriteUInt32BigEndian(
            destination[..sizeof(uint)],
            unchecked((uint)Interlocked.Increment(ref pathChallengeSequence)));
        bytesWritten = PathChallengeDataLength;
        return true;
    }

    /// <summary>
    /// Computes the padding required to expand a path-validation datagram to the RFC 9000 minimum payload size.
    /// </summary>
    public static bool TryGetPathValidationDatagramPaddingLength(int currentPayloadLength, out int paddingLength)
    {
        return QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(currentPayloadLength, out paddingLength);
    }

    /// <summary>
    /// Measures the elapsed time between sending PATH_CHALLENGE data and receiving PATH_RESPONSE data.
    /// </summary>
    public static bool TryMeasurePathChallengeRoundTripMicros(
        ulong pathChallengeSentAtMicros,
        ulong pathResponseReceivedAtMicros,
        out ulong roundTripMicros)
    {
        return QuicRecoveryTiming.TryMeasurePathChallengeRoundTripMicros(
            pathChallengeSentAtMicros,
            pathResponseReceivedAtMicros,
            out roundTripMicros);
    }

    /// <summary>
    /// Formats PADDING frames needed to expand a path-validation datagram to the RFC 9000 minimum payload size.
    /// </summary>
    /// <remarks>
    /// The caller must ensure the remaining anti-amplification budget permits the requested expansion.
    /// </remarks>
    public static bool TryFormatPathValidationDatagramPadding(
        int currentPayloadLength,
        QuicAntiAmplificationBudget antiAmplificationBudget,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryGetPathValidationDatagramPaddingLength(currentPayloadLength, out int paddingLength))
        {
            return false;
        }

        if (paddingLength == 0)
        {
            return true;
        }

        if (!antiAmplificationBudget.IsAddressValidated
            && antiAmplificationBudget.RemainingSendBudget < (ulong)paddingLength)
        {
            return false;
        }

        return QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            currentPayloadLength,
            destination,
            out bytesWritten);
    }
}

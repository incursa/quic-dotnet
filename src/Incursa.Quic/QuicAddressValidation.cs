namespace Incursa.Quic;

/// <summary>
/// Provides helpers for the RFC 9000 address-validation rules that can be expressed without a connection state machine.
/// </summary>
public static class QuicAddressValidation
{
    private const int MinimumEntropyBits = 64;
    private const int MinimumEntropyBytes = MinimumEntropyBits / 8;

    /// <summary>
    /// Determines whether a peer address may be considered validated from an endpoint-chosen connection ID.
    /// </summary>
    /// <remarks>
    /// This helper only checks the structural 64-bit minimum and whether the connection ID was chosen by the endpoint.
    /// </remarks>
    public static bool CanConsiderPeerAddressValidated(ReadOnlySpan<byte> connectionId, bool chosenByEndpoint)
    {
        return chosenByEndpoint && connectionId.Length >= MinimumEntropyBytes;
    }

    /// <summary>
    /// Computes the number of bytes needed to pad an Initial datagram payload to the RFC 9000 minimum.
    /// </summary>
    public static bool TryGetVersion1InitialDatagramPaddingLength(int currentPayloadLength, out int paddingLength)
    {
        paddingLength = default;

        if (currentPayloadLength < 0)
        {
            return false;
        }

        if (currentPayloadLength >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
        {
            return true;
        }

        paddingLength = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - currentPayloadLength;
        return true;
    }

    /// <summary>
    /// Formats the padding bytes needed to bring an Initial datagram payload up to the RFC 9000 minimum.
    /// </summary>
    public static bool TryFormatVersion1InitialDatagramPadding(
        int currentPayloadLength,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryGetVersion1InitialDatagramPaddingLength(currentPayloadLength, out int paddingLength)
            || destination.Length < paddingLength)
        {
            return false;
        }

        int index = 0;
        while (index < paddingLength)
        {
            if (!QuicFrameCodec.TryFormatPaddingFrame(destination[index..], out int paddingFrameBytesWritten))
            {
                bytesWritten = default;
                return false;
            }

            index += paddingFrameBytesWritten;
        }

        bytesWritten = index;
        return true;
    }
}

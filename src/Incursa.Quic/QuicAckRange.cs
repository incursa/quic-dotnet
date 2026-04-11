namespace Incursa.Quic;

/// <summary>
/// A parsed ACK Range entry after the first ACK Range.
/// </summary>
internal readonly struct QuicAckRange
{
    /// <summary>
    /// Initializes a new ACK Range entry.
    /// </summary>
    internal QuicAckRange(ulong gap, ulong ackRangeLength, ulong smallestAcknowledged, ulong largestAcknowledged)
    {
        Gap = gap;
        AckRangeLength = ackRangeLength;
        SmallestAcknowledged = smallestAcknowledged;
        LargestAcknowledged = largestAcknowledged;
    }

    /// <summary>
    /// Gets the encoded Gap value.
    /// </summary>
    internal ulong Gap { get; }

    /// <summary>
    /// Gets the encoded ACK Range Length value.
    /// </summary>
    internal ulong AckRangeLength { get; }

    /// <summary>
    /// Gets the smallest acknowledged packet number in the range.
    /// </summary>
    internal ulong SmallestAcknowledged { get; }

    /// <summary>
    /// Gets the largest acknowledged packet number in the range.
    /// </summary>
    internal ulong LargestAcknowledged { get; }
}


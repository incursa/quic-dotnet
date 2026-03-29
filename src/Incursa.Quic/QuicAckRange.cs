namespace Incursa.Quic;

/// <summary>
/// A parsed ACK Range entry after the first ACK Range.
/// </summary>
public readonly struct QuicAckRange
{
    /// <summary>
    /// Initializes a new ACK Range entry.
    /// </summary>
    public QuicAckRange(ulong gap, ulong ackRangeLength, ulong smallestAcknowledged, ulong largestAcknowledged)
    {
        Gap = gap;
        AckRangeLength = ackRangeLength;
        SmallestAcknowledged = smallestAcknowledged;
        LargestAcknowledged = largestAcknowledged;
    }

    /// <summary>
    /// Gets the encoded Gap value.
    /// </summary>
    public ulong Gap { get; }

    /// <summary>
    /// Gets the encoded ACK Range Length value.
    /// </summary>
    public ulong AckRangeLength { get; }

    /// <summary>
    /// Gets the smallest acknowledged packet number in the range.
    /// </summary>
    public ulong SmallestAcknowledged { get; }

    /// <summary>
    /// Gets the largest acknowledged packet number in the range.
    /// </summary>
    public ulong LargestAcknowledged { get; }
}

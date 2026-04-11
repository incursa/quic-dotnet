namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed ACK frame view.
/// </summary>
internal sealed class QuicAckFrame
{
    /// <summary>
    /// Gets or sets the ACK frame type. Valid values are 0x02 and 0x03.
    /// </summary>
    internal byte FrameType { get; set; }

    /// <summary>
    /// Gets or sets the Largest Acknowledged field.
    /// </summary>
    internal ulong LargestAcknowledged { get; set; }

    /// <summary>
    /// Gets or sets the ACK Delay field.
    /// </summary>
    internal ulong AckDelay { get; set; }

    /// <summary>
    /// Gets or sets the First ACK Range field.
    /// </summary>
    internal ulong FirstAckRange { get; set; }

    /// <summary>
    /// Gets or sets the additional ACK Ranges after the first ACK Range.
    /// </summary>
    internal QuicAckRange[] AdditionalRanges { get; set; } = [];

    /// <summary>
    /// Gets or sets the optional ECN counters carried by ACK frame type 0x03.
    /// </summary>
    internal QuicEcnCounts? EcnCounts { get; set; }

    /// <summary>
    /// Gets the number of additional ACK Ranges.
    /// </summary>
    internal ulong AckRangeCount => (ulong)AdditionalRanges.Length;
}


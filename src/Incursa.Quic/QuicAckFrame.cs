namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed ACK frame view.
/// </summary>
public sealed class QuicAckFrame
{
    /// <summary>
    /// Gets or sets the ACK frame type. Valid values are 0x02 and 0x03.
    /// </summary>
    public byte FrameType { get; set; }

    /// <summary>
    /// Gets or sets the Largest Acknowledged field.
    /// </summary>
    public ulong LargestAcknowledged { get; set; }

    /// <summary>
    /// Gets or sets the ACK Delay field.
    /// </summary>
    public ulong AckDelay { get; set; }

    /// <summary>
    /// Gets or sets the First ACK Range field.
    /// </summary>
    public ulong FirstAckRange { get; set; }

    /// <summary>
    /// Gets or sets the additional ACK Ranges after the first ACK Range.
    /// </summary>
    public QuicAckRange[] AdditionalRanges { get; set; } = [];

    /// <summary>
    /// Gets or sets the optional ECN counters carried by ACK frame type 0x03.
    /// </summary>
    public QuicEcnCounts? EcnCounts { get; set; }

    /// <summary>
    /// Gets the number of additional ACK Ranges.
    /// </summary>
    public ulong AckRangeCount => (ulong)AdditionalRanges.Length;
}

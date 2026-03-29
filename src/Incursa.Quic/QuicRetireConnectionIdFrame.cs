namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed RETIRE_CONNECTION_ID frame.
/// </summary>
public readonly struct QuicRetireConnectionIdFrame
{
    /// <summary>
    /// Initializes a RETIRE_CONNECTION_ID frame view.
    /// </summary>
    public QuicRetireConnectionIdFrame(ulong sequenceNumber)
    {
        SequenceNumber = sequenceNumber;
    }

    /// <summary>
    /// Gets the retired connection ID sequence number.
    /// </summary>
    public ulong SequenceNumber { get; }
}

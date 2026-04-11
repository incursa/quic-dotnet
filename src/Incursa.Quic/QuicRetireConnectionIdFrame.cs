namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed RETIRE_CONNECTION_ID frame.
/// </summary>
internal readonly struct QuicRetireConnectionIdFrame
{
    /// <summary>
    /// Initializes a RETIRE_CONNECTION_ID frame view.
    /// </summary>
    internal QuicRetireConnectionIdFrame(ulong sequenceNumber)
    {
        SequenceNumber = sequenceNumber;
    }

    /// <summary>
    /// Gets the retired connection ID sequence number.
    /// </summary>
    internal ulong SequenceNumber { get; }
}


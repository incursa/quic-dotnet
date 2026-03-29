namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed MAX_STREAM_DATA frame.
/// </summary>
public readonly struct QuicMaxStreamDataFrame
{
    /// <summary>
    /// Initializes a MAX_STREAM_DATA frame view.
    /// </summary>
    public QuicMaxStreamDataFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }

    /// <summary>
    /// Gets the affected stream identifier.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets the maximum stream data limit.
    /// </summary>
    public ulong MaximumStreamData { get; }
}

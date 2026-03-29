namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed STREAM_DATA_BLOCKED frame.
/// </summary>
public readonly struct QuicStreamDataBlockedFrame
{
    /// <summary>
    /// Initializes a STREAM_DATA_BLOCKED frame view.
    /// </summary>
    public QuicStreamDataBlockedFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }

    /// <summary>
    /// Gets the blocked stream identifier.
    /// </summary>
    public ulong StreamId { get; }

    /// <summary>
    /// Gets the stream data offset at which blocking occurred.
    /// </summary>
    public ulong MaximumStreamData { get; }
}
